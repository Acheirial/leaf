//! Hysteria2 inbound.
//!
//! One QUIC endpoint serves everything: HTTP/3 for the auth exchange, framed
//! bidi streams for proxied TCP and QUIC datagrams for proxied UDP. Proxied
//! connections are handed to the rest of the crate through the framework's
//! inbound transport stream, exactly like the QUIC inbound does.

mod adapter;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::task::{Context, Poll};
use futures::Stream;
use http::{Method, Request, Response, StatusCode};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, trace};

use crate::config::Hysteria2InboundSettings;
use crate::proxy::hysteria2::obfs::{validate_psk, ObfsRuntime};
use crate::proxy::hysteria2::protocol::{
    self, read_tcp_request, write_tcp_response, Defragger, UdpMessage, MAX_DATAGRAM_FRAME_SIZE,
    MAX_UDP_SIZE,
};
use crate::proxy::hysteria2::{parse_addr, transport_config, ALPN_H3};
use crate::proxy::*;
use crate::session::{DatagramSource, Network, Session, SocksAddr, StreamId};

use adapter::{AdapterContext, H3Connection, ProxiedStream};

/// Status code that signals a successful authentication.
const STATUS_AUTH_OK: u16 = 233;
const URL_HOST: &str = "hysteria";
const URL_PATH: &str = "/auth";
/// Header carrying the authentication credentials.
const HEADER_AUTH: &str = "Hysteria-Auth";
const HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
const HEADER_CC_RX: &str = "Hysteria-CC-RX";
const HEADER_PADDING: &str = "Hysteria-Padding";
/// How often idle UDP sessions are looked at.
const UDP_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

/// Everything an inbound needs, shared by all its connections.
struct Inner {
    server_config: quinn::ServerConfig,
    password: String,
    /// Server's maximum receive rate in bytes per second; reported to clients.
    server_max_rx: u64,
    /// Server's maximum send rate in bytes per second.
    server_max_tx: u64,
    ignore_client_bandwidth: bool,
    udp_idle_timeout: Duration,
    masquerade: Masquerade,
    psk: Option<Vec<u8>>,
}

pub struct DatagramHandler {
    inner: Arc<Inner>,
}

impl DatagramHandler {
    pub fn new(settings: &Hysteria2InboundSettings) -> Result<Self> {
        let password = settings
            .password
            .clone()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| anyhow!("hysteria2 inbound: password is required"))?;
        let certificate = settings
            .certificate
            .clone()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| anyhow!("hysteria2 inbound: certificate is required"))?;
        let certificate_key = settings
            .certificate_key
            .clone()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| anyhow!("hysteria2 inbound: certificateKey is required"))?;
        let (cert, key) =
            crate::proxy::hysteria2::load_certificate(&certificate, &certificate_key)?;

        let mut crypto =
            rustls::ServerConfig::builder_with_provider(crate::proxy::hysteria2::crypto_provider())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(cert, key)?;
        crypto.alpn_protocols.push(ALPN_H3.as_bytes().to_vec());
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        ));
        server_config.transport_config(Arc::new(transport_config(
            crate::option::get_env_var_or::<u64>("QUIC_SERVER_MAX_IDLE_TIMEOUT_MS", 120_000),
            crate::option::get_env_var_or::<u64>("QUIC_SERVER_KEEP_ALIVE_INTERVAL_MS", 0),
            settings.mtu,
            crate::proxy::hysteria2::mbps_to_bps(settings.up_mbps.unwrap_or(0)),
        )));

        Ok(Self {
            inner: Arc::new(Inner {
                server_config,
                password,
                server_max_rx: crate::proxy::hysteria2::mbps_to_bps(
                    settings.down_mbps.unwrap_or(0),
                ),
                server_max_tx: crate::proxy::hysteria2::mbps_to_bps(settings.up_mbps.unwrap_or(0)),
                ignore_client_bandwidth: settings.ignore_client_bandwidth.unwrap_or(false),
                udp_idle_timeout: Duration::from_secs(settings.udp_idle_timeout.unwrap_or(60)),
                masquerade: Masquerade::from_settings(settings),
                psk: inbound_obfs_psk(settings)?,
            }),
        })
    }
}

/// Builds the optional salamander pre-shared key.
fn inbound_obfs_psk(settings: &Hysteria2InboundSettings) -> Result<Option<Vec<u8>>> {
    match settings.obfs.as_deref() {
        None | Some("") => Ok(None),
        Some("salamander") => {
            let psk = settings.obfs_password.clone().ok_or_else(|| {
                anyhow!("hysteria2 inbound: obfsPassword is required for salamander")
            })?;
            let psk = psk.into_bytes();
            validate_psk(&psk)?;
            Ok(Some(psk))
        }
        Some(other) => Err(anyhow!(
            "hysteria2 inbound: unsupported obfs type {}",
            other
        )),
    }
}

/// What to answer when a request is not a valid auth request.
enum Masquerade {
    NotFound,
    String(String),
    File(PathBuf),
    /// A reverse proxy target. The reference proxies to it; this crate has no
    /// HTTP client in the feature set, so such requests are answered with a
    /// gateway error instead of leaking the proxy.
    Proxy(String),
}

impl Masquerade {
    fn from_settings(settings: &Hysteria2InboundSettings) -> Self {
        if let Some(s) = settings
            .masquerade_string
            .as_ref()
            .filter(|s| !s.is_empty())
        {
            return Masquerade::String(s.clone());
        }
        if let Some(f) = settings.masquerade_file.as_ref().filter(|s| !s.is_empty()) {
            return Masquerade::File(PathBuf::from(f));
        }
        match settings.masquerade.as_deref() {
            None | Some("") => Masquerade::NotFound,
            Some(m) if m.starts_with("http://") || m.starts_with("https://") => {
                Masquerade::Proxy(m.to_string())
            }
            Some(m) if Path::new(m).exists() => Masquerade::File(PathBuf::from(m)),
            Some(m) => Masquerade::String(m.to_string()),
        }
    }

    /// Produces the status, content type and body for a request.
    async fn response(&self, req: &Request<()>) -> (StatusCode, &'static str, Vec<u8>) {
        match self {
            Masquerade::NotFound => (
                StatusCode::NOT_FOUND,
                "text/plain",
                b"404 page not found\n".to_vec(),
            ),
            Masquerade::String(body) => (StatusCode::OK, "text/plain", body.as_bytes().to_vec()),
            Masquerade::Proxy(target) => {
                debug!(
                    "hysteria2 inbound: masquerade proxy {} is not supported",
                    target
                );
                (
                    StatusCode::BAD_GATEWAY,
                    "text/plain",
                    b"502 Bad Gateway\n".to_vec(),
                )
            }
            Masquerade::File(path) => match read_masquerade_file(path, req.uri().path()).await {
                Ok((content_type, body)) => (StatusCode::OK, content_type, body),
                Err(e) => {
                    trace!("hysteria2 inbound: masquerade file error: {}", e);
                    (
                        StatusCode::NOT_FOUND,
                        "text/plain",
                        b"404 page not found\n".to_vec(),
                    )
                }
            },
        }
    }
}

/// Serves one path out of a file or a directory, refusing to escape it.
async fn read_masquerade_file(path: &Path, uri_path: &str) -> io::Result<(&'static str, Vec<u8>)> {
    let rel = uri_path
        .split('?')
        .next()
        .unwrap_or("")
        .trim_start_matches('/');
    if rel.split('/').any(|c| c == ".." || c == ".") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path traversal",
        ));
    }
    if path.is_dir() {
        let mut full = path.join(if rel.is_empty() { "index.html" } else { rel });
        if full.is_dir() {
            full = full.join("index.html");
        }
        let data = tokio::fs::read(&full).await?;
        Ok((content_type_of(&full), data))
    } else {
        let data = tokio::fs::read(path).await?;
        Ok((content_type_of(path), data))
    }
}

fn content_type_of(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") | Some("mjs") => "text/javascript",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("wasm") => "application/wasm",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

struct Incoming {
    rx: mpsc::Receiver<AnyBaseInboundTransport>,
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[async_trait]
impl InboundDatagramHandler for DatagramHandler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        trace!("hysteria2 inbound: handling inbound datagram");
        let (tx, rx) = mpsc::channel(*crate::option::QUIC_ACCEPT_CHANNEL_SIZE);
        let std_socket = socket.into_std()?;
        let runtime: Arc<dyn quinn::Runtime> = match self.inner.psk.as_ref() {
            Some(psk) => Arc::new(ObfsRuntime::new(psk.clone())),
            None => Arc::new(quinn::TokioRuntime),
        };
        let local_addr = std_socket.local_addr()?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(self.inner.server_config.clone()),
            std_socket,
            runtime,
        )
        .map_err(io::Error::other)?;
        let inner = self.inner.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let inner = inner.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let remote_addr = incoming.remote_address();
                    match incoming.accept() {
                        Ok(connecting) => {
                            if let Err(e) = handle_conn(inner, tx, connecting, local_addr).await {
                                debug!(
                                    "hysteria2 inbound: connection from {} failed: {}",
                                    remote_addr, e
                                );
                            }
                        }
                        Err(e) => {
                            debug!(
                                "hysteria2 inbound: accepting connection from {} failed: {}",
                                remote_addr, e
                            );
                        }
                    }
                });
            }
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming { rx })))
    }
}

/// Authentication state shared by the connection's HTTP/3 handler and its
/// stream dispatcher.
struct AuthCtx {
    inner: Arc<Inner>,
    authenticated: Arc<AtomicBool>,
    conn: quinn::Connection,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    /// Port the QUIC endpoint listens on, used by the masquerade's `Alt-Svc`.
    local_addr: SocketAddr,
}

async fn handle_conn(
    inner: Arc<Inner>,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    connecting: quinn::Connecting,
    local_addr: SocketAddr,
) -> Result<()> {
    let conn = connecting.await?;
    let remote_addr = conn.remote_address();
    trace!(
        "hysteria2 inbound: handling connection from {}",
        remote_addr
    );

    let authenticated = Arc::new(AtomicBool::new(false));
    let (proxied_tx, mut proxied_rx) = mpsc::channel(*crate::option::QUIC_ACCEPT_CHANNEL_SIZE);
    let adapter_ctx = Arc::new(AdapterContext {
        authenticated: authenticated.clone(),
        proxied: proxied_tx,
    });

    // Proxied streams are served independently of the HTTP/3 side.
    {
        let tx = tx.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            while let Some(stream) = proxied_rx.recv().await {
                let inner_tx = tx.clone();
                let conn = conn.clone();
                tokio::spawn(async move {
                    handle_proxied_stream(conn, stream, inner_tx).await;
                });
            }
        });
    }

    let ctx = AuthCtx {
        inner,
        authenticated,
        conn: conn.clone(),
        tx,
        local_addr,
    };

    let mut h3_conn: h3::server::Connection<H3Connection, Bytes> = h3::server::builder()
        .build(H3Connection::new(conn.clone(), adapter_ctx))
        .await?;
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let ctx = AuthCtx {
                    inner: ctx.inner.clone(),
                    authenticated: ctx.authenticated.clone(),
                    conn: ctx.conn.clone(),
                    tx: ctx.tx.clone(),
                    local_addr,
                };
                tokio::spawn(async move {
                    if let Err(e) = serve_request(ctx, resolver).await {
                        debug!("hysteria2 inbound: request failed: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                debug!("hysteria2 inbound: http/3 connection ended: {}", e);
                break;
            }
        }
    }

    // Proxied streams are dispatched from inside the HTTP/3 connection above;
    // all that is left here is to keep the connection alive until it closes,
    // so the HTTP/3 connection's own drop cannot tear down streams the
    // dispatcher is still serving.
    let _ = conn.closed().await;
    debug!("hysteria2 inbound: connection from {} closed", remote_addr);
    Ok(())
}

/// Handles one HTTP/3 request: the auth exchange, or the masquerade.
async fn serve_request(
    ctx: AuthCtx,
    resolver: h3::server::RequestResolver<H3Connection, Bytes>,
) -> Result<()> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| anyhow!("resolve request failed: {}", e))?;

    let is_auth_request = req.method() == Method::POST
        && req.uri().path() == URL_PATH
        && req.uri().authority().map(|a| a.as_str()) == Some(URL_HOST);
    if !is_auth_request {
        return masquerade(&ctx, &req, &mut stream).await;
    }

    let provided = req
        .headers()
        .get(HEADER_AUTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != ctx.inner.password {
        debug!("hysteria2 inbound: authentication failed");
        return masquerade(&ctx, &req, &mut stream).await;
    }

    if !ctx.authenticated.swap(true, Ordering::SeqCst) {
        debug!("hysteria2 inbound: client authenticated");
        if ctx.inner.server_max_tx > 0 {
            trace!(
                "hysteria2 inbound: server send limit {} B/s",
                ctx.inner.server_max_tx
            );
        }
        tokio::spawn(run_udp_sessions(
            ctx.inner.clone(),
            ctx.conn.clone(),
            ctx.tx.clone(),
        ));
    }

    // `Hysteria-CC-RX` is the server's own receive limit, or "auto" when the
    // server refuses to give one and wants the client to detect its rate.
    let cc_rx = if ctx.inner.ignore_client_bandwidth {
        "auto".to_string()
    } else {
        ctx.inner.server_max_rx.to_string()
    };
    let padding = String::from_utf8_lossy(&protocol::auth_response_padding()).into_owned();
    let resp = Response::builder()
        .status(StatusCode::from_u16(STATUS_AUTH_OK).expect("valid status code"))
        .header(HEADER_UDP_ENABLED, "true")
        .header(HEADER_CC_RX, cc_rx)
        .header(HEADER_PADDING, padding)
        .body(())
        .map_err(|e| anyhow!("build auth response failed: {}", e))?;
    stream
        .send_response(resp)
        .await
        .map_err(|e| anyhow!("send auth response failed: {}", e))?;
    stream
        .finish()
        .await
        .map_err(|e| anyhow!("finish auth response failed: {}", e))?;
    Ok(())
}

/// Answers a request that is not a valid authentication attempt.
async fn masquerade(
    ctx: &AuthCtx,
    req: &Request<()>,
    stream: &mut h3::server::RequestStream<adapter::H3BidiStream, Bytes>,
) -> Result<()> {
    let (status, content_type, body) = ctx.inner.masquerade.response(req).await;
    // The responses are small and bounded, so the body is sent whole.
    let resp = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("content-length", body.len().to_string())
        .header(
            "alt-svc",
            format!("h3=\":{}\"; ma=2592000", ctx.local_addr.port()),
        )
        .body(())
        .map_err(|e| anyhow!("build masquerade response failed: {}", e))?;
    stream
        .send_response(resp)
        .await
        .map_err(|e| anyhow!("send masquerade response failed: {}", e))?;
    if !body.is_empty() {
        stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|e| anyhow!("send masquerade body failed: {}", e))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| anyhow!("finish masquerade response failed: {}", e))?;
    Ok(())
}

/// Reads a proxied TCP request and hands the stream to the framework.
async fn handle_proxied_stream(
    conn: quinn::Connection,
    stream: ProxiedStream,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
) {
    let ProxiedStream { mut send, mut recv } = stream;
    // The frame type has already been consumed by the dispatcher, exactly as
    // the reference's `ProxyStreamHijacker` does.
    let addr = match read_tcp_request(&mut recv).await {
        Ok(addr) => addr,
        Err(e) => {
            debug!("hysteria2 inbound: invalid tcp request: {}", e);
            let _ = send.reset(quinn::VarInt::from_u32(0x101));
            return;
        }
    };
    let destination = match parse_addr(&addr) {
        Ok(destination) => destination,
        Err(e) => {
            debug!("hysteria2 inbound: invalid destination {}: {}", addr, e);
            let _ = write_tcp_response(&mut send, false, "invalid address").await;
            let _ = send.reset(quinn::VarInt::from_u32(0x101));
            return;
        }
    };

    // Answer before dialing: the framework performs the dial after the stream
    // is handed over, and the client must not be left waiting for a response
    // that can only be produced once routing has picked an outbound.
    if let Err(e) = write_tcp_response(&mut send, true, "Connected").await {
        debug!("hysteria2 inbound: writing tcp response failed: {}", e);
        return;
    }

    let sess = Session {
        network: Network::Tcp,
        source: conn.remote_address(),
        destination,
        stream_id: Some(StreamId::U64(send.id().index())),
        ..Default::default()
    };
    let transport = BaseInboundTransport::Stream(Box::new(StreamProxyStream { recv, send }), sess);
    if tx.send(transport).await.is_err() {
        debug!("hysteria2 inbound: inbound transport is gone");
    }
}

/// A proxied TCP stream carried by a QUIC bidi stream.
struct StreamProxyStream<R, W> {
    recv: R,
    send: W,
}

impl<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncRead
    for StreamProxyStream<R, W>
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
    for StreamProxyStream<R, W>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// One UDP session, as seen by the framework.
struct SessionEntry {
    tx: mpsc::Sender<(Vec<u8>, SocksAddr)>,
    last_active: Instant,
}

/// Reads QUIC datagrams and routes them to per-session inbound datagrams.
async fn run_udp_sessions(
    inner: Arc<Inner>,
    conn: quinn::Connection,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
) {
    let mut sessions: HashMap<u32, SessionEntry> = HashMap::new();
    let mut defraggers: HashMap<u32, Defragger> = HashMap::new();
    let mut cleanup = tokio::time::interval(UDP_CLEANUP_INTERVAL);
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            datagram = conn.read_datagram() => {
                let data = match datagram {
                    Ok(data) => data,
                    Err(e) => {
                        debug!("hysteria2 inbound: datagram reader stopped: {}", e);
                        break;
                    }
                };
                let msg = match UdpMessage::parse(&data) {
                    Ok(msg) => msg,
                    Err(e) => {
                        trace!("hysteria2 inbound: invalid UDP message: {}", e);
                        continue;
                    }
                };
                let msg = match defraggers
                    .entry(msg.session_id)
                    .or_insert_with(Defragger::new)
                    .feed(msg)
                {
                    Some(msg) => msg,
                    // Waiting for the remaining fragments.
                    None => continue,
                };
                let session_id = msg.session_id;
                let destination = match parse_addr(&msg.addr) {
                    Ok(destination) => destination,
                    Err(e) => {
                        debug!("hysteria2 inbound: invalid UDP address {}: {}", &msg.addr, e);
                        continue;
                    }
                };
                if let Some(entry) = sessions.get_mut(&session_id) {
                    entry.last_active = Instant::now();
                    if entry.tx.try_send((msg.data, destination)).is_err() {
                        trace!(
                            "hysteria2 inbound: dropping UDP packet of session {}",
                            session_id
                        );
                    }
                    continue;
                }
                let (payload_tx, payload_rx) = mpsc::channel(*crate::option::UDP_UPLINK_CHANNEL_SIZE);
                sessions.insert(
                    session_id,
                    SessionEntry {
                        tx: payload_tx.clone(),
                        last_active: Instant::now(),
                    },
                );
                let sess = Session {
                    network: Network::Udp,
                    source: conn.remote_address(),
                    destination: destination.clone(),
                    ..Default::default()
                };
                trace!(
                    "hysteria2 inbound: new UDP session {} -> {}",
                    session_id,
                    &destination
                );
                let inbound = UdpSessionInbound::new(session_id, conn.clone(), payload_rx);
                let _ = payload_tx.try_send((msg.data, destination));
                if tx
                    .send(BaseInboundTransport::Datagram(
                        Box::new(inbound),
                        Some(sess),
                    ))
                    .await
                    .is_err()
                {
                    debug!("hysteria2 inbound: inbound transport is gone");
                    break;
                }
            }
            _ = cleanup.tick() => {
                let now = Instant::now();
                sessions.retain(|id, entry| {
                    let alive = now.duration_since(entry.last_active) <= inner.udp_idle_timeout;
                    if !alive {
                        trace!("hysteria2 inbound: reaping idle UDP session {}", id);
                        defraggers.remove(id);
                    }
                    alive
                });
            }
        }
    }
}

/// An inbound datagram backed by one Hysteria2 UDP session.
struct UdpSessionInbound {
    session_id: u32,
    peer: SocketAddr,
    conn: quinn::Connection,
    rx: mpsc::Receiver<(Vec<u8>, SocksAddr)>,
}

impl UdpSessionInbound {
    fn new(
        session_id: u32,
        conn: quinn::Connection,
        rx: mpsc::Receiver<(Vec<u8>, SocksAddr)>,
    ) -> Self {
        Self {
            session_id,
            peer: conn.remote_address(),
            conn,
            rx,
        }
    }
}

impl InboundDatagram for UdpSessionInbound {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        (
            Box::new(UdpSessionRecvHalf {
                session_id: self.session_id,
                peer: self.peer,
                rx: self.rx,
            }),
            Box::new(UdpSessionSendHalf {
                session_id: self.session_id,
                conn: self.conn,
            }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other(
            "hysteria2 UDP sessions cannot be turned into a std socket",
        ))
    }
}

struct UdpSessionRecvHalf {
    session_id: u32,
    peer: SocketAddr,
    rx: mpsc::Receiver<(Vec<u8>, SocksAddr)>,
}

#[async_trait]
impl InboundDatagramRecvHalf for UdpSessionRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (data, destination) =
            self.rx.recv().await.ok_or_else(|| {
                ProxyError::DatagramFatal(anyhow!("hysteria2 UDP session closed"))
            })?;
        if data.len() > buf.len() {
            return Err(ProxyError::DatagramWarn(anyhow!(
                "hysteria2 UDP packet of {} bytes does not fit the buffer",
                data.len()
            )));
        }
        let n = data.len();
        buf[..n].copy_from_slice(&data);
        Ok((
            n,
            DatagramSource::new(self.peer, Some(StreamId::U64(self.session_id as u64))),
            destination,
        ))
    }
}

struct UdpSessionSendHalf {
    session_id: u32,
    conn: quinn::Connection,
}

#[async_trait]
impl InboundDatagramSendHalf for UdpSessionSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        // The address in the message is the one the payload came from, so the
        // client can tell its sessions apart.
        let msg = UdpMessage {
            session_id: self.session_id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: src_addr.to_string(),
            data: buf.to_vec(),
        };
        send_udp_message(&self.conn, msg).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Sends one UDP message, fragmenting it when it does not fit in a single QUIC
/// datagram. Used by both directions.
pub(crate) async fn send_udp_message(conn: &quinn::Connection, msg: UdpMessage) -> io::Result<()> {
    let max_size = conn
        .max_datagram_size()
        .unwrap_or(MAX_DATAGRAM_FRAME_SIZE)
        .min(MAX_UDP_SIZE);
    let mut buf = Vec::with_capacity(msg.size());
    if msg.size() <= max_size {
        msg.serialize(&mut buf);
        return conn
            .send_datagram_wait(Bytes::from(buf))
            .await
            .map_err(io::Error::other);
    }
    if msg.size() > MAX_UDP_SIZE {
        debug!(
            "hysteria2: dropping oversized UDP message ({} bytes)",
            msg.size()
        );
        return Ok(());
    }
    for frag in protocol::frag_udp_message(&msg, max_size) {
        buf.clear();
        frag.serialize(&mut buf);
        conn.send_datagram_wait(Bytes::from(buf.clone()))
            .await
            .map_err(io::Error::other)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(
        masquerade: Option<&str>,
        file: Option<&str>,
        string: Option<&str>,
    ) -> Hysteria2InboundSettings {
        let mut s = Hysteria2InboundSettings::new();
        s.password = Some("pass".to_string());
        s.masquerade = masquerade.map(|m| m.to_string());
        s.masquerade_file = file.map(|m| m.to_string());
        s.masquerade_string = string.map(|m| m.to_string());
        s
    }

    #[test]
    fn masquerade_variants() {
        assert!(matches!(
            Masquerade::from_settings(&settings(None, None, None)),
            Masquerade::NotFound
        ));
        assert!(matches!(
            Masquerade::from_settings(&settings(None, None, Some("hi"))),
            Masquerade::String(s) if s == "hi"
        ));
        assert!(matches!(
            Masquerade::from_settings(&settings(Some("file:///tmp"), None, None)),
            Masquerade::String(s) if s == "file:///tmp"
        ));
        assert!(matches!(
            Masquerade::from_settings(&settings(Some("https://example.com"), None, None)),
            Masquerade::Proxy(_)
        ));
    }

    #[tokio::test]
    async fn masquerade_file_rejects_traversal() {
        let dir = std::env::temp_dir();
        assert!(read_masquerade_file(&dir, "/../etc/passwd").await.is_err());
        assert!(read_masquerade_file(&dir, "/./x").await.is_err());
    }

    #[test]
    fn obfs_requires_password() {
        let mut s = settings(None, None, None);
        s.obfs = Some("salamander".to_string());
        assert!(inbound_obfs_psk(&s).is_err());
        s.obfs_password = Some("abcd".to_string());
        assert!(inbound_obfs_psk(&s).unwrap().is_some());
        s.obfs = Some("gecko".to_string());
        assert!(inbound_obfs_psk(&s).is_err());
    }
}
