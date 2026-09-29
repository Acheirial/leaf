//! Hysteria2 outbound: dials a QUIC connection, authenticates over HTTP/3 and
//! then carries TCP as a framed bidi stream and UDP as QUIC datagrams.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tracing::{debug, trace, warn, Instrument};

use crate::app::SyncDnsClient;
use crate::config::Hysteria2OutboundSettings;
use crate::proxy::*;
use crate::session::{Session, SocksAddr};

use super::obfs::{validate_psk, ObfsRuntime};
use super::protocol::{
    self, frag_udp_message, Defragger, UdpMessage, MAX_DATAGRAM_FRAME_SIZE, MAX_UDP_SIZE,
};
use super::{parse_addr, parse_server, transport_config, ALPN_H3};

/// Status code the reference uses to signal a successful authentication.
const STATUS_AUTH_OK: u16 = 233;
/// HTTP/3 error code used when the connection is torn down after a protocol
/// level failure (`H3_GENERAL_PROTOCOL_ERROR`).
const CLOSE_ERR_PROTOCOL_ERROR: u32 = 0x101;

/// The auth request URI, exactly as the reference builds it: host `hysteria`,
/// path `/auth`.
const AUTH_URI: &str = "https://hysteria/auth";

mod verify {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// Accepts any certificate; used when `insecure` is set.
    #[derive(Debug)]
    pub struct NotVerified;

    impl ServerCertVerifier for NotVerified {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

/// Routes incoming UDP messages to the session that owns them.
#[derive(Default)]
struct DatagramRouter {
    sessions: SyncMutex<HashMap<u32, mpsc::Sender<UdpMessage>>>,
}

impl DatagramRouter {
    fn register(&self, id: u32, tx: mpsc::Sender<UdpMessage>) {
        self.sessions.lock().insert(id, tx);
    }

    fn unregister(&self, id: u32) {
        self.sessions.lock().remove(&id);
    }

    fn feed(&self, msg: UdpMessage) {
        let sessions = self.sessions.lock();
        match sessions.get(&msg.session_id) {
            Some(tx) => {
                // Bounded channel: a slow consumer loses datagrams rather than
                // growing the queue without bound, as UDP semantics allow.
                if let Err(e) = tx.try_send(msg) {
                    debug!("hysteria2 outbound: dropping UDP message: {}", e);
                }
            }
            None => trace!(
                "hysteria2 outbound: message for unknown session {}",
                msg.session_id
            ),
        }
    }
}

/// A QUIC connection that has completed the auth exchange.
struct AuthConn {
    conn: quinn::Connection,
    udp_enabled: bool,
    router: Arc<DatagramRouter>,
    next_session_id: AtomicU32,
}

impl AuthConn {
    fn next_session_id(&self) -> u32 {
        // The reference starts at 1, and 0 is never a valid session.
        loop {
            let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    /// Sends one UDP message, fragmenting it when it does not fit in a single
    /// QUIC datagram.
    async fn send_udp_message(&self, msg: UdpMessage) -> io::Result<()> {
        let max_size = self
            .conn
            .max_datagram_size()
            .unwrap_or(MAX_DATAGRAM_FRAME_SIZE);
        let mut buf = Vec::with_capacity(msg.size());
        if msg.size() <= max_size {
            msg.serialize(&mut buf);
            return self
                .conn
                .send_datagram_wait(Bytes::from(buf))
                .await
                .map_err(io::Error::other);
        }
        if msg.size() > MAX_UDP_SIZE {
            return Err(io::Error::other(format!(
                "hysteria2 outbound: UDP message too large: {} bytes",
                msg.size()
            )));
        }
        for frag in frag_udp_message(&msg, max_size) {
            buf.clear();
            frag.serialize(&mut buf);
            self.conn
                .send_datagram_wait(Bytes::from(buf.clone()))
                .await
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

/// Shared client state: the QUIC endpoint, the authenticated connection and the
/// settings needed to (re)dial.
struct Client {
    address: String,
    port: u16,
    password: String,
    server_name: String,
    up_bps: u64,
    down_bps: u64,
    psk: Option<Vec<u8>>,
    client_config: quinn::ClientConfig,
    dns_client: SyncDnsClient,
    endpoint: Mutex<Option<quinn::Endpoint>>,
    conn: Mutex<Option<Arc<AuthConn>>>,
}

impl Client {
    fn new(settings: &Hysteria2OutboundSettings, dns_client: SyncDnsClient) -> Result<Self> {
        let server = settings
            .server
            .clone()
            .ok_or_else(|| anyhow!("hysteria2 outbound: server is required"))?;
        let (address, port) = parse_server(&server)?;
        let password = settings.password.clone().unwrap_or_default();
        let server_name = settings.sni.clone().unwrap_or_else(|| address.clone());
        let insecure = settings.insecure.unwrap_or(false);
        let up_bps = super::mbps_to_bps(settings.up_mbps.unwrap_or(0));
        let down_bps = super::mbps_to_bps(settings.down_mbps.unwrap_or(0));
        let alpns = match settings.alpn.as_deref() {
            Some(alpn) if !alpn.is_empty() => alpn
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
            _ => vec![ALPN_H3.to_string()],
        };

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client_crypto =
            rustls::ClientConfig::builder_with_provider(super::crypto_provider())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        for alpn in alpns {
            client_crypto.alpn_protocols.push(alpn.as_bytes().to_vec());
        }
        if insecure {
            client_crypto
                .dangerous()
                .set_certificate_verifier(Arc::new(verify::NotVerified));
        }
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));
        client_config.transport_config(Arc::new(transport_config(
            *crate::option::QUIC_MAX_IDLE_TIMEOUT_MS as u64,
            *crate::option::QUIC_KEEP_ALIVE_INTERVAL_MS,
            settings.mtu,
            up_bps,
        )));

        Ok(Self {
            address,
            port,
            password,
            server_name,
            up_bps,
            down_bps,
            psk: obfs_psk(settings)?,
            client_config,
            dns_client,
            endpoint: Mutex::new(None),
            conn: Mutex::new(None),
        })
    }

    /// The obfuscating (or plain) QUIC endpoint, created on first use.
    async fn endpoint(&self) -> Result<quinn::Endpoint> {
        let mut guard = self.endpoint.lock().await;
        if let Some(ep) = guard.as_ref() {
            return Ok(ep.clone());
        }
        let socket = crate::proxy::new_udp_socket(&crate::option::UNSPECIFIED_BIND_ADDR)
            .instrument(tracing::Span::current())
            .await?;
        let runtime: Arc<dyn quinn::Runtime> = match self.psk.as_ref() {
            Some(psk) => Arc::new(ObfsRuntime::new(psk.clone())),
            None => Arc::new(quinn::TokioRuntime),
        };
        let mut ep = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into_std()?,
            runtime,
        )?;
        ep.set_default_client_config(self.client_config.clone());
        *guard = Some(ep.clone());
        Ok(ep)
    }

    /// Returns the current authenticated connection, dialing a new one when
    /// there is none or the previous one has been closed.
    async fn conn(&self) -> Result<Arc<AuthConn>> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            if conn.conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        let conn = Arc::new(self.dial().await?);
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn dial(&self) -> Result<AuthConn> {
        let endpoint = self.endpoint().await?;
        let dial_timeout = Duration::from_secs(*crate::option::OUTBOUND_DIAL_TIMEOUT);
        let ips = self
            .dns_client
            .read()
            .await
            .direct_lookup(&self.address)
            .map_err(|e| io::Error::other(format!("lookup {} failed: {}", &self.address, e)))
            .instrument(tracing::Span::current())
            .await?;
        if ips.is_empty() {
            return Err(anyhow!("could not resolve to any address"));
        }
        let mut last_err: Option<anyhow::Error> = None;
        for ip in ips {
            let addr = SocketAddr::new(ip, self.port);
            let connecting = match endpoint.connect(addr, &self.server_name) {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };
            let conn = match timeout(dial_timeout, connecting).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow!("connect quic timed out"));
                    continue;
                }
            };
            match self.authenticate(&conn).await {
                Ok(udp_enabled) => {
                    debug!(
                        "hysteria2 outbound: authenticated to {} udp={}",
                        addr, udp_enabled
                    );
                    let router = Arc::new(DatagramRouter::default());
                    spawn_datagram_reader(conn.clone(), router.clone());
                    return Ok(AuthConn {
                        conn,
                        udp_enabled,
                        router,
                        next_session_id: AtomicU32::new(1),
                    });
                }
                Err(e) => {
                    let _ = conn.close(quinn::VarInt::from_u32(CLOSE_ERR_PROTOCOL_ERROR), b"");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("connect quic failed")))
    }

    /// Performs the HTTP/3 auth exchange, returning whether the server accepts
    /// UDP relay.
    async fn authenticate(&self, conn: &quinn::Connection) -> Result<bool> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(AUTH_URI)
            .body(())
            .map_err(|e| anyhow!("build auth request failed: {}", e))?;
        {
            let headers = req.headers_mut();
            headers.insert(
                "Hysteria-Auth",
                HeaderValue::from_bytes(self.password.as_bytes())
                    .map_err(|e| anyhow!("invalid password: {}", e))?,
            );
            headers.insert(
                "Hysteria-CC-RX",
                HeaderValue::from_str(&self.down_bps.to_string())?,
            );
            headers.insert(
                "Hysteria-Padding",
                HeaderValue::from_bytes(&protocol::auth_request_padding())?,
            );
        }

        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(conn.clone()))
                .await
                .map_err(|e| anyhow!("http/3 handshake failed: {}", e))?;
        // The HTTP/3 driver has to keep being polled for the control and QPACK
        // streams to work, so it runs for the life of the connection.
        tokio::spawn(async move {
            let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| anyhow!("auth request failed: {}", e))?;
        stream
            .finish()
            .await
            .map_err(|e| anyhow!("auth request failed: {}", e))?;
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| anyhow!("auth response failed: {}", e))?;
        let status = resp.status();
        if status != StatusCode::from_u16(STATUS_AUTH_OK).expect("valid status code") {
            return Err(anyhow!("authentication failed with status {}", status));
        }
        let header = |name: &str| -> Option<String> {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };
        let udp_enabled = header("Hysteria-UDP")
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);
        let cc_rx = header("Hysteria-CC-RX");
        if cc_rx.as_deref() == Some("auto") {
            debug!("hysteria2 outbound: server asked us to detect bandwidth");
        } else {
            let server_rx = cc_rx.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            // The sending rate is min(server's receive rate, our own send rate).
            let tx = if server_rx == 0 || server_rx > self.up_bps {
                self.up_bps
            } else {
                server_rx
            };
            trace!("hysteria2 outbound: negotiated tx rate {} B/s", tx);
        }
        Ok(udp_enabled)
    }
}

/// Forwards QUIC datagrams from the connection into the matching UDP session.
fn spawn_datagram_reader(conn: quinn::Connection, router: Arc<DatagramRouter>) {
    tokio::spawn(async move {
        loop {
            match conn.read_datagram().await {
                Ok(data) => match UdpMessage::parse(&data) {
                    Ok(msg) => router.feed(msg),
                    // Invalid messages are simply dropped, as in the reference.
                    Err(e) => trace!("hysteria2 outbound: invalid UDP message: {}", e),
                },
                Err(e) => {
                    debug!("hysteria2 outbound: datagram reader stopped: {}", e);
                    return;
                }
            }
        }
    });
}

/// A stream that carries one proxied TCP connection over a QUIC bidi stream.
pub struct QuicProxyStream<R, W> {
    recv: R,
    send: W,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for QuicProxyStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for QuicProxyStream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// Outbound handler for TCP.
pub struct StreamHandler {
    client: Arc<Client>,
}

impl StreamHandler {
    pub fn new(settings: &Hysteria2OutboundSettings, dns_client: SyncDnsClient) -> Result<Self> {
        Ok(Self {
            client: Arc::new(Client::new(settings, dns_client)?),
        })
    }
}

impl UdpConnector for StreamHandler {}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        trace!("hysteria2 outbound: handling stream");
        let conn = self
            .client
            .conn()
            .instrument(tracing::Span::current())
            .await
            .map_err(io::Error::other)?;
        let (mut send, mut recv) = conn.conn.open_bi().await.map_err(io::Error::other)?;

        // The request and whatever the caller already wrote go out together:
        // it saves a round trip on the first byte, and the server writes its
        // response before reading anything, so neither side can block the
        // other.
        let mut head = protocol::encode_tcp_request(&sess.destination.to_string());
        head.extend_from_slice(&peek_tcp_one_off(lhs).await);
        send.write_all(&head).await.map_err(io::Error::other)?;

        let (ok, msg) = protocol::read_tcp_response(&mut recv)
            .await
            .map_err(io::Error::other)?;
        if !ok {
            return Err(io::Error::other(format!(
                "hysteria2 outbound: server refused the connection: {}",
                msg
            )));
        }
        Ok(Box::new(QuicProxyStream { recv, send }))
    }
}

/// Outbound handler for UDP.
pub struct DatagramHandler {
    client: Arc<Client>,
}

impl DatagramHandler {
    pub fn new(settings: &Hysteria2OutboundSettings, dns_client: SyncDnsClient) -> Result<Self> {
        Ok(Self {
            client: Arc::new(Client::new(settings, dns_client)?),
        })
    }
}

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        trace!("hysteria2 outbound: handling datagram");
        let conn = self
            .client
            .conn()
            .instrument(tracing::Span::current())
            .await
            .map_err(io::Error::other)?;
        if !conn.udp_enabled {
            return Err(io::Error::other(
                "hysteria2 outbound: server does not support UDP",
            ));
        }
        let session_id = conn.next_session_id();
        let (tx, rx) = mpsc::channel(*crate::option::UDP_UPLINK_CHANNEL_SIZE);
        conn.router.register(session_id, tx);
        Ok(Box::new(Datagram {
            session_id,
            conn,
            rx,
            defragger: Defragger::new(),
        }))
    }
}

/// A UDP session carried by the connection's datagram channel.
struct Datagram {
    session_id: u32,
    conn: Arc<AuthConn>,
    rx: mpsc::Receiver<UdpMessage>,
    defragger: Defragger,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf {
                defragger: self.defragger,
                rx: self.rx,
            }),
            Box::new(DatagramSendHalf {
                session_id: self.session_id,
                conn: self.conn,
            }),
        )
    }
}

struct DatagramRecvHalf {
    defragger: Defragger,
    rx: mpsc::Receiver<UdpMessage>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        loop {
            let msg = self
                .rx
                .recv()
                .await
                .ok_or_else(|| io::Error::other("hysteria2 outbound: UDP session closed"))?;
            let msg = match self.defragger.feed(msg) {
                Some(msg) => msg,
                // Still waiting for the remaining fragments.
                None => continue,
            };
            if msg.data.len() > buf.len() {
                return Err(io::Error::other("hysteria2 outbound: UDP buffer too small"));
            }
            let n = msg.data.len();
            buf[..n].copy_from_slice(&msg.data);
            let addr = parse_addr(&msg.addr).unwrap_or_else(|_| {
                warn!(
                    "hysteria2 outbound: invalid source address {}, ignoring",
                    &msg.addr
                );
                SocksAddr::any_ipv4()
            });
            trace!("hysteria2 outbound: received UDP {} bytes from {}", n, addr);
            return Ok((n, addr));
        }
    }
}

struct DatagramSendHalf {
    session_id: u32,
    conn: Arc<AuthConn>,
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        trace!(
            "hysteria2 outbound: send UDP {} bytes to {}",
            buf.len(),
            target
        );
        let msg = UdpMessage {
            session_id: self.session_id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: target.to_string(),
            data: buf.to_vec(),
        };
        self.conn.send_udp_message(msg).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.conn.router.unregister(self.session_id);
        Ok(())
    }
}

/// Builds the optional salamander pre-shared key.
fn obfs_psk(settings: &Hysteria2OutboundSettings) -> Result<Option<Vec<u8>>> {
    match settings.obfs.as_deref() {
        None | Some("") => Ok(None),
        Some("salamander") => {
            let psk = settings.obfs_password.clone().ok_or_else(|| {
                anyhow!("hysteria2 outbound: obfsPassword is required for salamander")
            })?;
            let psk = psk.into_bytes();
            validate_psk(&psk)?;
            Ok(Some(psk))
        }
        Some(other) => Err(anyhow!(
            "hysteria2 outbound: unsupported obfs type {}",
            other
        )),
    }
}
