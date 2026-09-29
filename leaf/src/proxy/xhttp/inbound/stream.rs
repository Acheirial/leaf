//! The XHTTP inbound: an HTTP/1.1 server that turns requests into session
//! traffic.
//!
//! One request per connection, as Xray's HTTP/1.1 transport does. A downlink
//! GET becomes the connection handed to the payload protocol; uplink POSTs are
//! consumed and pushed into that session's queue, whichever TCP connection
//! they arrive on.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::debug;

use crate::config;
use crate::proxy::xhttp::b64;
use crate::proxy::xhttp::config::{
    Config as XhttpConfig, PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER,
    PLACEMENT_PATH, PLACEMENT_QUERY,
};
use crate::proxy::xhttp::h1::{self, BodyReader, ChunkedWriter, Request};
use crate::proxy::xhttp::stream::SplitStream;
use crate::proxy::xhttp::xpadding;
use crate::proxy::*;
use crate::session::Session;

use super::session::{DropNotifyReader, Packet, Session as XhttpSession, UploadQueueReader};

/// Sessions that out-of-order uploads and a not-yet-arrived downlink need.
/// Older entries are evicted once the table is this large.
const MAX_SESSIONS: usize = 4096;

pub struct Handler {
    config: Arc<XhttpConfig>,
    sessions: Arc<Mutex<HashMap<String, Arc<XhttpSession>>>>,
}

impl Handler {
    pub fn new(settings: &config::XhttpInboundSettings) -> Result<Self> {
        let config = XhttpConfig::from_inbound(settings)?;
        Ok(Handler {
            config: Arc::new(config),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn upsert_session(&self, id: &str) -> Arc<XhttpSession> {
        let mut map = self.sessions.lock();
        if let Some(session) = map.get(id) {
            return session.clone();
        }
        if map.len() >= MAX_SESSIONS {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(id, _)| id.clone())
            {
                map.remove(&oldest);
            }
        }
        let session = Arc::new(XhttpSession::new(
            self.config.normalized_sc_max_buffered_posts(),
        ));
        map.insert(id.to_string(), session.clone());
        session
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        let (rh, mut wh) = tokio::io::split(stream);
        let mut buf = BufReader::new(rh);

        let req = h1::read_request_head(&mut buf, self.config.normalized_server_max_header_bytes())
            .await?;

        if !self.config.host.is_empty()
            && !host_matches(req.header("Host").unwrap_or(""), &self.config.host)
        {
            debug!("xhttp rejected host {:?}", req.header("Host"));
            simple_response(&mut wh, 404, "Not Found", Vec::new()).await?;
            return Ok(InboundTransport::Empty);
        }

        let norm_path = self.config.normalized_path();
        if !req.path.starts_with(&norm_path) {
            debug!("xhttp rejected path {:?}", req.path);
            simple_response(&mut wh, 404, "Not Found", Vec::new()).await?;
            return Ok(InboundTransport::Empty);
        }

        let (padding, placement) =
            xpadding::extract_padding(&req, self.config.x_padding_obfs_mode, &self.config);
        let valid = self.config.normalized_x_padding_bytes();
        if !xpadding::is_padding_valid(
            &self.config.x_padding_method,
            &padding,
            valid.from,
            valid.to,
        ) {
            debug!(
                "xhttp rejected padding ({}): {} bytes",
                placement,
                padding.len()
            );
            simple_response(&mut wh, 400, "Bad Request", Vec::new()).await?;
            return Ok(InboundTransport::Empty);
        }

        let (session_id, seq_str) = extract_meta(&req, &norm_path, &self.config);

        let mode = self.config.mode.as_str();
        if session_id.is_empty()
            && !mode.is_empty()
            && mode != "auto"
            && mode != "stream-one"
            && mode != "stream-up"
        {
            simple_response(&mut wh, 400, "Bad Request", Vec::new()).await?;
            return Ok(InboundTransport::Empty);
        }

        let is_uplink = if req.method == "GET" {
            !seq_str.is_empty()
        } else {
            true
        };

        if is_uplink && !session_id.is_empty() {
            if seq_str.is_empty() {
                return self.handle_stream_up(sess, req, buf, wh, &session_id).await;
            }
            return self
                .handle_packet_up(sess, req, buf, wh, &session_id, &seq_str)
                .await;
        }

        if req.method == "GET" || session_id.is_empty() {
            return self.handle_downlink(sess, req, buf, wh, &session_id).await;
        }

        simple_response(&mut wh, 405, "Method Not Allowed", Vec::new()).await?;
        Ok(InboundTransport::Empty)
    }
}

impl Handler {
    /// `stream-up`: the POST body is the uplink, read directly by the downlink.
    async fn handle_stream_up(
        &self,
        sess: Session,
        req: Request,
        buf: BufReader<tokio::io::ReadHalf<AnyStream>>,
        mut wh: tokio::io::WriteHalf<AnyStream>,
        session_id: &str,
    ) -> io::Result<AnyInboundTransport> {
        match self.config.mode.as_str() {
            "" | "auto" | "stream-up" => {}
            _ => {
                simple_response(&mut wh, 400, "Bad Request", Vec::new()).await?;
                return Ok(InboundTransport::Empty);
            }
        }

        let session = self.upsert_session(session_id);
        let (dtx, drx) = tokio::sync::oneshot::channel();
        let body = DropNotifyReader::new(BodyReader::new(buf, req.body_kind()), dtx);
        let boxed: Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin> = Box::new(body);
        if session.tx.send(Packet::Reader(boxed)).await.is_err() {
            simple_response(&mut wh, 500, "Internal Server Error", Vec::new()).await?;
            return Ok(InboundTransport::Empty);
        }

        // The response goes out when the downlink drops the body reader, which
        // is what Xray's `httpSC.Wait()` unblocks on. The connection is kept
        // open by a task of its own, so accepting it does not have to wait for
        // the upload to end (the listener bounds accept handling).
        tokio::spawn(async move {
            let _ = drx.await;
            let headers = vec![("Cache-Control".to_string(), "no-store".to_string())];
            if let Err(e) = simple_response(&mut wh, 200, "OK", headers).await {
                debug!("xhttp stream-up response failed: {}", e);
            }
        });
        drop(sess);
        Ok(InboundTransport::Empty)
    }

    /// `packet-up`: one POST carries one sequenced chunk of the uplink.
    async fn handle_packet_up(
        &self,
        sess: Session,
        req: Request,
        buf: BufReader<tokio::io::ReadHalf<AnyStream>>,
        mut wh: tokio::io::WriteHalf<AnyStream>,
        session_id: &str,
        seq_str: &str,
    ) -> io::Result<AnyInboundTransport> {
        match self.config.mode.as_str() {
            "" | "auto" | "packet-up" => {}
            _ => {
                simple_response(&mut wh, 400, "Bad Request", Vec::new()).await?;
                return Ok(InboundTransport::Empty);
            }
        }

        let max = self.config.normalized_sc_max_each_post_bytes().to.max(0) as usize;
        let placement = self.config.normalized_uplink_data_placement().to_string();
        let data_key = self.config.uplink_data_key.clone();

        let mut header_payload = Vec::new();
        if placement == PLACEMENT_AUTO || placement == PLACEMENT_HEADER {
            let mut encoded = String::new();
            let mut i = 0usize;
            while let Some(chunk) = req.header(&format!("{}-{}", data_key, i)) {
                encoded.push_str(chunk);
                i += 1;
            }
            header_payload = match b64::decode(&encoded) {
                Ok(v) => v,
                Err(e) => {
                    debug!("xhttp invalid base64 in headers: {}", e);
                    simple_response(&mut wh, 400, "Bad Request", Vec::new()).await?;
                    return Ok(InboundTransport::Empty);
                }
            };
        }

        let mut cookie_payload = Vec::new();
        if placement == PLACEMENT_AUTO || placement == PLACEMENT_COOKIE {
            let mut encoded = String::new();
            let mut i = 0usize;
            while let Some(chunk) = req.cookie(&format!("{}_{}", data_key, i)) {
                encoded.push_str(&chunk);
                i += 1;
            }
            cookie_payload = match b64::decode(&encoded) {
                Ok(v) => v,
                Err(e) => {
                    debug!("xhttp invalid base64 in cookies: {}", e);
                    simple_response(&mut wh, 400, "Bad Request", Vec::new()).await?;
                    return Ok(InboundTransport::Empty);
                }
            };
        }

        let mut body_payload = Vec::new();
        if placement == PLACEMENT_AUTO || placement == PLACEMENT_BODY {
            let mut body = BodyReader::new(buf, req.body_kind());
            let mut tmp = vec![0u8; 16 * 1024];
            loop {
                let n = body.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                if body_payload.len() + n > max {
                    simple_response(&mut wh, 413, "Payload Too Large", Vec::new()).await?;
                    return Ok(InboundTransport::Empty);
                }
                body_payload.extend_from_slice(&tmp[..n]);
            }
        }

        let payload = match placement.as_str() {
            PLACEMENT_HEADER => header_payload,
            PLACEMENT_COOKIE => cookie_payload,
            PLACEMENT_BODY => body_payload,
            _ => {
                let mut all = header_payload;
                all.extend_from_slice(&cookie_payload);
                all.extend_from_slice(&body_payload);
                all
            }
        };

        if payload.len() > max {
            simple_response(&mut wh, 413, "Payload Too Large", Vec::new()).await?;
            return Ok(InboundTransport::Empty);
        }

        let seq = match seq_str.parse::<u64>() {
            Ok(seq) => seq,
            Err(_) => {
                simple_response(&mut wh, 500, "Internal Server Error", Vec::new()).await?;
                return Ok(InboundTransport::Empty);
            }
        };

        let session = self.upsert_session(session_id);
        if session
            .tx
            .send(Packet::Payload {
                seq,
                data: Bytes::from(payload),
            })
            .await
            .is_err()
        {
            simple_response(&mut wh, 500, "Internal Server Error", Vec::new()).await?;
            return Ok(InboundTransport::Empty);
        }

        let headers = vec![("Cache-Control".to_string(), "no-store".to_string())];
        simple_response(&mut wh, 200, "OK", headers).await?;
        drop(sess);
        Ok(InboundTransport::Empty)
    }

    /// `stream-down` (a GET for a session) and `stream-one` (a single request
    /// carrying both directions).
    async fn handle_downlink(
        &self,
        sess: Session,
        req: Request,
        buf: BufReader<tokio::io::ReadHalf<AnyStream>>,
        mut wh: tokio::io::WriteHalf<AnyStream>,
        session_id: &str,
    ) -> io::Result<AnyInboundTransport> {
        let mut headers = vec![
            ("X-Accel-Buffering".to_string(), "no".to_string()),
            ("Cache-Control".to_string(), "no-store".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
        ];
        if !self.config.no_sse_header {
            headers.push(("Content-Type".to_string(), "text/event-stream".to_string()));
        }
        let padding_len = self.config.normalized_x_padding_bytes().value();
        headers.extend(xpadding::response_padding_headers(
            &self.config,
            padding_len,
        ));
        h1::write_head(&mut wh, "HTTP/1.1 200 OK", &headers).await?;
        wh.flush().await?;

        if session_id.is_empty() {
            // stream-one: the request body is the uplink, the response body
            // the downlink, on the same connection.
            let reader = BodyReader::new(buf, req.body_kind());
            return Ok(InboundTransport::Stream(
                Box::new(SplitStream::new(reader, ChunkedWriter::new(wh))),
                sess,
            ));
        }

        let session = self.upsert_session(session_id);
        let rx = match session.claim_receiver() {
            Some(rx) => rx,
            None => {
                debug!("xhttp session {} already has a downlink", session_id);
                return Ok(InboundTransport::Empty);
            }
        };
        let reader = UploadQueueReader::new(rx, self.config.normalized_sc_max_buffered_posts());

        // The GET has no body; reading the connection to EOF tells us when the
        // client is done, and dropping the session is what ends the upload
        // side (its sender goes away with the map entry). The same removal
        // happens when the downlink is dropped, which is also what closes the
        // connection so the client sees the end of the response.
        let sessions = self.sessions.clone();
        let id = session_id.to_string();
        let detect_sessions = sessions.clone();
        let detect_id = id.clone();
        let detector = tokio::spawn(async move {
            let mut buf = buf;
            let mut discard = [0u8; 256];
            loop {
                match buf.read(&mut discard).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            detect_sessions.lock().remove(&detect_id);
        });

        let writer = ServerDownlink {
            writer: ChunkedWriter::new(wh),
            detector,
            sessions,
            id,
        };
        Ok(InboundTransport::Stream(
            Box::new(SplitStream::new(reader, writer)),
            sess,
        ))
    }
}

/// The server's end of a session downlink: writes the response body, and on
/// drop ends the session and lets the detector -- which holds the connection's
/// read half -- go, so the connection closes and the client sees EOF.
struct ServerDownlink {
    writer: ChunkedWriter<tokio::io::WriteHalf<AnyStream>>,
    detector: tokio::task::JoinHandle<()>,
    sessions: Arc<Mutex<HashMap<String, Arc<XhttpSession>>>>,
    id: String,
}

impl AsyncWrite for ServerDownlink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl Drop for ServerDownlink {
    fn drop(&mut self) {
        self.sessions.lock().remove(&self.id);
        self.detector.abort();
    }
}

async fn simple_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: u16,
    reason: &str,
    extra: Vec<(String, String)>,
) -> io::Result<()> {
    let mut headers = vec![("Content-Length".to_string(), "0".to_string())];
    headers.extend(extra);
    h1::write_head(w, &format!("HTTP/1.1 {} {}", status, reason), &headers).await?;
    w.flush().await
}

fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

fn host_matches(host: &str, expected: &str) -> bool {
    strip_port(host).eq_ignore_ascii_case(strip_port(expected))
}

fn extract_meta(req: &Request, norm_path: &str, cfg: &XhttpConfig) -> (String, String) {
    let session_placement = cfg.normalized_session_placement();
    let seq_placement = cfg.normalized_seq_placement();
    let session_key = cfg.normalized_session_key();
    let seq_key = cfg.normalized_seq_key();

    let mut subpath: Vec<String> = Vec::new();
    if session_placement == PLACEMENT_PATH || seq_placement == PLACEMENT_PATH {
        let suffix = if req.path.len() >= norm_path.len() {
            &req.path[norm_path.len()..]
        } else {
            ""
        };
        subpath = suffix.split('/').map(|s| s.to_string()).collect();
    }
    let mut index = 0usize;

    let mut session = String::new();
    match session_placement {
        PLACEMENT_PATH => {
            if index < subpath.len() {
                session = subpath[index].clone();
                index += 1;
            }
        }
        PLACEMENT_QUERY => session = req.query_param(&session_key).unwrap_or_default(),
        PLACEMENT_HEADER => session = req.header(&session_key).unwrap_or("").to_string(),
        PLACEMENT_COOKIE => session = req.cookie(&session_key).unwrap_or_default(),
        _ => {}
    }

    let mut seq = String::new();
    match seq_placement {
        PLACEMENT_PATH => {
            if index < subpath.len() {
                seq = subpath[index].clone();
            }
        }
        PLACEMENT_QUERY => seq = req.query_param(&seq_key).unwrap_or_default(),
        PLACEMENT_HEADER => seq = req.header(&seq_key).unwrap_or("").to_string(),
        PLACEMENT_COOKIE => seq = req.cookie(&seq_key).unwrap_or_default(),
        _ => {}
    }

    (session, seq)
}
