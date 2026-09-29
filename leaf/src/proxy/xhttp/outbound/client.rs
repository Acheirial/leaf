//! The XHTTP outbound client: the four modes, over HTTP/1.1.
//!
//! `packet-up` fans the uplink out over one POST per chunk, each on its own
//! connection, while the downlink streams from the connection the chain
//! dialled. `stream-up` streams one POST body as the uplink and opens a second
//! connection for the downlink GET. `stream-one` puts both directions in one
//! request/response. Every mode keeps the session id tying the requests
//! together and the sequence number ordering the packets.
//!
//! Each logical direction is a bounded in-memory pipe (`tokio::io::duplex`,
//! `PIPE_BYTES` each way): the payload protocol sees a normal stream, and the
//! opposite end is pumped onto the network by a task, so a slow network
//! applies backpressure instead of buffering without bound.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::task::JoinHandle;
use tracing::debug;

use crate::app::SyncDnsClient;
use crate::proxy::new_tcp_stream;
use crate::proxy::xhttp::b64;
use crate::proxy::xhttp::config::{
    Config, RangeConfig, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH, PLACEMENT_QUERY,
    PLACEMENT_QUERY_IN_HEADER,
};
use crate::proxy::xhttp::h1::{self, BodyReader, ChunkedWriter};
use crate::proxy::xhttp::stream::SplitStream;
use crate::proxy::xhttp::xpadding;
use crate::proxy::AnyStream;
use crate::session::SocksAddr;

/// Bytes buffered in each in-memory pipe before a write blocks.
const PIPE_BYTES: usize = 64 * 1024;

struct Prepared {
    method: String,
    target: String,
    host: String,
    headers: Vec<(String, String)>,
}

fn append_to_path(path: &str, value: &str) -> String {
    if path.ends_with('/') {
        format!("{}{}", path, value)
    } else {
        format!("{}/{}", path, value)
    }
}

fn add_cookie(headers: &mut Vec<(String, String)>, key: &str, value: &str) {
    headers.push(("Cookie".to_string(), format!("{}={}", key, value)));
}

fn encode_component(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
        }
    }
    out
}

fn prepare(
    cfg: &Config,
    method: &str,
    host: &str,
    session_id: &str,
    seq: Option<&str>,
    stream_body: bool,
) -> Prepared {
    let mut path = cfg.normalized_path();
    let mut query: Vec<(String, String)> = Vec::new();
    for pair in cfg.normalized_query().split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => query.push((k.to_string(), v.to_string())),
            None => query.push((pair.to_string(), String::new())),
        }
    }

    let mut headers: Vec<(String, String)> = cfg.headers.clone();
    if !crate::option::HTTP_USER_AGENT.is_empty() {
        headers.push((
            "User-Agent".to_string(),
            crate::option::HTTP_USER_AGENT.clone(),
        ));
    }

    if !session_id.is_empty() {
        let key = cfg.normalized_session_key();
        match cfg.normalized_session_placement() {
            PLACEMENT_PATH => path = append_to_path(&path, session_id),
            PLACEMENT_QUERY => query.push((key, session_id.to_string())),
            PLACEMENT_HEADER => headers.push((key, session_id.to_string())),
            PLACEMENT_COOKIE => add_cookie(&mut headers, &key, session_id),
            _ => {}
        }
    }
    if let Some(seq) = seq.filter(|s| !s.is_empty()) {
        let key = cfg.normalized_seq_key();
        match cfg.normalized_seq_placement() {
            PLACEMENT_PATH => path = append_to_path(&path, seq),
            PLACEMENT_QUERY => query.push((key, seq.to_string())),
            PLACEMENT_HEADER => headers.push((key, seq.to_string())),
            PLACEMENT_COOKIE => add_cookie(&mut headers, &key, seq),
            _ => {}
        }
    }

    // xPadding, defaulting (as Xray does for network requests) to a
    // query-looking value smuggled through the `Referer` header.
    let pad = xpadding::generate_padding(cfg.normalized_x_padding_bytes().value());
    if !pad.is_empty() {
        if !cfg.x_padding_obfs_mode {
            let base = format!("http://{}{}", host, cfg.normalized_path());
            headers.push(("Referer".to_string(), format!("{}?x_padding={}", base, pad)));
        } else {
            match cfg.x_padding_placement.as_str() {
                PLACEMENT_HEADER => headers.push((cfg.x_padding_header.clone(), pad)),
                PLACEMENT_QUERY_IN_HEADER => {
                    let base = format!("http://{}{}", host, cfg.normalized_path());
                    headers.push((
                        cfg.x_padding_header.clone(),
                        format!("{}?{}={}", base, cfg.x_padding_key, pad),
                    ));
                }
                PLACEMENT_QUERY => query.push((cfg.x_padding_key.clone(), pad)),
                PLACEMENT_COOKIE => add_cookie(&mut headers, &cfg.x_padding_key, pad.as_str()),
                _ => {}
            }
        }
    }

    if stream_body && !cfg.no_grpc_header {
        headers.push(("Content-Type".to_string(), "application/grpc".to_string()));
    }

    let mut target = path;
    if !query.is_empty() {
        target.push('?');
        let encoded: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v)))
            .collect();
        target.push_str(&encoded.join("&"));
    }

    Prepared {
        method: method.to_string(),
        target,
        host: host.to_string(),
        headers,
    }
}

async fn write_request_head<W: AsyncWrite + Unpin>(
    w: &mut W,
    prepared: &Prepared,
    extra: &[(String, String)],
) -> io::Result<()> {
    let mut headers = vec![("Host".to_string(), prepared.host.clone())];
    headers.extend(prepared.headers.iter().cloned());
    headers.extend_from_slice(extra);
    h1::write_head(
        w,
        &format!("{} {} HTTP/1.1", prepared.method, prepared.target),
        &headers,
    )
    .await
}

fn host_of(cfg: &Config, dest: &SocksAddr) -> String {
    if cfg.host.is_empty() {
        dest.host()
    } else {
        cfg.host.clone()
    }
}

/// Reads the response head and copies the body into `sink`; the reader of the
/// pipe then sees the body followed by EOF.
async fn pump_response<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    sink: &mut W,
) -> io::Result<()> {
    let mut buf = BufReader::new(reader);
    let resp = h1::read_response_head(&mut buf).await?;
    if resp.status != 200 {
        return Err(io::Error::other(format!(
            "xhttp downlink got status {}",
            resp.status
        )));
    }
    let mut body = BodyReader::new(buf, resp.body_kind());
    let mut tmp = vec![0u8; 16 * 1024];
    loop {
        match body.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => sink.write_all(&tmp[..n]).await?,
            // A connection closed without the terminating chunk is how a
            // server that simply drops its end signals EOF.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Streams a chunked request body from `source` until it closes.
async fn pump_chunked<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    source: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    let mut tmp = vec![0u8; 16 * 1024];
    loop {
        match source.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                writer.write_all(&tmp[..n]).await?;
                writer.flush().await?;
            }
            Err(e) => return Err(e),
        }
    }
    writer.shutdown().await
}

/// A reader fed by a task that pumps one response body into it. The handle is
/// returned so the caller can close the read side; a detached task ends by
/// itself when the pipe's reader goes away.
fn spawn_downlink<R: AsyncRead + Send + Unpin + 'static>(
    reader: R,
) -> (tokio::io::DuplexStream, JoinHandle<()>) {
    let (mut down_write, down_read) = tokio::io::duplex(PIPE_BYTES);
    let handle = tokio::spawn(async move {
        if let Err(e) = pump_response(reader, &mut down_write).await {
            debug!("xhttp downlink failed: {}", e);
        }
        let _ = down_write.shutdown().await;
    });
    (down_read, handle)
}

/// `stream-one`: one POST carries both directions.
pub async fn stream_one(
    cfg: Arc<Config>,
    stream: AnyStream,
    dest: SocksAddr,
) -> io::Result<AnyStream> {
    let host = host_of(&cfg, &dest);
    let (rh, mut wh) = tokio::io::split(stream);

    let post = prepare(
        &cfg,
        &cfg.normalized_uplink_http_method(),
        &host,
        "",
        None,
        true,
    );
    write_request_head(
        &mut wh,
        &post,
        &[("Transfer-Encoding".to_string(), "chunked".to_string())],
    )
    .await?;
    wh.flush().await?;

    let (up_write, mut up_read) = tokio::io::duplex(PIPE_BYTES);
    tokio::spawn(async move {
        let mut writer = ChunkedWriter::new(wh);
        if let Err(e) = pump_chunked(&mut up_read, &mut writer).await {
            debug!("xhttp stream-one upload failed: {}", e);
        }
    });

    let (down_read, _down_handle) = spawn_downlink(rh);
    Ok(Box::new(SplitStream::new(down_read, up_write)))
}

/// `stream-up`: one streaming POST for the uplink, a GET on a second
/// connection for the downlink.
pub async fn stream_up(
    cfg: Arc<Config>,
    dns: SyncDnsClient,
    stream: AnyStream,
    dest: SocksAddr,
) -> io::Result<AnyStream> {
    let host = host_of(&cfg, &dest);
    let session_id = cfg.generate_session_id();

    let (rh, mut wh) = tokio::io::split(stream);
    let post = prepare(
        &cfg,
        &cfg.normalized_uplink_http_method(),
        &host,
        &session_id,
        None,
        true,
    );
    let (up_write, mut up_read) = tokio::io::duplex(PIPE_BYTES);
    tokio::spawn(async move {
        if let Err(e) = write_request_head(
            &mut wh,
            &post,
            &[("Transfer-Encoding".to_string(), "chunked".to_string())],
        )
        .await
        {
            debug!("xhttp stream-up head failed: {}", e);
            return;
        }
        if let Err(e) = wh.flush().await {
            debug!("xhttp stream-up flush failed: {}", e);
            return;
        }
        let mut writer = ChunkedWriter::new(wh);
        if let Err(e) = pump_chunked(&mut up_read, &mut writer).await {
            debug!("xhttp stream-up upload failed: {}", e);
        }
        // The response only arrives once the server's downlink is done with
        // the POST body; read and discard it.
        let mut buf = BufReader::new(rh);
        if let Ok(resp) = h1::read_response_head(&mut buf).await {
            if resp.status != 200 {
                debug!("xhttp stream-up got status {}", resp.status);
            }
        }
    });

    let address = dest.host();
    let port = dest.port();
    let down_stream = new_tcp_stream(dns.clone(), &address, &port).await?;
    let (drh, mut dwh) = tokio::io::split(down_stream);
    let get = prepare(&cfg, "GET", &host, &session_id, None, false);
    write_request_head(&mut dwh, &get, &[]).await?;
    dwh.flush().await?;
    drop(dwh);
    let (down_read, _down_handle) = spawn_downlink(drh);

    Ok(Box::new(SplitStream::new(down_read, up_write)))
}

/// `packet-up`: the downlink is a GET on the dialled connection, each uplink
/// chunk is its own POST on a fresh connection.
pub async fn packet_up(
    cfg: Arc<Config>,
    dns: SyncDnsClient,
    stream: AnyStream,
    dest: SocksAddr,
) -> io::Result<AnyStream> {
    let host = host_of(&cfg, &dest);
    let session_id = cfg.generate_session_id();

    let (rh, mut wh) = tokio::io::split(stream);
    let get = prepare(&cfg, "GET", &host, &session_id, None, false);
    write_request_head(&mut wh, &get, &[]).await?;
    wh.flush().await?;
    drop(wh);

    let (down_read, down_handle) = spawn_downlink(rh);

    let (up_write, mut up_read) = tokio::io::duplex(PIPE_BYTES);
    tokio::spawn(async move {
        if let Err(e) = packet_up_writer(&cfg, &dns, &host, &session_id, &dest, &mut up_read).await
        {
            debug!("xhttp packet-up upload failed: {}", e);
        }
        // Every upload has been posted; closing the downlink connection is
        // what tells the server the session is over, which is what lets the
        // payload's read side see EOF.
        down_handle.abort();
    });

    Ok(Box::new(SplitStream::new(down_read, up_write)))
}

async fn packet_up_writer<R: AsyncRead + Unpin>(
    cfg: &Config,
    dns: &SyncDnsClient,
    host: &str,
    session_id: &str,
    dest: &SocksAddr,
    source: &mut R,
) -> io::Result<()> {
    let max = cfg.normalized_sc_max_each_post_bytes().value().max(1) as usize;
    let interval = cfg.normalized_sc_min_posts_interval_ms();
    let mut seq: u64 = 0;
    let mut pending = BytesMut::with_capacity(max.min(64 * 1024));
    let mut tmp = vec![0u8; 64 * 1024];

    loop {
        let n = match source.read(&mut tmp).await {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&tmp[..n]);
        // Everything read is posted, split into at most one POST's worth, so a
        // small interactive write is not held waiting for a full buffer.
        while !pending.is_empty() {
            let take = pending.len().min(max);
            let chunk = pending.split_to(take).freeze();
            post_packet(cfg, dns, host, session_id, dest, seq, chunk, interval).await?;
            seq += 1;
        }
    }
}

async fn post_packet(
    cfg: &Config,
    dns: &SyncDnsClient,
    host: &str,
    session_id: &str,
    dest: &SocksAddr,
    seq: u64,
    data: Bytes,
    interval: RangeConfig,
) -> io::Result<()> {
    if interval.from > 0 {
        let ms = interval.value().max(0) as u64;
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    let address = dest.host();
    let port = dest.port();
    let stream = new_tcp_stream((*dns).clone(), &address, &port).await?;
    let (rh, mut wh) = tokio::io::split(stream);
    let seq_str = seq.to_string();
    let post = prepare(
        cfg,
        &cfg.normalized_uplink_http_method(),
        host,
        session_id,
        Some(&seq_str),
        false,
    );

    let placement = cfg.normalized_uplink_data_placement();
    if placement == PLACEMENT_HEADER || placement == PLACEMENT_COOKIE {
        let encoded = b64::encode(&data);
        let chunk_size = cfg.normalized_uplink_chunk_size().value().max(64) as usize;
        let mut extra = Vec::new();
        for (i, chunk) in encoded.as_bytes().chunks(chunk_size).enumerate() {
            let text = String::from_utf8_lossy(chunk).into_owned();
            if placement == PLACEMENT_HEADER {
                extra.push((format!("{}-{}", cfg.uplink_data_key, i), text));
            } else {
                add_cookie(&mut extra, &format!("{}_{}", cfg.uplink_data_key, i), &text);
            }
        }
        write_request_head(&mut wh, &post, &extra).await?;
        wh.flush().await?;
    } else {
        let extra = vec![("Content-Length".to_string(), data.len().to_string())];
        write_request_head(&mut wh, &post, &extra).await?;
        wh.write_all(&data).await?;
        wh.flush().await?;
    }
    drop(wh);

    let mut buf = BufReader::new(rh);
    let resp = h1::read_response_head(&mut buf).await?;
    if resp.status != 200 {
        return Err(io::Error::other(format!(
            "xhttp upload got status {}",
            resp.status
        )));
    }
    Ok(())
}
