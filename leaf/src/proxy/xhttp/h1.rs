//! A very small HTTP/1.1 codec: just enough of the protocol for XHTTP.
//!
//! Both the inbound server and the outbound client use it, `content-length`
//! and `chunked` bodies included, one request per connection. Nothing here
//! keeps a connection alive, which is what Xray's HTTP/1.1 XHTTP transport
//! does too (`DisableKeepAlives`).

use std::io;
use std::pin::Pin;
use std::task::ready;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, ReadBuf};

fn trim_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

fn split_target(target: &str) -> (String, String) {
    match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub path: String,
    pub query: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// A value out of the query string, percent-decoded only enough to undo
    /// the form encoding this port itself emits (`+` is not a space here).
    pub fn query_param(&self, key: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == key {
                Some(percent_decode(v))
            } else {
                None
            }
        })
    }

    pub fn cookies(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for value in self
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Cookie"))
            .map(|(_, v)| v.as_str())
        {
            for pair in value.split(';') {
                if let Some((k, v)) = pair.trim().split_once('=') {
                    out.push((k.to_string(), v.to_string()));
                }
            }
        }
        out
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }

    pub fn body_kind(&self) -> BodyKind {
        if let Some(te) = self.header("Transfer-Encoding") {
            if te
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
            {
                return BodyKind::Chunked;
            }
        }
        if let Some(len) = self.header("Content-Length") {
            return BodyKind::Length(len.trim().parse::<u64>().unwrap_or(0));
        }
        BodyKind::Empty
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_kind(&self) -> BodyKind {
        if let Some(te) = self.header("Transfer-Encoding") {
            if te
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
            {
                return BodyKind::Chunked;
            }
        }
        if let Some(len) = self.header("Content-Length") {
            return BodyKind::Length(len.trim().parse::<u64>().unwrap_or(0));
        }
        BodyKind::Eof
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Reads a request head. The body, if any, stays in the reader.
pub async fn read_request_head<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    max_header_bytes: usize,
) -> io::Result<Request> {
    let mut total = 0usize;
    let mut line = Vec::new();

    let n = reader.read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before a request",
        ));
    }
    total += n;
    let request_line = String::from_utf8_lossy(trim_crlf(&line)).into_owned();
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").trim().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(io::Error::other("malformed request line"));
    }

    let mut headers = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside the request head",
            ));
        }
        total += n;
        if total > max_header_bytes {
            return Err(io::Error::other("request head too large"));
        }
        let head = trim_crlf(&line);
        if head.is_empty() {
            break;
        }
        if let Some(idx) = head.iter().position(|&b| b == b':') {
            let k = String::from_utf8_lossy(&head[..idx]).trim().to_string();
            let v = String::from_utf8_lossy(&head[idx + 1..]).trim().to_string();
            headers.push((k, v));
        }
    }

    let (path, query) = split_target(&target);
    Ok(Request {
        method,
        target,
        path,
        query,
        version,
        headers,
    })
}

/// Reads a response head. The body, if any, stays in the reader.
pub async fn read_response_head<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> io::Result<Response> {
    let mut line = Vec::new();
    let n = reader.read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before a response",
        ));
    }
    let status_line = String::from_utf8_lossy(trim_crlf(&line)).into_owned();
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().unwrap_or("");
    let status = parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .map_err(|_| io::Error::other("malformed status line"))?;

    let mut headers = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside the response head",
            ));
        }
        let head = trim_crlf(&line);
        if head.is_empty() {
            break;
        }
        if let Some(idx) = head.iter().position(|&b| b == b':') {
            let k = String::from_utf8_lossy(&head[..idx]).trim().to_string();
            let v = String::from_utf8_lossy(&head[idx + 1..]).trim().to_string();
            headers.push((k, v));
        }
    }
    Ok(Response { status, headers })
}

/// Writes a head: the first line, the headers, the blank line.
pub async fn write_head<W: AsyncWrite + Unpin>(
    w: &mut W,
    first_line: &str,
    headers: &[(String, String)],
) -> io::Result<()> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(first_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (k, v) in headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    use tokio::io::AsyncWriteExt;
    w.write_all(&out).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// No body at all.
    Empty,
    Length(u64),
    Chunked,
    /// Read until the peer closes.
    Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    Size,
    Data,
    AfterData,
}

/// An HTTP/1.1 message body as an `AsyncRead`. `reader` is handed over whole
/// so that bytes already buffered while the head was parsed are not lost.
pub struct BodyReader<R> {
    reader: R,
    kind: BodyKind,
    remaining: u64,
    chunk_remaining: u64,
    state: ChunkState,
    buf: BytesMut,
    finished: bool,
}

impl<R> BodyReader<R> {
    pub fn new(reader: R, kind: BodyKind) -> Self {
        let remaining = match kind {
            BodyKind::Length(n) => n,
            BodyKind::Empty => 0,
            _ => u64::MAX,
        };
        BodyReader {
            reader,
            kind,
            remaining,
            chunk_remaining: 0,
            state: ChunkState::Size,
            buf: BytesMut::new(),
            finished: kind == BodyKind::Empty,
        }
    }
}

const FILL_CHUNK: usize = 16 * 1024;

impl<R: AsyncRead + Unpin> BodyReader<R> {
    fn poll_fill(s: &mut Self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut tmp = [0u8; FILL_CHUNK];
        let mut rb = ReadBuf::new(&mut tmp);
        ready!(Pin::new(&mut s.reader).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        if n > 0 {
            s.buf.extend_from_slice(rb.filled());
        }
        Poll::Ready(Ok(n))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BodyReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        if dst.remaining() == 0 || s.finished {
            return Poll::Ready(Ok(()));
        }

        match s.kind {
            BodyKind::Empty => Poll::Ready(Ok(())),
            BodyKind::Eof => Pin::new(&mut s.reader).poll_read(cx, dst),
            BodyKind::Length(_) => {
                if s.remaining == 0 {
                    s.finished = true;
                    return Poll::Ready(Ok(()));
                }
                let want = (dst.remaining() as u64).min(s.remaining) as usize;
                let mut tmp = [0u8; FILL_CHUNK];
                let mut rb = ReadBuf::new(&mut tmp[..want.min(FILL_CHUNK)]);
                ready!(Pin::new(&mut s.reader).poll_read(cx, &mut rb))?;
                let n = rb.filled().len();
                if n == 0 {
                    s.finished = true;
                    return Poll::Ready(Ok(()));
                }
                dst.put_slice(rb.filled());
                s.remaining -= n as u64;
                if s.remaining == 0 {
                    s.finished = true;
                }
                Poll::Ready(Ok(()))
            }
            BodyKind::Chunked => loop {
                match s.state {
                    ChunkState::Size => {
                        if let Some(pos) = s.buf.iter().position(|&b| b == b'\n') {
                            let line = trim_crlf(&s.buf[..pos]);
                            let size = parse_chunk_size(line)
                                .ok_or_else(|| io::Error::other("malformed chunk size"))?;
                            s.buf.advance(pos + 1);
                            if size == 0 {
                                s.finished = true;
                                return Poll::Ready(Ok(()));
                            }
                            s.chunk_remaining = size;
                            s.state = ChunkState::Data;
                        } else {
                            if ready!(Self::poll_fill(s, cx))? == 0 {
                                s.finished = true;
                                return Poll::Ready(Ok(()));
                            }
                        }
                    }
                    ChunkState::Data => {
                        if s.chunk_remaining == 0 {
                            s.state = ChunkState::AfterData;
                            continue;
                        }
                        if !s.buf.is_empty() {
                            let n = (dst.remaining() as u64)
                                .min(s.buf.len() as u64)
                                .min(s.chunk_remaining)
                                as usize;
                            dst.put_slice(&s.buf[..n]);
                            s.buf.advance(n);
                            s.chunk_remaining -= n as u64;
                            return Poll::Ready(Ok(()));
                        }
                        if ready!(Self::poll_fill(s, cx))? == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eof inside a chunk",
                            )));
                        }
                    }
                    ChunkState::AfterData => {
                        if s.buf.len() >= 2 {
                            if &s.buf[..2] == b"\r\n" {
                                s.buf.advance(2);
                                s.state = ChunkState::Size;
                            } else if s.buf[0] == b'\n' {
                                s.buf.advance(1);
                                s.state = ChunkState::Size;
                            } else {
                                return Poll::Ready(Err(io::Error::other(
                                    "malformed chunk terminator",
                                )));
                            }
                        } else if ready!(Self::poll_fill(s, cx))? == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eof after a chunk",
                            )));
                        }
                    }
                }
            },
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let line = match line.iter().position(|&b| b == b';') {
        Some(i) => &line[..i],
        None => line,
    };
    let text = String::from_utf8_lossy(line);
    u64::from_str_radix(text.trim(), 16).ok()
}

/// Writes an HTTP/1.1 body using chunked transfer encoding. `poll_shutdown`
/// writes the final zero-length chunk.
pub struct ChunkedWriter<W> {
    inner: W,
    pending: BytesMut,
    shutdown: bool,
}

impl<W> ChunkedWriter<W> {
    pub fn new(inner: W) -> Self {
        ChunkedWriter {
            inner,
            pending: BytesMut::new(),
            shutdown: false,
        }
    }

    fn flush_pending(s: &mut Self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !s.pending.is_empty() {
            let n = ready!(Pin::new(&mut s.inner).poll_write(cx, &s.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write a chunk",
                )));
            }
            s.pending.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ChunkedWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let s = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if s.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            )));
        }
        if s.pending.is_empty() {
            s.pending
                .extend_from_slice(format!("{:x}\r\n", buf.len()).as_bytes());
            s.pending.extend_from_slice(buf);
            s.pending.extend_from_slice(b"\r\n");
        }
        ready!(Self::flush_pending(s, cx))?;
        ready!(Pin::new(&mut s.inner).poll_flush(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        ready!(Self::flush_pending(s, cx))?;
        Pin::new(&mut s.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        if s.shutdown {
            return Poll::Ready(Ok(()));
        }
        s.pending.extend_from_slice(b"0\r\n\r\n");
        ready!(Self::flush_pending(s, cx))?;
        ready!(Pin::new(&mut s.inner).poll_flush(cx))?;
        s.shutdown = true;
        Pin::new(&mut s.inner).poll_shutdown(cx)
    }
}
