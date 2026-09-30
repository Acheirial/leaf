//! The record layer stream.
//!
//! [`CommonStream`] is the Rust equivalent of the reference `CommonConn`
//! (`Xray-core/proxy/vless/encryption/common.go`): it splits the inner VLESS
//! stream into TLS-shaped AEAD records. [`XorStream`] is `XorConn`
//! (`xor.go`), used by the `random` mode to XOR each record header so the
//! stream does not look like TLS.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::common::{
    decode_header, encode_header, Aead, AeadKind, AesCtr, MAX_RECORD_PLAINTEXT, RECORD_HEADER_LEN,
    TAG_LEN,
};

fn crypto_err() -> io::Error {
    io::Error::other("VLESS encryption record rejected")
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

enum ReadState {
    Header,
    Data(usize),
}

/// A VLESS stream carried as AEAD records.
pub(crate) struct CommonStream<S> {
    inner: S,
    kind: AeadKind,
    united_key: Vec<u8>,
    write_aead: Aead,
    peer_aead: Aead,
    /// Raw bytes (0-RTT only) written before the first record; the reference's
    /// `PreWrite`. Always empty for the modes this build supports.
    pre_write: Vec<u8>,

    read_buf: Vec<u8>,
    read_pos: usize,
    record_header: [u8; RECORD_HEADER_LEN],
    read_state: ReadState,
    pending: Vec<u8>,
    pending_off: usize,

    out: Vec<u8>,
    out_off: usize,
}

impl<S> CommonStream<S> {
    pub(crate) fn new(
        inner: S,
        kind: AeadKind,
        united_key: Vec<u8>,
        write_aead: Aead,
        peer_aead: Aead,
        pre_write: Vec<u8>,
    ) -> Self {
        CommonStream {
            inner,
            kind,
            united_key,
            write_aead,
            peer_aead,
            pre_write,
            read_buf: Vec::new(),
            read_pos: 0,
            record_header: [0u8; RECORD_HEADER_LEN],
            read_state: ReadState::Header,
            pending: Vec::new(),
            pending_off: 0,
            out: Vec::new(),
            out_off: 0,
        }
    }

    /// Read exactly `size` bytes into `read_buf`, resuming across polls.
    /// Returns `Ok(false)` when the peer closed before any byte was read.
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, size: usize) -> Poll<io::Result<bool>>
    where
        S: AsyncRead + Unpin,
    {
        if self.read_buf.len() < size {
            self.read_buf.resize(size, 0);
        }
        while self.read_pos < size {
            let mut rb = ReadBuf::new(&mut self.read_buf[self.read_pos..size]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                if self.read_pos == 0 {
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(early_eof()));
            }
            self.read_pos += n;
        }
        self.read_pos = 0;
        Poll::Ready(Ok(true))
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.out_off < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_off..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_off += n;
        }
        self.out.clear();
        self.out_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CommonStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.pending_off < me.pending.len() {
                let n = buf.remaining().min(me.pending.len() - me.pending_off);
                buf.put_slice(&me.pending[me.pending_off..me.pending_off + n]);
                me.pending_off += n;
                if me.pending_off == me.pending.len() {
                    me.pending.clear();
                    me.pending_off = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match me.read_state {
                ReadState::Header => {
                    if !ready!(me.poll_read_exact(cx, RECORD_HEADER_LEN))? {
                        return Poll::Ready(Ok(())); // clean EOF at a record boundary
                    }
                    me.record_header
                        .copy_from_slice(&me.read_buf[..RECORD_HEADER_LEN]);
                    let l = match decode_header(&me.record_header) {
                        Ok(l) => l,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    me.read_state = ReadState::Data(l);
                }
                ReadState::Data(l) => {
                    let rekey = me.peer_aead.max_nonce_reached();
                    if !ready!(me.poll_read_exact(cx, l))? {
                        return Poll::Ready(Err(early_eof()));
                    }
                    let ct = me.read_buf[..l].to_vec();
                    let pt = match me.peer_aead.open(&ct, &me.record_header) {
                        Some(pt) => pt,
                        None => return Poll::Ready(Err(crypto_err())),
                    };
                    if rekey {
                        let mut ctx = Vec::with_capacity(RECORD_HEADER_LEN + ct.len());
                        ctx.extend_from_slice(&me.record_header);
                        ctx.extend_from_slice(&ct);
                        me.peer_aead = Aead::new(&ctx, &me.united_key, me.kind);
                    }
                    me.pending = pt;
                    me.pending_off = 0;
                    me.read_state = ReadState::Header;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CommonStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.out_off < me.out.len() {
            // Flush the backlog before accepting more; a partial drain returns
            // Pending so the caller retries the same buffer.
            ready!(me.poll_flush_out(cx))?;
            if me.out_off < me.out.len() {
                return Poll::Pending;
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Emit any 0-RTT pre-write first.
        if !me.pre_write.is_empty() {
            let pre = std::mem::take(&mut me.pre_write);
            me.out.extend_from_slice(&pre);
        }
        let mut cursor = 0;
        while cursor < buf.len() {
            let end = (cursor + MAX_RECORD_PLAINTEXT).min(buf.len());
            let chunk = &buf[cursor..end];
            cursor = end;
            let mut header = [0u8; RECORD_HEADER_LEN];
            encode_header(&mut header, chunk.len() + TAG_LEN);
            let rekey = me.write_aead.max_nonce_reached();
            let start = me.out.len();
            me.out.extend_from_slice(&header);
            me.write_aead.seal_into(&mut me.out, chunk, &header);
            if rekey {
                let ctx = me.out[start..].to_vec();
                me.write_aead = Aead::new(&ctx, &me.united_key, me.kind);
            }
        }
        // Best-effort drain; anything left is buffered and flushed later.
        let _ = me.poll_flush_out(cx)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_flush_out(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_flush_out(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// `XorConn`: XORs the 5-byte header of every record and leaves the already
/// encrypted body alone (`xor.go:Write`/`Read`).
pub(crate) struct XorStream<S> {
    inner: S,
    out_ctr: AesCtr,
    in_ctr: AesCtr,
    out_skip: usize,
    out_header: Vec<u8>,
    in_skip: usize,
    in_header: Vec<u8>,
    out: Vec<u8>,
    out_off: usize,
}

impl<S> XorStream<S> {
    pub(crate) fn new(inner: S, out_ctr: AesCtr, in_ctr: AesCtr) -> Self {
        XorStream {
            inner,
            out_ctr,
            in_ctr,
            out_skip: 0,
            out_header: Vec::with_capacity(RECORD_HEADER_LEN),
            in_skip: 0,
            in_header: Vec::with_capacity(RECORD_HEADER_LEN),
            out: Vec::new(),
            out_off: 0,
        }
    }

    fn xor_records(&mut self, data: &mut [u8], inbound: bool) {
        let mut pos = 0;
        loop {
            let skip = if inbound { self.in_skip } else { self.out_skip };
            if data.len() - pos <= skip {
                if inbound {
                    self.in_skip = skip - (data.len() - pos);
                } else {
                    self.out_skip = skip - (data.len() - pos);
                }
                break;
            }
            pos += skip;
            if inbound {
                self.in_skip = 0;
            } else {
                self.out_skip = 0;
            }
            let have = if inbound {
                self.in_header.len()
            } else {
                self.out_header.len()
            };
            let need = RECORD_HEADER_LEN - have;
            if data.len() - pos < need {
                // The header spans this write; XOR what we have and remember
                // the partial header so the next call can decode it.
                let mut header = if inbound {
                    std::mem::take(&mut self.in_header)
                } else {
                    std::mem::take(&mut self.out_header)
                };
                header.extend_from_slice(&data[pos..]);
                if inbound {
                    self.in_ctr.apply(&mut data[pos..]);
                    self.in_header = header;
                } else {
                    self.out_ctr.apply(&mut data[pos..]);
                    self.out_header = header;
                }
                break;
            }
            // Reconstruct the plaintext header and decode the body length.
            let mut full = [0u8; RECORD_HEADER_LEN];
            let stored = if inbound {
                let h = std::mem::take(&mut self.in_header);
                h
            } else {
                let h = std::mem::take(&mut self.out_header);
                h
            };
            full[..stored.len()].copy_from_slice(&stored);
            full[stored.len()..].copy_from_slice(&data[pos..pos + need]);
            let body_len = decode_header(&full).unwrap_or(0);
            if inbound {
                self.in_ctr.apply(&mut data[pos..pos + need]);
                self.in_skip = body_len;
            } else {
                self.out_ctr.apply(&mut data[pos..pos + need]);
                self.out_skip = body_len;
            }
            pos += need;
        }
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.out_off < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_off..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_off += n;
        }
        self.out.clear();
        self.out_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for XorStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut me.inner).poll_read(cx, buf))?;
        let n = buf.filled().len() - before;
        if n > 0 {
            me.xor_records(&mut buf.filled_mut()[before..], true);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for XorStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.out_off < me.out.len() {
            ready!(me.poll_flush_out(cx))?;
            if me.out_off < me.out.len() {
                return Poll::Pending;
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut data = Vec::with_capacity(buf.len());
        data.extend_from_slice(buf);
        me.xor_records(&mut data, false);
        me.out = data;
        me.out_off = 0;
        let _ = me.poll_flush_out(cx)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_flush_out(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_flush_out(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
