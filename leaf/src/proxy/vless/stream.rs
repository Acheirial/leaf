//! The stream a VLESS client speaks over.
//!
//! After the request header (written by the outbound handler) the body may be
//! the `xtls-rprx-vision` flow: writes are padded into vision blocks and reads
//! are unpadded. The server always answers with a response header, which this
//! stream consumes lazily on the first read so the handler can return before
//! the peer has said anything.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::vision::{Padder, Unpadder};

pub struct VisionStream<S> {
    inner: S,
    padder: Padder,
    unpadder: Unpadder,
    /// Whether the VLESS response header still has to be consumed before the
    /// body, as it does on the client side.
    response_header_pending: bool,
    response_header: Vec<u8>,
    plaintext: Vec<u8>,
    /// Vision blocks that have been encoded but not yet written out.
    pending: Vec<u8>,
    pending_off: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
    /// Wraps a client stream: reads skip the response header, and the vision
    /// flow is applied when `vision` is set.
    pub fn client(inner: S, user_uuid: [u8; 16], vision: bool) -> Self {
        VisionStream {
            inner,
            padder: if vision {
                Padder::new(user_uuid)
            } else {
                Padder::disabled()
            },
            unpadder: if vision {
                Unpadder::new(user_uuid)
            } else {
                Unpadder::disabled()
            },
            response_header_pending: true,
            response_header: Vec::new(),
            plaintext: Vec::new(),
            pending: Vec::new(),
            pending_off: 0,
        }
    }

    /// Wraps a server stream: no response header to consume, and the vision
    /// flow is applied when `vision` is set.
    pub fn server(inner: S, user_uuid: [u8; 16], vision: bool) -> Self {
        VisionStream {
            inner,
            padder: if vision {
                Padder::new(user_uuid)
            } else {
                Padder::disabled()
            },
            unpadder: if vision {
                Unpadder::new(user_uuid)
            } else {
                Unpadder::disabled()
            },
            response_header_pending: false,
            response_header: Vec::new(),
            plaintext: Vec::new(),
            pending: Vec::new(),
            pending_off: 0,
        }
    }

    pub fn get_stream_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

/// Feeds a freshly read chunk through the response header and the unpadder,
/// appending any plaintext to `plaintext`.
fn consume_response_header(
    header: &mut Vec<u8>,
    pending: &mut bool,
    chunk: &[u8],
    unpadder: &mut Unpadder,
    plaintext: &mut Vec<u8>,
) {
    if !*pending {
        plaintext.extend_from_slice(&unpadder.unpad(chunk));
        return;
    }
    header.extend_from_slice(chunk);
    if header.len() < 2 {
        return;
    }
    let needed = 2 + header[1] as usize;
    if header.len() < needed {
        return;
    }
    let rest = header.split_off(needed);
    header.clear();
    *pending = false;
    plaintext.extend_from_slice(&unpadder.unpad(&rest));
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.plaintext.is_empty() {
                let len = std::cmp::min(buf.remaining(), this.plaintext.len());
                buf.put_slice(&this.plaintext[..len]);
                this.plaintext.drain(..len);
                return Poll::Ready(Ok(()));
            }

            let mut temp = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let chunk = read_buf.filled().to_vec();
                    consume_response_header(
                        &mut this.response_header,
                        &mut this.response_header_pending,
                        &chunk,
                        &mut this.unpadder,
                        &mut this.plaintext,
                    );
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Drain whatever an earlier write could not flush before taking more.
        if this.pending_off < this.pending.len() {
            match this.flush_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        this.pending = this.padder.pad(buf);
        this.pending_off = 0;
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // The data has been accepted into `pending`; report it as written
            // and let the next call apply backpressure.
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_off < self.pending.len() {
            let start = self.pending_off;
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.pending[start..]) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write vision block",
                )));
            }
            self.pending_off += n;
        }
        self.pending.clear();
        self.pending_off = 0;
        Poll::Ready(Ok(()))
    }
}
