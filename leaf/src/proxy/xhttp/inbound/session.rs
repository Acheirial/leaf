//! Server-side session state: the per-session upload reassembly queue.
//!
//! Xray keys an `httpSession` by session id and lets the downlink GET and every
//! uplink POST find it whichever connection they arrive on. The queue that
//! carries uploads to the downlink reader is bounded: at most
//! `scMaxBufferedPosts` (default 30) out-of-order packets are held, and the
//! session table itself is capped (see `MAX_SESSIONS`), so a flood of POSTs
//! cannot grow either without bound.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::{Buf, Bytes};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

/// One upload packet, either a whole `packet-up` body or the live body of a
/// `stream-up` POST.
pub enum Packet {
    Payload { seq: u64, data: Bytes },
    Reader(Box<dyn AsyncRead + Send + Sync + Unpin>),
}

/// The per-session state the server keeps. `rx` is claimed exactly once, by
/// the downlink that turns the session into a connection.
pub struct Session {
    pub tx: mpsc::Sender<Packet>,
    pub rx: Mutex<Option<mpsc::Receiver<Packet>>>,
    pub created: Instant,
}

impl Session {
    pub fn new(buffer: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer.max(1));
        Session {
            tx,
            rx: Mutex::new(Some(rx)),
            created: Instant::now(),
        }
    }

    /// Hands the receive half to the first caller, if a downlink has not
    /// claimed it yet; a later uplink only needs `tx`.
    pub fn claim_receiver(&self) -> Option<mpsc::Receiver<Packet>> {
        self.rx.lock().take()
    }
}

/// Reads a session's uploads in sequence order, reassembling `packet-up`
/// packets and switching to a direct reader for `stream-up`.
pub struct UploadQueueReader {
    rx: Mutex<mpsc::Receiver<Packet>>,
    heap: BinaryHeap<Reverse<(u64, Bytes)>>,
    current: Bytes,
    next_seq: u64,
    max_packets: usize,
    reader: Option<Box<dyn AsyncRead + Send + Sync + Unpin>>,
    done: bool,
}

impl UploadQueueReader {
    pub fn new(rx: mpsc::Receiver<Packet>, max_packets: usize) -> Self {
        UploadQueueReader {
            rx: Mutex::new(rx),
            heap: BinaryHeap::new(),
            current: Bytes::new(),
            next_seq: 0,
            max_packets: max_packets.max(1),
            reader: None,
            done: false,
        }
    }
}

impl AsyncRead for UploadQueueReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !s.current.is_empty() {
                let n = dst.remaining().min(s.current.len());
                dst.put_slice(&s.current[..n]);
                s.current.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(reader) = s.reader.as_mut() {
                return Pin::new(reader).poll_read(cx, dst);
            }
            if let Some(Reverse((seq, _))) = s.heap.peek() {
                if *seq == s.next_seq {
                    let Reverse((seq, data)) = s.heap.pop().expect("peeked");
                    s.next_seq = seq + 1;
                    s.current = data;
                    continue;
                }
            }
            if s.done {
                return Poll::Ready(Ok(()));
            }
            let next = {
                let mut guard = s.rx.lock();
                guard.poll_recv(cx)
            };
            match next {
                Poll::Ready(Some(Packet::Reader(reader))) => {
                    s.reader = Some(reader);
                }
                Poll::Ready(Some(Packet::Payload { seq, data })) => {
                    if seq == s.next_seq {
                        s.next_seq += 1;
                        s.current = data;
                    } else if seq > s.next_seq {
                        if s.heap.len() >= s.max_packets {
                            return Poll::Ready(Err(io::Error::other(
                                "xhttp upload reassembly buffer is too large",
                            )));
                        }
                        s.heap.push(Reverse((seq, data)));
                    } else {
                        // A duplicate already delivered; drop it.
                    }
                }
                Poll::Ready(None) => {
                    s.done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Wraps the live body of a `stream-up` POST so the POST handler learns when
/// the downlink is finished with it (the reader is dropped), which is when the
/// POST's response is written -- the same trigger Xray's `httpSC.Wait()` is.
pub struct DropNotifyReader<R> {
    inner: R,
    tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<R> DropNotifyReader<R> {
    pub fn new(inner: R, tx: tokio::sync::oneshot::Sender<()>) -> Self {
        DropNotifyReader {
            inner,
            tx: Some(tx),
        }
    }
}

impl<R> Drop for DropNotifyReader<R> {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DropNotifyReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, dst)
    }
}
