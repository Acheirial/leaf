//! An [`h3::quic::Connection`] over quinn that separates Hysteria2 proxy
//! streams from HTTP/3 requests.
//!
//! The reference hands every incoming stream to its HTTP/3 server, which peeks
//! the first frame type and offers unrecognised ones to a `StreamDispatcher`
//! hook. h3 has no such hook, so the same decision is made one layer down: this
//! adapter peeks the first varint of every bidirectional stream and either
//! forwards the stream to the TCP proxy or replays the bytes into h3 as a
//! regular request.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::{BoxStream, StreamExt};
use h3::error::Code;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::proxy::hysteria2::protocol::{self, FRAME_TYPE_TCP_REQUEST};

/// A stream the adapter decided is a Hysteria2 TCP proxy request.
pub struct ProxiedStream {
    pub send: SendStream,
    pub recv: RecvStream,
}

/// What the adapter needs from the connection it belongs to.
pub struct AdapterContext {
    /// Set once the peer authenticated; before that, proxy streams are refused.
    pub authenticated: Arc<AtomicBool>,
    /// Where accepted proxy streams are handed over.
    pub proxied: mpsc::Sender<ProxiedStream>,
}

type OpenBiFuture = BoxFuture<'static, Result<(SendStream, RecvStream), quinn::ConnectionError>>;
type OpenUniFuture = BoxFuture<'static, Result<SendStream, quinn::ConnectionError>>;

pub struct H3Connection {
    conn: quinn::Connection,
    incoming_bi: BoxStream<'static, Result<(SendStream, RecvStream), quinn::ConnectionError>>,
    incoming_uni: BoxStream<'static, Result<RecvStream, quinn::ConnectionError>>,
    pending: Option<Peeking>,
    opening_bi: Option<OpenBiFuture>,
    opening_uni: Option<OpenUniFuture>,
    ctx: Arc<AdapterContext>,
}

struct Peeking {
    send: SendStream,
    fut: BoxFuture<'static, (RecvStream, io::Result<(u64, Bytes)>)>,
}

impl H3Connection {
    pub fn new(conn: quinn::Connection, ctx: Arc<AdapterContext>) -> Self {
        let incoming_bi = Box::pin(futures::stream::unfold(conn.clone(), |conn| async move {
            Some((conn.accept_bi().await, conn))
        }));
        let incoming_uni = Box::pin(futures::stream::unfold(conn.clone(), |conn| async move {
            Some((conn.accept_uni().await, conn))
        }));
        Self {
            conn,
            incoming_bi,
            incoming_uni,
            pending: None,
            opening_bi: None,
            opening_uni: None,
            ctx,
        }
    }
}

/// Reads the first varint of a stream, leaving the stream positioned right
/// after it. The raw bytes are returned so they can be replayed to h3.
async fn peek_frame_type(mut recv: RecvStream) -> (RecvStream, io::Result<(u64, Bytes)>) {
    let mut first = [0u8; 1];
    if let Err(e) = recv.read_exact(&mut first).await {
        return (recv, Err(io::Error::other(e)));
    }
    let len = protocol::varint_len_of_first_byte(first[0]);
    let mut raw = BytesMut::with_capacity(len);
    raw.extend_from_slice(&first);
    if len > 1 {
        let mut rest = vec![0u8; len - 1];
        if let Err(e) = recv.read_exact(&mut rest).await {
            return (recv, Err(io::Error::other(e)));
        }
        raw.extend_from_slice(&rest);
    }
    let value = match protocol::get_varint(&raw) {
        Ok((value, _)) => value,
        Err(e) => return (recv, Err(io::Error::other(e))),
    };
    (recv, Ok((value, raw.freeze())))
}

/// Polls the "open a bidirectional stream" slot, keeping the in-flight future
/// so a pending open is not cancelled by a later poll.
fn poll_open_bi_stream(
    conn: &quinn::Connection,
    slot: &mut Option<OpenBiFuture>,
    cx: &mut Context<'_>,
) -> Poll<Result<H3BidiStream, StreamErrorIncoming>> {
    if slot.is_none() {
        let conn = conn.clone();
        *slot = Some(Box::pin(async move { conn.open_bi().await }));
    }
    let fut = slot.as_mut().expect("just created");
    match fut.as_mut().poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok((send, recv))) => {
            *slot = None;
            Poll::Ready(Ok(H3BidiStream {
                send: H3SendStream::new(send),
                recv: H3RecvStream::new(recv, Bytes::new()),
            }))
        }
        Poll::Ready(Err(e)) => {
            *slot = None;
            Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            }))
        }
    }
}

fn poll_open_uni_stream(
    conn: &quinn::Connection,
    slot: &mut Option<OpenUniFuture>,
    cx: &mut Context<'_>,
) -> Poll<Result<H3SendStream, StreamErrorIncoming>> {
    if slot.is_none() {
        let conn = conn.clone();
        *slot = Some(Box::pin(async move { conn.open_uni().await }));
    }
    let fut = slot.as_mut().expect("just created");
    match fut.as_mut().poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(send)) => {
            *slot = None;
            Poll::Ready(Ok(H3SendStream::new(send)))
        }
        Poll::Ready(Err(e)) => {
            *slot = None;
            Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            }))
        }
    }
}

fn close_connection(conn: &quinn::Connection, code: Code, reason: &[u8]) {
    conn.close(
        quinn::VarInt::from_u64(code.value()).unwrap_or(quinn::VarInt::MAX),
        reason,
    );
}

impl quic::Connection<Bytes> for H3Connection {
    type RecvStream = H3RecvStream;
    type OpenStreams = H3OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        match self.incoming_uni.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(ConnectionErrorIncoming::InternalError(
                "unidirectional stream source ended".to_string(),
            ))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(convert_connection_error(e))),
            Poll::Ready(Some(Ok(recv))) => Poll::Ready(Ok(H3RecvStream::new(recv, Bytes::new()))),
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        loop {
            if let Some(mut peeking) = self.pending.take() {
                match peeking.fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.pending = Some(peeking);
                        return Poll::Pending;
                    }
                    Poll::Ready((recv, res)) => {
                        let send = peeking.send;
                        match res {
                            Ok((frame_type, raw)) => {
                                if frame_type == FRAME_TYPE_TCP_REQUEST {
                                    if self.ctx.authenticated.load(Ordering::Relaxed) {
                                        trace!("hysteria2 inbound: proxied stream accepted");
                                        let stream = ProxiedStream { send, recv };
                                        if let Err(e) = self.ctx.proxied.try_send(stream) {
                                            debug!(
                                                "hysteria2 inbound: dropping proxied stream: {}",
                                                e
                                            );
                                        }
                                    } else {
                                        debug!(
                                            "hysteria2 inbound: proxy stream before authentication"
                                        );
                                        let mut send = send;
                                        let _ = send.reset(quinn::VarInt::from_u32(0x101));
                                    }
                                    // Not an HTTP/3 request; keep accepting.
                                    continue;
                                }
                                return Poll::Ready(Ok(H3BidiStream {
                                    send: H3SendStream::new(send),
                                    recv: H3RecvStream::new(recv, raw),
                                }));
                            }
                            Err(e) => {
                                // The stream died before declaring a frame
                                // type. h3 has no way to skip a stream, so the
                                // connection is finished.
                                return Poll::Ready(Err(ConnectionErrorIncoming::Undefined(
                                    Arc::new(e),
                                )));
                            }
                        }
                    }
                }
            }

            match self.incoming_bi.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(ConnectionErrorIncoming::InternalError(
                        "bidirectional stream source ended".to_string(),
                    )))
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(convert_connection_error(e))),
                Poll::Ready(Some(Ok((send, recv)))) => {
                    self.pending = Some(Peeking {
                        send,
                        fut: Box::pin(peek_frame_type(recv)),
                    });
                }
            }
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        H3OpenStreams {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl quic::OpenStreams<Bytes> for H3Connection {
    type BidiStream = H3BidiStream;
    type SendStream = H3SendStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        poll_open_bi_stream(&self.conn, &mut self.opening_bi, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        poll_open_uni_stream(&self.conn, &mut self.opening_uni, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        close_connection(&self.conn, code, reason)
    }
}

/// Opens outgoing streams on the underlying connection.
pub struct H3OpenStreams {
    conn: quinn::Connection,
    opening_bi: Option<OpenBiFuture>,
    opening_uni: Option<OpenUniFuture>,
}

impl quic::OpenStreams<Bytes> for H3OpenStreams {
    type BidiStream = H3BidiStream;
    type SendStream = H3SendStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        poll_open_bi_stream(&self.conn, &mut self.opening_bi, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        poll_open_uni_stream(&self.conn, &mut self.opening_uni, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        close_connection(&self.conn, code, reason)
    }
}

/// Bidirectional stream, split into a send and a receive half.
pub struct H3BidiStream {
    send: H3SendStream,
    recv: H3RecvStream,
}

impl quic::BidiStream<Bytes> for H3BidiStream {
    type SendStream = H3SendStream;
    type RecvStream = H3RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl quic::RecvStream for H3BidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl quic::SendStream<Bytes> for H3BidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

/// A quinn receive stream with optional replayed bytes in front of it.
pub struct H3RecvStream {
    id: StreamId,
    prefix: Bytes,
    stream: Option<RecvStream>,
    fut: Option<BoxFuture<'static, (RecvStream, Result<Option<quinn::Chunk>, quinn::ReadError>)>>,
}

impl H3RecvStream {
    fn new(stream: RecvStream, prefix: Bytes) -> Self {
        let num: u64 = stream.id().into();
        Self {
            id: num.try_into().expect("valid stream id"),
            prefix,
            stream: Some(stream),
            fut: None,
        }
    }
}

impl quic::RecvStream for H3RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if !self.prefix.is_empty() {
            return Poll::Ready(Ok(Some(std::mem::take(&mut self.prefix))));
        }
        if self.fut.is_none() {
            let mut stream = self.stream.take().expect("stream is present");
            self.fut = Some(Box::pin(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            }));
        }
        let fut = self.fut.as_mut().expect("just created");
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((stream, res)) => {
                self.fut = None;
                self.stream = Some(stream);
                match res {
                    Ok(Some(chunk)) => Poll::Ready(Ok(Some(chunk.bytes))),
                    Ok(None) => Poll::Ready(Ok(None)),
                    Err(e) => Poll::Ready(Err(convert_read_error(e))),
                }
            }
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        // While a read is in flight the read owns the stream; the request is
        // then simply not delivered, which is acceptable for a stop.
        if let Some(stream) = self.stream.as_mut() {
            let _ = stream.stop(quinn::VarInt::from_u64(error_code).unwrap_or(quinn::VarInt::MAX));
        }
    }

    fn recv_id(&self) -> StreamId {
        self.id
    }
}

/// A quinn send stream implementing h3's stream interface.
pub struct H3SendStream {
    stream: SendStream,
    writing: Option<WriteBuf<Bytes>>,
}

impl H3SendStream {
    fn new(stream: SendStream) -> Self {
        Self {
            stream,
            writing: None,
        }
    }
}

impl quic::SendStream<Bytes> for H3SendStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let H3SendStream { stream, writing } = self;
        if let Some(data) = writing.as_mut() {
            while data.has_remaining() {
                match Pin::new(&mut *stream).poll_write(cx, data.chunk()) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(n)) => data.advance(n),
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(convert_write_error(e)));
                    }
                }
            }
        }
        *writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "send_data called while the send stream is not ready".to_string(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))),
        )
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(quinn::VarInt::from_u64(reset_code).unwrap_or(quinn::VarInt::MAX));
    }

    fn send_id(&self) -> StreamId {
        let num: u64 = self.stream.id().into();
        num.try_into().expect("valid stream id")
    }
}

fn convert_connection_error(e: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match e {
        quinn::ConnectionError::ApplicationClosed(app) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: app.error_code.into_inner(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        other => ConnectionErrorIncoming::Undefined(Arc::new(other)),
    }
}

fn convert_read_error(e: quinn::ReadError) -> StreamErrorIncoming {
    match e {
        quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::ReadError::ConnectionLost(conn) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(conn),
        },
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}

fn convert_write_error(e: quinn::WriteError) -> StreamErrorIncoming {
    match e {
        quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(conn) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(conn),
        },
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}
