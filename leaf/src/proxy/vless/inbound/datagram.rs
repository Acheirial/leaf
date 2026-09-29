use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::debug;

use super::super::datagram::{encode_packet, PacketDecoder};
use crate::config;
use crate::{proxy::*, session::*};

/// A VLESS `cmd=2` stream: a fixed destination, then `[length:2][payload]`
/// datagrams in both directions.
pub struct Datagram<S> {
    stream: S,
    source: SocketAddr,
    destination: SocksAddr,
}

impl<S> Datagram<S> {
    pub fn new(stream: S, source: SocketAddr, destination: SocksAddr) -> Self {
        Datagram {
            stream,
            source,
            destination,
        }
    }
}

impl<S> InboundDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (reader, writer) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf {
                reader,
                decoder: PacketDecoder::new(),
                pending: VecDeque::new(),
                source: self.source,
                destination: self.destination,
            }),
            Box::new(DatagramSendHalf { writer }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other(
            "a VLESS datagram is carried over a stream, not a UDP socket",
        ))
    }
}

pub struct DatagramRecvHalf<T> {
    reader: ReadHalf<T>,
    decoder: PacketDecoder,
    pending: VecDeque<Vec<u8>>,
    source: SocketAddr,
    destination: SocksAddr,
}

#[async_trait]
impl<T> InboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        loop {
            if let Some(packet) = self.pending.pop_front() {
                let to_write = std::cmp::min(packet.len(), buf.len());
                buf[..to_write].copy_from_slice(&packet[..to_write]);
                return Ok((
                    to_write,
                    DatagramSource::new(self.source, None),
                    self.destination.clone(),
                ));
            }

            let mut io_buf = [0u8; 8192];
            let n = self
                .reader
                .read(&mut io_buf)
                .await
                .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
            if n == 0 {
                return Err(ProxyError::DatagramFatal(anyhow::anyhow!(
                    "vless udp stream closed"
                )));
            }
            self.decoder.push(&io_buf[..n]);
            while let Some(packet) = self.decoder.next_packet() {
                self.pending.push_back(packet);
            }
        }
    }
}

pub struct DatagramSendHalf<T> {
    writer: WriteHalf<T>,
}

#[async_trait]
impl<T> InboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        _src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.writer.write_all(&encode_packet(buf)).await?;
        self.writer.flush().await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}

/// The inbound UDP transport.
///
/// VLESS has no raw UDP transport: UDP travels inside a `cmd=2` stream, which
/// [`super::stream::Handler`] produces. This handler therefore accepts the
/// listener's UDP socket and yields nothing, rather than pretending to speak a
/// protocol VLESS does not define over datagrams.
pub struct Handler;

impl Handler {
    pub fn new(_settings: &config::VlessInboundSettings) -> anyhow::Result<Self> {
        Ok(Handler)
    }
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, _socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        debug!(
            "vless inbound does not serve a raw UDP transport; UDP is carried in a cmd=2 stream"
        );
        Ok(InboundTransport::Empty)
    }
}
