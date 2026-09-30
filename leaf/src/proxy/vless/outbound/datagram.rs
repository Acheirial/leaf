use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::super::datagram::{encode_packet, encode_udp_header, PacketDecoder};
use super::super::encoding::{Addons, VERSION};
use super::super::encryption::ClientInstance;
use crate::app::SyncDnsClient;
use crate::config;
use crate::{proxy::*, session::*};

pub struct Handler {
    address: String,
    port: u16,
    uuid: [u8; 16],
    encryption: Option<Arc<ClientInstance>>,
}

impl Handler {
    pub fn new(
        settings: &config::VlessOutboundSettings,
        _dns_client: SyncDnsClient,
    ) -> anyhow::Result<Self> {
        let uuid = uuid::Uuid::parse_str(&settings.uuid)
            .map_err(|e| anyhow::anyhow!("invalid vless uuid {}: {}", settings.uuid, e))?;
        let encryption = match settings.encryption.as_deref() {
            Some(e) if !e.is_empty() && e != "none" => {
                Some(Arc::new(ClientInstance::from_encryption(e)?))
            }
            _ => None,
        };
        Ok(Handler {
            address: settings.address.clone(),
            port: settings.port as u16,
            uuid: *uuid.as_bytes(),
            encryption,
        })
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let mut stream = match transport {
            Some(OutboundTransport::Stream(stream)) => stream,
            _ => return Err(io::Error::other("invalid input")),
        };

        if let Some(encryption) = &self.encryption {
            stream = encryption.handshake(stream).await?;
        }

        let header = encode_udp_header(&self.uuid, &sess.destination, &Addons::default());

        Ok(Box::new(Datagram {
            stream,
            destination: sess.destination.clone(),
            header: Some(header),
        }))
    }
}

pub struct Datagram<S> {
    stream: S,
    destination: SocksAddr,
    header: Option<Vec<u8>>,
}

impl<S> OutboundDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf {
                reader: r,
                decoder: PacketDecoder::new(),
                header: ResponseHeader::new(),
                buffer: VecDeque::new(),
                destination: self.destination,
            }),
            Box::new(DatagramSendHalf {
                writer: w,
                header: self.header,
            }),
        )
    }
}

/// Consumes the server's response header before the datagrams begin. It is a
/// `[version:1][addons len:1][addons]` tuple with normally empty addons.
struct ResponseHeader {
    parsed: bool,
    buffer: Vec<u8>,
    needed: Option<usize>,
}

impl ResponseHeader {
    fn new() -> Self {
        ResponseHeader {
            parsed: false,
            buffer: Vec::new(),
            needed: None,
        }
    }
}

pub struct DatagramRecvHalf<T> {
    reader: ReadHalf<T>,
    decoder: PacketDecoder,
    header: ResponseHeader,
    buffer: VecDeque<Vec<u8>>,
    destination: SocksAddr,
}

#[async_trait]
impl<T> OutboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        loop {
            if let Some(payload) = self.buffer.pop_front() {
                let to_write = std::cmp::min(payload.len(), buf.len());
                buf[..to_write].copy_from_slice(&payload[..to_write]);
                return Ok((to_write, self.destination.clone()));
            }

            let mut io_buf = [0u8; 8192];
            let n = self.reader.read(&mut io_buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }

            let chunk = &io_buf[..n];
            if !self.header.parsed {
                self.header.buffer.extend_from_slice(chunk);
                if self.header.needed.is_none() && self.header.buffer.len() >= 2 {
                    self.header.needed = Some(2 + self.header.buffer[1] as usize);
                }
                if self
                    .header
                    .needed
                    .map_or(false, |needed| self.header.buffer.len() >= needed)
                {
                    let needed = self.header.needed.unwrap();
                    if self.header.buffer[0] != VERSION {
                        return Err(io::Error::other(format!(
                            "vless: unexpected response version {} (expecting {})",
                            self.header.buffer[0], VERSION
                        )));
                    }
                    self.header.buffer.drain(..needed);
                    self.header.parsed = true;
                    let rest = std::mem::take(&mut self.header.buffer);
                    self.decoder.push(&rest);
                } else {
                    continue;
                }
            } else {
                self.decoder.push(chunk);
            }

            while let Some(packet) = self.decoder.next_packet() {
                self.buffer.push_back(packet);
            }
        }
    }
}

pub struct DatagramSendHalf<T> {
    writer: WriteHalf<T>,
    header: Option<Vec<u8>>,
}

#[async_trait]
impl<T> OutboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocksAddr) -> io::Result<usize> {
        let mut frame = Vec::with_capacity(buf.len() + 2);
        if let Some(header) = self.header.take() {
            frame.extend_from_slice(&header);
        }
        frame.extend_from_slice(&encode_packet(buf));
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}
