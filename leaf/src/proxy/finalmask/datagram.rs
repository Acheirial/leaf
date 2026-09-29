//! Wraps leaf's datagram transports with a [`UdpPipeline`] of masks.
//!
//! A socket carries one pipeline, shared by its receive and send halves, so
//! the masks that keep per-peer state (noise, header-custom) see both
//! directions of the same peer.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::proxy::*;
use crate::session::{DatagramSource, SocksAddr};

use super::masks::{PacketMeta, UdpPipeline};

/// The largest wire packet a mask can see: a UDP datagram's own limit.
const MAX_WIRE_PACKET: usize = 65535;

fn peer_addr(addr: &SocksAddr) -> Option<SocketAddr> {
    match addr {
        SocksAddr::Ip(addr) => Some(*addr),
        SocksAddr::Domain(..) => None,
    }
}

/// A mask pipeline over an inbound datagram.
pub struct MaskedInboundDatagram {
    inner: AnyInboundDatagram,
    pipeline: Arc<Mutex<UdpPipeline>>,
}

impl MaskedInboundDatagram {
    pub fn new(inner: AnyInboundDatagram, pipeline: UdpPipeline) -> Self {
        Self {
            inner,
            pipeline: Arc::new(Mutex::new(pipeline)),
        }
    }
}

impl InboundDatagram for MaskedInboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (recv, send) = self.inner.split();
        (
            Box::new(MaskedInboundRecvHalf {
                inner: recv,
                pipeline: self.pipeline.clone(),
                scratch: Vec::new(),
            }),
            Box::new(MaskedInboundSendHalf {
                inner: send,
                pipeline: self.pipeline,
            }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.inner.into_std()
    }
}

struct MaskedInboundRecvHalf {
    inner: Box<dyn InboundDatagramRecvHalf>,
    pipeline: Arc<Mutex<UdpPipeline>>,
    scratch: Vec<u8>,
}

#[async_trait]
impl InboundDatagramRecvHalf for MaskedInboundRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        loop {
            let want = (buf.len() + MAX_WIRE_PACKET).max(MAX_WIRE_PACKET);
            if self.scratch.len() < want {
                self.scratch.resize(want, 0);
            }
            let (n, src, dst) = self.inner.recv_from(&mut self.scratch).await?;
            let meta = PacketMeta {
                local: peer_addr(&dst),
                remote: Some(src.address),
            };
            let decoded = {
                let mut pipeline = self.pipeline.lock();
                pipeline.decode(&self.scratch[..n], &meta)
            };
            match decoded {
                Ok(Some(payload)) if payload.len() <= buf.len() => {
                    buf[..payload.len()].copy_from_slice(&payload);
                    return Ok((payload.len(), src, dst));
                }
                Ok(_) => continue,
                Err(e) => return Err(ProxyError::DatagramWarn(e.into())),
            }
        }
    }
}

struct MaskedInboundSendHalf {
    inner: Box<dyn InboundDatagramSendHalf>,
    pipeline: Arc<Mutex<UdpPipeline>>,
}

#[async_trait]
impl InboundDatagramSendHalf for MaskedInboundSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let meta = PacketMeta {
            local: peer_addr(src_addr),
            remote: Some(*dst_addr),
        };
        let wire = self
            .pipeline
            .lock()
            .encode(buf, &meta)
            .map_err(|e| io::Error::other(format!("finalmask encode failed: {}", e)))?;
        for pkt in &wire {
            self.inner.send_to(pkt, src_addr, dst_addr).await?;
        }
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}

/// A mask pipeline over an outbound datagram.
pub struct MaskedOutboundDatagram {
    inner: AnyOutboundDatagram,
    pipeline: Arc<Mutex<UdpPipeline>>,
}

impl MaskedOutboundDatagram {
    pub fn new(inner: AnyOutboundDatagram, pipeline: UdpPipeline) -> Self {
        Self {
            inner,
            pipeline: Arc::new(Mutex::new(pipeline)),
        }
    }
}

impl OutboundDatagram for MaskedOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (recv, send) = self.inner.split();
        (
            Box::new(MaskedOutboundRecvHalf {
                inner: recv,
                pipeline: self.pipeline.clone(),
                scratch: Vec::new(),
            }),
            Box::new(MaskedOutboundSendHalf {
                inner: send,
                pipeline: self.pipeline,
            }),
        )
    }
}

struct MaskedOutboundRecvHalf {
    inner: Box<dyn OutboundDatagramRecvHalf>,
    pipeline: Arc<Mutex<UdpPipeline>>,
    scratch: Vec<u8>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for MaskedOutboundRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        loop {
            let want = (buf.len() + MAX_WIRE_PACKET).max(MAX_WIRE_PACKET);
            if self.scratch.len() < want {
                self.scratch.resize(want, 0);
            }
            let (n, addr) = self.inner.recv_from(&mut self.scratch).await?;
            let meta = PacketMeta {
                local: None,
                remote: peer_addr(&addr),
            };
            let decoded = {
                let mut pipeline = self.pipeline.lock();
                pipeline.decode(&self.scratch[..n], &meta)
            };
            match decoded {
                Ok(Some(payload)) if payload.len() <= buf.len() => {
                    buf[..payload.len()].copy_from_slice(&payload);
                    return Ok((payload.len(), addr));
                }
                Ok(_) => continue,
                Err(e) => {
                    return Err(io::Error::other(format!("finalmask decode failed: {}", e)));
                }
            }
        }
    }
}

struct MaskedOutboundSendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
    pipeline: Arc<Mutex<UdpPipeline>>,
}

#[async_trait]
impl OutboundDatagramSendHalf for MaskedOutboundSendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        let meta = PacketMeta {
            local: None,
            remote: peer_addr(dst_addr),
        };
        let wire = self
            .pipeline
            .lock()
            .encode(buf, &meta)
            .map_err(|e| io::Error::other(format!("finalmask encode failed: {}", e)))?;
        for pkt in &wire {
            self.inner.send_to(pkt, dst_addr).await?;
        }
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}
