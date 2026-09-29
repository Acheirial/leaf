//! The mask implementations of the FinalMask framework.
//!
//! A mask is a transform that sits below the protocol, like a transport pair
//! (ws/tls). Two shapes exist, one per transport:
//!
//! * [`TcpMask`] wraps a reliable byte stream. It is created per connection by
//!   a [`TcpMaskFactory`], because a mask instance is stateful (a stream coder,
//!   a handshake that has or has not run yet).
//! * [`UdpMask`] transforms one datagram at a time. A [`UdpMaskFactory`] makes
//!   the runtime instances, one per socket.
//!
//! The chain order is the configuration order, first entry closest to the
//! application. [`build_tcp`] therefore wraps from the back, so the first
//! configured mask ends up outermost, and [`UdpPipeline`] encodes forwards and
//! decodes backwards. Both match the transformation order of Xray's FinalMask.

pub mod custom;
pub mod fragment;
pub mod noise;
pub mod salamander;
pub mod sudoku;

use std::io;
use std::net::SocketAddr;

use crate::proxy::AnyStream;

/// Which side of the connection a mask instance belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

/// The addresses of one UDP packet, when they are known. Masks that need
/// per-peer state or address-derived expressions read them here.
#[derive(Clone, Default, Debug)]
pub struct PacketMeta {
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
}

/// A TCP mask bound to one side of one connection.
pub trait TcpMask: Send + Sync + Unpin {
    /// Wraps `inner`, returning the stream the layer above should read from
    /// and write to.
    fn wrap(self: Box<Self>, inner: AnyStream) -> io::Result<AnyStream>;
}

/// Creates a fresh [`TcpMask`] for a new connection.
pub trait TcpMaskFactory: Send + Sync + Unpin {
    fn create(&self, role: Role) -> io::Result<Box<dyn TcpMask>>;
}

/// A UDP mask bound to one side of one socket.
pub trait UdpMask: Send + Sync + Unpin {
    /// Encodes `pkt` toward the wire, calling `out` once for every packet to
    /// transmit. Most masks emit the payload exactly once; noise emits its
    /// decoys first. `out` applies the masks that are closer to the wire, so a
    /// mask must always route its output through it.
    fn encode(
        &mut self,
        pkt: &[u8],
        meta: &PacketMeta,
        out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()>;

    /// Decodes one wire packet. `Ok(None)` drops it, which is what a mask does
    /// with a packet that fails its check.
    fn decode(&mut self, pkt: &[u8], meta: &PacketMeta) -> io::Result<Option<Vec<u8>>>;
}

/// Creates a fresh [`UdpMask`] for a new socket.
pub trait UdpMaskFactory: Send + Sync + Unpin {
    fn create(&self, role: Role) -> io::Result<Box<dyn UdpMask>>;
}

/// Builds a TCP chain over `raw`.
///
/// The configuration order is preserved: the first entry ends up closest to
/// the application and is the first to transform an outgoing byte, exactly as
/// Xray's `DialTCP`/`Listen` nest them.
pub fn build_tcp(
    factories: &[Box<dyn TcpMaskFactory>],
    role: Role,
    raw: AnyStream,
) -> io::Result<AnyStream> {
    let mut stream = raw;
    for factory in factories.iter().rev() {
        let mask = factory.create(role)?;
        stream = mask.wrap(stream)?;
    }
    Ok(stream)
}

/// The runtime UDP chain, one per socket.
pub struct UdpPipeline {
    masks: Vec<Box<dyn UdpMask>>,
}

impl UdpPipeline {
    pub fn new(factories: &[Box<dyn UdpMaskFactory>], role: Role) -> io::Result<Self> {
        let mut masks = Vec::with_capacity(factories.len());
        for factory in factories {
            masks.push(factory.create(role)?);
        }
        Ok(Self { masks })
    }

    /// The packets to put on the wire for one payload.
    pub fn encode(&mut self, pkt: &[u8], meta: &PacketMeta) -> io::Result<Vec<Vec<u8>>> {
        let mut wire = Vec::new();
        encode_into(&mut self.masks, pkt, meta, &mut wire)?;
        Ok(wire)
    }

    /// The payload of one wire packet, or `None` when a mask drops it.
    pub fn decode(&mut self, pkt: &[u8], meta: &PacketMeta) -> io::Result<Option<Vec<u8>>> {
        let mut cur = pkt.to_vec();
        for mask in self.masks.iter_mut().rev() {
            match mask.decode(&cur, meta)? {
                Some(decoded) => cur = decoded,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }
}

fn encode_into(
    masks: &mut [Box<dyn UdpMask>],
    pkt: &[u8],
    meta: &PacketMeta,
    wire: &mut Vec<Vec<u8>>,
) -> io::Result<()> {
    match masks.split_first_mut() {
        None => {
            wire.push(pkt.to_vec());
            Ok(())
        }
        Some((first, rest)) => {
            let mut out = |p: &[u8]| encode_into(rest, p, meta, wire);
            first.encode(pkt, meta, &mut out)
        }
    }
}
