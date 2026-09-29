//! The `cmd=2` datagram framing shared by both directions.
//!
//! A VLESS UDP request opens a stream with the UDP command and a single
//! destination, then carries every datagram as `[length:2][payload]`
//! (Xray's `LengthPacketWriter` / `LengthPacketReader`).

use crate::session::SocksAddr;

use super::encoding::{self, Addons, CMD_UDP};

/// Encodes the request header of a UDP (`cmd=2`) stream.
pub fn encode_udp_header(user: &[u8; 16], destination: &SocksAddr, addons: &Addons) -> Vec<u8> {
    encoding::encode_request_header(user, CMD_UDP, destination, addons)
}

/// The most a single datagram can be: its length is a `u16`.
pub const MAX_PACKET: usize = 0xffff;

/// Encodes one datagram into the `[length:2][payload]` framing.
pub fn encode_packet(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Reassembles `[length:2][payload]` datagrams from a byte stream.
#[derive(Default)]
pub struct PacketDecoder {
    buffer: Vec<u8>,
}

impl PacketDecoder {
    pub fn new() -> Self {
        PacketDecoder { buffer: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Pops the next complete datagram, if there is one.
    pub fn next_packet(&mut self) -> Option<Vec<u8>> {
        if self.buffer.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
        if self.buffer.len() < 2 + len {
            return None;
        }
        self.buffer.drain(..2);
        Some(self.buffer.drain(..len).collect())
    }
}
