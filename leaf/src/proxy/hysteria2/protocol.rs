//! Hysteria2 wire format: QUIC varints, the TCP request/response frames and
//! the UDP message carried by QUIC datagrams.
//!
//! Mirrors `core/internal/protocol` and `core/internal/frag` of the reference
//! implementation (`/home/dev/hysteria`).

use anyhow::{bail, Result};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Frame type of a TCP proxy request, sent as the first varint of a
/// client-initiated bidirectional stream.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

// Length caps, all straight from the reference; they exist to keep a hostile
// peer from making us allocate without bound.
pub const MAX_ADDRESS_LENGTH: u64 = 2048;
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
pub const MAX_PADDING_LENGTH: u64 = 4096;

/// Maximum size of a single QUIC datagram frame (the reference advertises this
/// and fragments UDP messages to fit).
pub const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
/// Maximum size of a serialized UDP message, fragmentation included.
pub const MAX_UDP_SIZE: usize = 4096;

const MAX_VARINT1: u64 = 63;
const MAX_VARINT2: u64 = 16383;
const MAX_VARINT4: u64 = 1073741823;
const MAX_VARINT8: u64 = 4611686018427387903;

/// Number of bytes a QUIC varint of `v` occupies.
pub fn varint_len(v: u64) -> usize {
    if v <= MAX_VARINT1 {
        1
    } else if v <= MAX_VARINT2 {
        2
    } else if v <= MAX_VARINT4 {
        4
    } else {
        8
    }
}

/// Appends `v` as a QUIC varint (RFC 9000 §16) to `buf`.
pub fn put_varint(buf: &mut Vec<u8>, v: u64) {
    debug_assert!(v <= MAX_VARINT8);
    if v <= MAX_VARINT1 {
        buf.push(v as u8);
    } else if v <= MAX_VARINT2 {
        buf.push(((v >> 8) as u8) | 0x40);
        buf.push(v as u8);
    } else if v <= MAX_VARINT4 {
        buf.push(((v >> 24) as u8) | 0x80);
        buf.push((v >> 16) as u8);
        buf.push((v >> 8) as u8);
        buf.push(v as u8);
    } else {
        buf.push(((v >> 56) as u8) | 0xc0);
        buf.push((v >> 48) as u8);
        buf.push((v >> 40) as u8);
        buf.push((v >> 32) as u8);
        buf.push((v >> 24) as u8);
        buf.push((v >> 16) as u8);
        buf.push((v >> 8) as u8);
        buf.push(v as u8);
    }
}

/// Length of a varint whose first byte is `b`.
pub fn varint_len_of_first_byte(b: u8) -> usize {
    1 << (b >> 6)
}

/// Decodes a QUIC varint from the start of `buf`, returning the value and the
/// number of bytes consumed.
pub fn get_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf.first().ok_or_else(|| anyhow::anyhow!("empty varint"))?;
    let len = varint_len_of_first_byte(first);
    if buf.len() < len {
        bail!("truncated varint");
    }
    Ok((decode_varint(&buf[..len]), len))
}

fn decode_varint(buf: &[u8]) -> u64 {
    match buf.len() {
        1 => (buf[0] & 0x3f) as u64,
        2 => (((buf[0] & 0x3f) as u64) << 8) | buf[1] as u64,
        4 => {
            (((buf[0] & 0x3f) as u64) << 24)
                | ((buf[1] as u64) << 16)
                | ((buf[2] as u64) << 8)
                | buf[3] as u64
        }
        _ => {
            (((buf[0] & 0x3f) as u64) << 56)
                | ((buf[1] as u64) << 48)
                | ((buf[2] as u64) << 40)
                | ((buf[3] as u64) << 32)
                | ((buf[4] as u64) << 24)
                | ((buf[5] as u64) << 16)
                | ((buf[6] as u64) << 8)
                | buf[7] as u64
        }
    }
}

/// Reads one QUIC varint from an async reader.
pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first).await?;
    let len = varint_len_of_first_byte(first[0]);
    if len == 1 {
        return Ok((first[0] & 0x3f) as u64);
    }
    let mut buf = [0u8; 8];
    buf[0] = first[0];
    r.read_exact(&mut buf[1..len]).await?;
    Ok(decode_varint(&buf[..len]))
}

/// Writes one QUIC varint to an async writer.
pub async fn write_varint<W: AsyncWrite + Unpin>(w: &mut W, v: u64) -> Result<()> {
    let mut buf = Vec::with_capacity(8);
    put_varint(&mut buf, v);
    w.write_all(&buf).await?;
    Ok(())
}

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A random padding string of length in `[min, max)`, as the reference's
/// `padding.String()` produces.
pub fn random_padding(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let n = if max > min {
        rng.gen_range(min..max)
    } else {
        min
    };
    (0..n)
        .map(|_| PADDING_CHARS[rng.gen_range(0..PADDING_CHARS.len())])
        .collect()
}

pub fn auth_request_padding() -> Vec<u8> {
    random_padding(256, 2048)
}

pub fn auth_response_padding() -> Vec<u8> {
    random_padding(256, 2048)
}

pub fn tcp_request_padding() -> Vec<u8> {
    random_padding(64, 512)
}

pub fn tcp_response_padding() -> Vec<u8> {
    random_padding(128, 1024)
}

/// Reads a TCP request. The frame type varint (`0x401`) must already have been
/// consumed -- the caller reads it to tell a proxy stream from an HTTP/3 one,
/// exactly like the reference's `ProxyStreamHijacker` does.
///
/// ```text
/// [varint] Address length
/// [bytes]  Address string (host:port)
/// [varint] Padding length
/// [bytes]  Random padding
/// ```
pub async fn read_tcp_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<String> {
    let addr_len = read_varint(r).await?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        bail!("invalid address length");
    }
    let mut addr = vec![0u8; addr_len as usize];
    r.read_exact(&mut addr).await?;
    let padding_len = read_varint(r).await?;
    if padding_len > MAX_PADDING_LENGTH {
        bail!("invalid padding length");
    }
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        r.read_exact(&mut padding).await?;
    }
    Ok(String::from_utf8_lossy(&addr).into_owned())
}

/// Serializes a TCP request, frame type included, into a buffer.
pub fn encode_tcp_request(addr: &str) -> Vec<u8> {
    let padding = tcp_request_padding();
    let addr = addr.as_bytes();
    let mut buf = Vec::with_capacity(16 + addr.len() + padding.len());
    put_varint(&mut buf, FRAME_TYPE_TCP_REQUEST);
    put_varint(&mut buf, addr.len() as u64);
    buf.extend_from_slice(addr);
    put_varint(&mut buf, padding.len() as u64);
    buf.extend_from_slice(&padding);
    buf
}

/// Writes a TCP request, frame type included.
pub async fn write_tcp_request<W: AsyncWrite + Unpin>(w: &mut W, addr: &str) -> Result<()> {
    w.write_all(&encode_tcp_request(addr)).await?;
    Ok(())
}

/// Reads a TCP response.
///
/// ```text
/// [uint8]  Status (0x00 = OK, 0x01 = Error)
/// [varint] Message length
/// [bytes]  Message string
/// [varint] Padding length
/// [bytes]  Random padding
/// ```
pub async fn read_tcp_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<(bool, String)> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status).await?;
    let msg_len = read_varint(r).await?;
    if msg_len > MAX_MESSAGE_LENGTH {
        bail!("invalid message length");
    }
    let mut msg = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        r.read_exact(&mut msg).await?;
    }
    let padding_len = read_varint(r).await?;
    if padding_len > MAX_PADDING_LENGTH {
        bail!("invalid padding length");
    }
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        r.read_exact(&mut padding).await?;
    }
    Ok((status[0] == 0, String::from_utf8_lossy(&msg).into_owned()))
}

/// Writes a TCP response.
pub async fn write_tcp_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    ok: bool,
    msg: &str,
) -> Result<()> {
    let padding = tcp_response_padding();
    let msg = msg.as_bytes();
    let mut buf = Vec::with_capacity(16 + msg.len() + padding.len());
    buf.push(if ok { 0 } else { 1 });
    put_varint(&mut buf, msg.len() as u64);
    buf.extend_from_slice(msg);
    put_varint(&mut buf, padding.len() as u64);
    buf.extend_from_slice(&padding);
    w.write_all(&buf).await?;
    Ok(())
}

/// A UDP message, carried in a QUIC datagram in both directions.
///
/// ```text
/// [uint32] Session ID
/// [uint16] Packet ID
/// [uint8]  Fragment ID
/// [uint8]  Fragment count
/// [varint] Address length
/// [bytes]  Address string (host:port)
/// [bytes]  Payload
/// ```
#[derive(Debug, Clone)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    /// Size of everything but the payload.
    pub fn header_size(&self) -> usize {
        8 + varint_len(self.addr.len() as u64) + self.addr.len()
    }

    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// Appends the serialized message to `out`, returning the number of bytes
    /// written.
    pub fn serialize(&self, out: &mut Vec<u8>) -> usize {
        out.reserve(self.size());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.packet_id.to_be_bytes());
        out.push(self.frag_id);
        out.push(self.frag_count);
        put_varint(out, self.addr.len() as u64);
        out.extend_from_slice(self.addr.as_bytes());
        out.extend_from_slice(&self.data);
        self.size()
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            bail!("message too short");
        }
        let session_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(buf[4..6].try_into().unwrap());
        let frag_id = buf[6];
        let frag_count = buf[7];
        let (addr_len, n) = get_varint(&buf[8..])?;
        if addr_len == 0 || addr_len > MAX_MESSAGE_LENGTH {
            bail!("invalid address length");
        }
        let start = 8 + n;
        // `<=` rather than `<`: at least one payload byte is expected.
        if buf.len() <= start + addr_len as usize {
            bail!("invalid message length");
        }
        let addr = String::from_utf8_lossy(&buf[start..start + addr_len as usize]).into_owned();
        let data = buf[start + addr_len as usize..].to_vec();
        Ok(Self {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data,
        })
    }
}

/// A packet ID for a message that has to be fragmented.
///
/// The reference assigns `uint16(rand.Intn(0xFFFF)) + 1`, i.e. uniformly from
/// `1..=u16::MAX`, and only when a message is actually split; zero is reserved
/// for unfragmented messages. Concurrent in-flight messages of one session
/// therefore carry distinct IDs, which is what lets the receiver's
/// single-packet-ID deframer tell their interleaved fragments apart.
pub fn random_packet_id() -> u16 {
    rand::thread_rng().gen_range(1..=u16::MAX)
}

/// Splits `m` so that every fragment fits in `max_size` bytes.
pub fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }
    let max_payload_size = max_size.saturating_sub(m.header_size());
    if max_payload_size == 0 || m.data.is_empty() {
        return Vec::new();
    }
    let frag_count = m.data.len().div_ceil(max_payload_size);
    let mut frags = Vec::with_capacity(frag_count);
    for (i, chunk) in m.data.chunks(max_payload_size).enumerate() {
        frags.push(UdpMessage {
            frag_id: i as u8,
            frag_count: frag_count as u8,
            data: chunk.to_vec(),
            ..m.clone()
        });
    }
    frags
}

/// Reassembles fragmented UDP messages. Like the reference, only one packet ID
/// is tracked at a time: a fragment of another packet resets the state, and a
/// packet with a missing fragment is dropped.
pub struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: usize,
}

impl Default for Defragger {
    fn default() -> Self {
        Self::new()
    }
}

impl Defragger {
    pub fn new() -> Self {
        Self {
            pkt_id: 0,
            frags: Vec::new(),
            count: 0,
        }
    }

    /// Feeds a message; returns the message itself when it is complete.
    ///
    /// Mirrors the reference's `frag.Defragger.Feed`: a fragment belonging to
    /// another packet (or declaring another fragment count) starts a fresh
    /// reassembly, a fragment of the known packet fills its slot, and a
    /// duplicate fragment of the known packet is dropped. State is deliberately
    /// *not* cleared once a message is assembled, so a retransmitted fragment
    /// is still recognised as a duplicate.
    pub fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            return None;
        }
        let idx = m.frag_id as usize;
        if m.packet_id != self.pkt_id || m.frag_count as usize != self.frags.len() {
            // New message, clear previous state.
            self.pkt_id = m.packet_id;
            self.frags = (0..m.frag_count).map(|_| None).collect();
            self.frags[idx] = Some(m);
            self.count = 1;
            return None;
        }
        if self.frags[idx].is_some() {
            return None;
        }
        self.frags[idx] = Some(m);
        self.count += 1;
        if self.count != self.frags.len() {
            return None;
        }
        let mut data = Vec::new();
        for frag in self.frags.iter() {
            let frag = frag.as_ref().expect("all fragments are present");
            data.extend_from_slice(&frag.data);
        }
        let head = self.frags[0].as_ref().expect("first fragment is present");
        Some(UdpMessage {
            session_id: head.session_id,
            packet_id: head.packet_id,
            frag_id: 0,
            frag_count: 1,
            addr: head.addr.clone(),
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            MAX_VARINT8,
        ] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_len(v));
            let (got, n) = get_varint(&buf).unwrap();
            assert_eq!(got, v);
            assert_eq!(n, buf.len());
        }
        // The frame type the reference uses.
        let mut buf = Vec::new();
        put_varint(&mut buf, FRAME_TYPE_TCP_REQUEST);
        assert_eq!(buf, vec![0x44, 0x01]);
    }

    #[test]
    fn udp_message_roundtrip() {
        let m = UdpMessage {
            session_id: 0xdeadbeef,
            packet_id: 7,
            frag_id: 0,
            frag_count: 1,
            addr: "example.com:443".to_string(),
            data: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        assert_eq!(m.serialize(&mut buf), m.size());
        assert_eq!(buf.len(), m.size());
        let parsed = UdpMessage::parse(&buf).unwrap();
        assert_eq!(parsed.session_id, m.session_id);
        assert_eq!(parsed.packet_id, m.packet_id);
        assert_eq!(parsed.addr, m.addr);
        assert_eq!(parsed.data, m.data);
        assert_eq!(parsed.size(), m.size());
    }

    #[test]
    fn udp_fragmentation_roundtrip() {
        let m = UdpMessage {
            session_id: 1,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: "1.2.3.4:53".to_string(),
            data: (0..4096u32).map(|i| i as u8).collect(),
        };
        let frags = frag_udp_message(&m, 1200);
        assert!(frags.len() > 1);
        for f in frags.iter() {
            assert!(f.size() <= 1200);
        }
        let mut d = Defragger::new();
        let mut done = None;
        for f in frags {
            if let Some(msg) = d.feed(f) {
                done = Some(msg);
            }
        }
        let done = done.expect("message should reassemble");
        assert_eq!(done.data, m.data);
        assert_eq!(done.addr, m.addr);
    }

    #[test]
    fn parser_rejects_bad_input() {
        assert!(UdpMessage::parse(&[0u8; 4]).is_err());
        // Address length of zero.
        let mut buf = vec![0u8; 8];
        buf.push(0);
        assert!(UdpMessage::parse(&buf).is_err());
    }

    fn frag(packet_id: u16, frag_id: u8, frag_count: u8, byte: u8) -> UdpMessage {
        UdpMessage {
            session_id: 1,
            packet_id,
            frag_id,
            frag_count,
            addr: "1.2.3.4:53".to_string(),
            data: vec![byte; 4],
        }
    }

    #[test]
    fn random_packet_id_is_never_zero() {
        // Zero is reserved for unfragmented messages.
        for _ in 0..1000 {
            assert_ne!(random_packet_id(), 0);
        }
    }

    #[test]
    fn fragmentation_keeps_the_packet_id() {
        let m = UdpMessage {
            session_id: 7,
            packet_id: random_packet_id(),
            frag_id: 0,
            frag_count: 1,
            addr: "1.2.3.4:53".to_string(),
            data: vec![0u8; 4096],
        };
        let frags = frag_udp_message(&m, 1200);
        assert!(frags.len() > 1);
        for f in &frags {
            // Every fragment of the message carries the same non-zero ID.
            assert_eq!(f.packet_id, m.packet_id);
            assert_eq!(f.frag_count as usize, frags.len());
        }
    }

    #[test]
    fn defragger_drops_duplicates_and_follows_packet_ids() {
        let mut d = Defragger::new();
        // Partial, then a duplicate of that fragment, then completion.
        assert!(d.feed(frag(100, 0, 2, 0xaa)).is_none());
        assert!(d.feed(frag(100, 0, 2, 0xaa)).is_none());
        let done = d.feed(frag(100, 1, 2, 0xbb)).expect("reassembled");
        let mut expected = vec![0xaa; 4];
        expected.extend_from_slice(&[0xbb; 4]);
        assert_eq!(done.data, expected);
        assert_eq!(done.packet_id, 100);
        assert_eq!(done.frag_count, 1);
        // A retransmitted fragment of the assembled packet is a duplicate.
        assert!(d.feed(frag(100, 1, 2, 0xbb)).is_none());
        // A different total count resets the state even for the same ID.
        assert!(d.feed(frag(100, 0, 3, 0xcc)).is_none());
        assert!(d.feed(frag(100, 1, 3, 0xcc)).is_none());
        let done = d.feed(frag(100, 2, 3, 0xcc)).expect("reassembled");
        assert_eq!(done.data, vec![0xcc; 12]);
    }
}
