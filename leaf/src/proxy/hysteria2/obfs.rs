//! "Salamander" obfuscation: every QUIC packet on the wire is prefixed with an
//! 8-byte random salt and XORed with `BLAKE2b-256(PSK || salt)`.
//!
//! The reference wraps a `net.PacketConn` before handing it to its QUIC stack.
//! quinn lets a [`quinn::Runtime`] supply the socket it uses, so the same
//! effect is reached by wrapping the runtime: every UDP socket quinn creates
//! comes back obfuscated. This keeps the obfuscation below QUIC, where it can
//! not be confused with QUIC's own packet protection.

use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use anyhow::{bail, Result};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use parking_lot::Mutex;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

/// Length of the per-packet random salt.
pub const SALT_LEN: usize = 8;
/// Length of the BLAKE2b-256 obfuscation key.
pub const KEY_LEN: usize = 32;
/// Minimum pre-shared key length accepted by the reference.
pub const PSK_MIN_LEN: usize = 4;

/// Anything larger than a QUIC datagram; used to size the scratch buffer.
const MAX_PACKET_SIZE: usize = 65535;

type Blake2b256 = Blake2b<U32>;

/// `BLAKE2b-256(key + salt)`, the per-packet obfuscation key.
pub fn derive_key(psk: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = Blake2b256::new();
    hasher.update(psk);
    hasher.update(salt);
    let digest = hasher.finalize();
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&digest);
    key
}

/// Validates a salamander pre-shared key.
pub fn validate_psk(psk: &[u8]) -> Result<()> {
    if psk.len() < PSK_MIN_LEN {
        bail!("obfs password must be at least {} bytes", PSK_MIN_LEN);
    }
    Ok(())
}

/// A [`quinn::Runtime`] that obfuscates every UDP socket it hands out.
#[derive(Debug)]
pub struct ObfsRuntime {
    inner: TokioRuntime,
    psk: Arc<Vec<u8>>,
}

impl ObfsRuntime {
    pub fn new(psk: Vec<u8>) -> Self {
        Self {
            inner: TokioRuntime,
            psk: Arc::new(psk),
        }
    }
}

impl Runtime for ObfsRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(i)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future)
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = self.inner.wrap_udp_socket(socket)?;
        Ok(Arc::new(ObfsSocket {
            inner,
            psk: self.psk.clone(),
            scratch: Mutex::new(Vec::new()),
        }))
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

/// An obfuscating [`AsyncUdpSocket`].
///
/// Datagrams are limited to one per call in both directions: generic receive
/// offload would otherwise merge several QUIC packets into a single buffer and
/// make a single salt cover all of them, which the peer cannot undo.
#[derive(Debug)]
struct ObfsSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    psk: Arc<Vec<u8>>,
    scratch: Mutex<Vec<u8>>,
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut buf = self.scratch.lock();
        buf.clear();
        buf.resize(SALT_LEN + transmit.contents.len(), 0);
        if buf.len() <= SALT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty datagram",
            ));
        }
        {
            use rand::Rng;
            rand::thread_rng().fill(&mut buf[..SALT_LEN]);
        }
        let key = derive_key(&self.psk, &buf[..SALT_LEN]);
        for (i, b) in transmit.contents.iter().enumerate() {
            buf[SALT_LEN + i] = *b ^ key[i % KEY_LEN];
        }
        let obfuscated = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buf[..],
            // Batching is disabled below, so a transmit always holds exactly
            // one QUIC packet and one salt covers all of it.
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&obfuscated)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut scratch = self.scratch.lock();
        if scratch.len() < MAX_PACKET_SIZE {
            scratch.resize(MAX_PACKET_SIZE, 0);
        }
        let mut inner_meta = [RecvMeta::default()];
        let n = {
            let mut inner_bufs = [IoSliceMut::new(&mut scratch[..])];
            std::task::ready!(self.inner.poll_recv(cx, &mut inner_bufs, &mut inner_meta))?
        };

        let mut valid = 0;
        for i in 0..n.min(bufs.len()).min(meta.len()) {
            let len = inner_meta[i].len;
            // A datagram shorter than a salt plus one byte cannot be a valid
            // packet; the reference discards it too.
            if len <= SALT_LEN {
                continue;
            }
            let (salt, payload) = scratch[..len].split_at_mut(SALT_LEN);
            let key = derive_key(&self.psk, salt);
            for (j, b) in payload.iter_mut().enumerate() {
                *b ^= key[j % KEY_LEN];
            }
            let plain_len = payload.len();
            if plain_len > bufs[valid].len() {
                // Larger than what the caller can hold; drop it rather than
                // hand up a truncated packet.
                continue;
            }
            bufs[valid][..plain_len].copy_from_slice(payload);
            meta[valid] = RecvMeta {
                addr: inner_meta[i].addr,
                len: plain_len,
                stride: plain_len,
                ecn: inner_meta[i].ecn,
                dst_ip: inner_meta[i].dst_ip,
            };
            valid += 1;
        }
        Poll::Ready(Ok(valid))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test against `BLAKE2b-256(psk || salt)`, the formula in the
    /// protocol document. The expected digests were produced independently
    /// (Python's `hashlib.blake2b`), not by this code.
    #[test]
    fn key_matches_reference_vector() {
        let got = derive_key(b"test", &[1u8, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            got,
            [
                0xf2, 0xf8, 0xb0, 0xb3, 0xf1, 0xeb, 0x45, 0xcf, 0xe1, 0x6b, 0x76, 0x59, 0x30, 0x73,
                0xee, 0x7e, 0x7f, 0x04, 0x8a, 0x28, 0x6d, 0xec, 0x89, 0x89, 0x2d, 0x74, 0x0e, 0x5c,
                0x8d, 0xdc, 0x2a, 0xa3,
            ]
        );

        let got = derive_key(b"hysteria-obfs", &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
        assert_eq!(
            got,
            [
                0x32, 0x74, 0x07, 0xbb, 0x69, 0xe8, 0x71, 0xe5, 0x83, 0x4f, 0x42, 0x92, 0xd6, 0x34,
                0x06, 0x98, 0x6c, 0x3f, 0xbd, 0x53, 0x71, 0x07, 0x2a, 0x4f, 0xe7, 0x75, 0xbf, 0xb1,
                0xa1, 0x95, 0x44, 0x42,
            ]
        );
        assert_eq!(got.len(), KEY_LEN);
    }

    #[test]
    fn obfuscate_is_symmetric() {
        let psk = b"password";
        let plain = b"a quic packet lives here";
        let salt = [9u8; SALT_LEN];
        let key = derive_key(psk, &salt);
        let mut out = plain.to_vec();
        for (i, b) in out.iter_mut().enumerate() {
            *b ^= key[i % KEY_LEN];
        }
        assert_ne!(&out[..], &plain[..]);
        for (i, b) in out.iter_mut().enumerate() {
            *b ^= key[i % KEY_LEN];
        }
        assert_eq!(&out[..], &plain[..]);
    }

    #[test]
    fn psk_length_is_checked() {
        assert!(validate_psk(b"abc").is_err());
        assert!(validate_psk(b"abcd").is_ok());
    }
}
