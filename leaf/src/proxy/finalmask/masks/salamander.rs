//! The UDP `salamander` mask (Hysteria2's obfuscator).
//!
//! Every packet carries an 8-byte random salt followed by the payload XORed
//! with the BLAKE2b-256 keystream of `pre-shared key || salt`:
//!
//! ```text
//! wire = salt(8) || (payload ^ BLAKE2b256(psk || salt))
//! ```
//!
//! The keystream repeats every 32 bytes.

use std::io;

use serde_derive::Deserialize;
use serde_json::Value;

use super::{UdpMask, UdpMaskFactory};
use crate::proxy::finalmask::{rand_bytes_between, FinalmaskError};

const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
const PSK_MIN_LEN: usize = 4;

/// The keystream of one salt.
fn keystream(psk: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut input = Vec::with_capacity(psk.len() + SALT_LEN);
    input.extend_from_slice(psk);
    input.extend_from_slice(salt);
    blake2b_256(&input)
}

fn obfuscate(psk: &[u8], pkt: &[u8], out: &mut Vec<u8>) {
    let mut salt = [0u8; SALT_LEN];
    rand_bytes_between(&mut salt, 0, 255);
    let key = keystream(psk, &salt);
    out.clear();
    out.extend_from_slice(&salt);
    out.extend(pkt.iter().enumerate().map(|(i, b)| b ^ key[i % KEY_LEN]));
}

fn deobfuscate(psk: &[u8], pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < SALT_LEN {
        return None;
    }
    let salt: [u8; SALT_LEN] = pkt[..SALT_LEN].try_into().unwrap();
    let key = keystream(psk, &salt);
    Some(
        pkt[SALT_LEN..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % KEY_LEN])
            .collect(),
    )
}

pub struct SalamanderFactory {
    psk: Vec<u8>,
}

impl SalamanderFactory {
    pub fn new(settings: &Value) -> Result<Self, FinalmaskError> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            password: String,
        }
        let raw: Raw =
            serde_json::from_value(settings.clone()).map_err(|e| FinalmaskError::Invalid {
                mask: "salamander".to_string(),
                reason: e.to_string(),
            })?;
        if raw.password.len() < PSK_MIN_LEN {
            return Err(FinalmaskError::Invalid {
                mask: "salamander".to_string(),
                reason: format!("password must be at least {} bytes", PSK_MIN_LEN),
            });
        }
        Ok(SalamanderFactory {
            psk: raw.password.into_bytes(),
        })
    }
}

impl UdpMaskFactory for SalamanderFactory {
    fn create(&self, _role: super::Role) -> io::Result<Box<dyn UdpMask>> {
        Ok(Box::new(SalamanderMask {
            psk: self.psk.clone(),
        }))
    }
}

struct SalamanderMask {
    psk: Vec<u8>,
}

impl UdpMask for SalamanderMask {
    fn encode(
        &mut self,
        pkt: &[u8],
        _meta: &super::PacketMeta,
        out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut wire = Vec::with_capacity(pkt.len() + SALT_LEN);
        obfuscate(&self.psk, pkt, &mut wire);
        out(&wire)
    }

    fn decode(&mut self, pkt: &[u8], _meta: &super::PacketMeta) -> io::Result<Option<Vec<u8>>> {
        Ok(deobfuscate(&self.psk, pkt))
    }
}

// --- BLAKE2b-256 -----------------------------------------------------------
//
// Leaf's dependency set does not carry a hash crate unconditionally, and the
// salamander keystream needs the unkeyed 32-byte variant only, so the
// compression function lives here.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_256(input: &[u8]) -> [u8; KEY_LEN] {
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ KEY_LEN as u64;

    let mut t: u128 = 0;
    let mut buf = [0u8; 128];
    let mut buflen = 0usize;
    let mut data = input;

    while !data.is_empty() {
        if buflen == 128 {
            t += 128;
            compress(&mut h, &buf, t, false);
            buflen = 0;
        }
        let n = (128 - buflen).min(data.len());
        buf[buflen..buflen + n].copy_from_slice(&data[..n]);
        buflen += n;
        data = &data[n..];
    }
    t += buflen as u128;
    for b in buf[buflen..].iter_mut() {
        *b = 0;
    }
    compress(&mut h, &buf, t, true);

    let mut out = [0u8; KEY_LEN];
    for (i, word) in h.iter().take(4).enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        *word = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in SIGMA.iter() {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}
