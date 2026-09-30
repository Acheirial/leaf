//! Shared wire primitives for the `mlkem768x25519plus` record layer.
//!
//! This mirrors `Xray-core/proxy/vless/encryption/common.go` and `xor.go`
//! directly: the AEAD key schedule, the TLS-shaped record header, the padding
//! grammar and the AES-CTR used by the `xorpub`/`random` modes.

use std::io;
use std::time::Duration;

use aes::cipher::BlockEncrypt;
use aes_gcm::aead::{Aead as _, Payload as AesPayload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead as _, Payload as ChachaPayload};
use chacha20poly1305::ChaCha20Poly1305;

use super::blake3_derive::derive_key;

/// AEAD tag length; all supported ciphers use a 128-bit tag.
pub(crate) const TAG_LEN: usize = 16;

/// The record header the reference emits (`common.go:EncodeHeader`): a TLS 1.3
/// application-data record with the (ciphertext) length.
pub(crate) const RECORD_HEADER_LEN: usize = 5;

/// The largest plaintext the reference batches into one record
/// (`common.go:Write`, `b = b[:8192]`). The header can therefore carry at most
/// `8192 + 16 = 8208`, well inside the `17..=16640` accepted range.
pub(crate) const MAX_RECORD_PLAINTEXT: usize = 8192;

/// The all-ones nonce, used exactly once by each handshake for the PFS public
/// key exchange (`common.go:MaxNonce`).
pub(crate) const MAX_NONCE: [u8; 12] = [0xff; 12];

/// The ASCII context of the AES-CTR key schedule (`xor.go:13`). Unlike the AEAD
/// contexts this one really is a string, but it goes through the same binary
/// primitive.
const CTR_CONTEXT: &[u8] = b"VLESS";

/// Which AEAD the reference picks (`common.go:NewAEAD`). The server always
/// guesses AES first and flips on the first record if the client chose ChaCha
/// (`server.go:236-241`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadKind {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadKind {
    /// The client's choice, mirroring `protocol.HasAESGCMHardwareSupport`.
    pub(crate) fn client_default() -> Self {
        if has_aes_hardware() {
            AeadKind::Aes256Gcm
        } else {
            AeadKind::ChaCha20Poly1305
        }
    }

    /// The cipher for a `useAES` flag such as the server's fallback state.
    pub(crate) fn from_use_aes(use_aes: bool) -> Self {
        if use_aes {
            AeadKind::Aes256Gcm
        } else {
            AeadKind::ChaCha20Poly1305
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn has_aes_hardware() -> bool {
    is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn has_aes_hardware() -> bool {
    // Other backends are not probed here; ChaCha is the safe default, and the
    // server always tries AES first before flipping.
    false
}

enum Cipher {
    Aes(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

/// A nonce-carrying AEAD, exactly like the reference's `AEAD` struct: the
/// 12-byte nonce is incremented before every seal/open
/// (`common.go:IncreaseNonce`, little-endian over the last byte first).
pub(crate) struct Aead {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl Aead {
    /// `NewAEAD(ctx, key, useAES)`: derive a 32-byte key with
    /// `blake3.DeriveKey(k, string(ctx), key)` and build the cipher by kind.
    pub(crate) fn new(ctx: &[u8], key: &[u8], kind: AeadKind) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(&derive_key(ctx, key));
        let cipher = match kind {
            AeadKind::Aes256Gcm => Cipher::Aes(
                <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&k).expect("aes-256 key"),
            ),
            AeadKind::ChaCha20Poly1305 => Cipher::ChaCha(
                <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(&k)
                    .expect("chacha20 key"),
            ),
        };
        Aead {
            cipher,
            nonce: [0u8; 12],
        }
    }

    /// Whether the next auto-increment would wrap to the all-ones nonce, the
    /// signal the reference uses to rekey (`common.go:Write`/`Read`).
    pub(crate) fn max_nonce_reached(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        for i in (0..12).rev() {
            self.nonce[i] = self.nonce[i].wrapping_add(1);
            if self.nonce[i] != 0 {
                break;
            }
        }
        self.nonce
    }

    fn seal_with(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        match &self.cipher {
            Cipher::Aes(c) => c
                .encrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    AesPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .expect("AEAD seal cannot fail"),
            Cipher::ChaCha(c) => c
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    ChachaPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .expect("AEAD seal cannot fail"),
        }
    }

    fn open_with(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        match &self.cipher {
            Cipher::Aes(c) => c
                .decrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    AesPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .ok(),
            Cipher::ChaCha(c) => c
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    ChachaPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .ok(),
        }
    }

    /// Auto-nonce seal, appending the ciphertext to `dst`.
    pub(crate) fn seal_into(&mut self, dst: &mut Vec<u8>, plaintext: &[u8], aad: &[u8]) {
        let nonce = self.next_nonce();
        dst.extend_from_slice(&self.seal_with(&nonce, plaintext, aad));
    }

    /// Auto-nonce seal with an explicit nonce (the PFS exchange uses
    /// `MAX_NONCE`).
    pub(crate) fn seal_with_nonce(
        &mut self,
        nonce: &[u8; 12],
        dst: &mut Vec<u8>,
        plaintext: &[u8],
        aad: &[u8],
    ) {
        dst.extend_from_slice(&self.seal_with(nonce, plaintext, aad));
    }

    /// Auto-nonce open.
    pub(crate) fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.next_nonce();
        self.open_with(&nonce, ciphertext, aad)
    }

    /// Explicit-nonce open.
    pub(crate) fn open_with_nonce(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<Vec<u8>> {
        self.open_with(nonce, ciphertext, aad)
    }
}

/// AES-256-CTR keyed by `blake3.DeriveKey("VLESS", key)`, matching
/// `xor.go:NewCTR`. The counter is the whole 16-byte block, big-endian, as Go's
/// `cipher.NewCTR` does.
pub(crate) struct AesCtr {
    cipher: aes::Aes256,
    counter: u128,
    keystream: [u8; 16],
    pos: usize,
}

impl AesCtr {
    pub(crate) fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(&derive_key(CTR_CONTEXT, key));
        let cipher =
            <aes::Aes256 as aes::cipher::KeyInit>::new_from_slice(&k).expect("aes-256 key");
        AesCtr {
            cipher,
            counter: u128::from_be_bytes(*iv),
            keystream: [0u8; 16],
            pos: 16,
        }
    }

    fn refill(&mut self) {
        let mut block = aes::cipher::Block::<aes::Aes256>::default();
        block.copy_from_slice(&self.counter.to_be_bytes());
        self.cipher.encrypt_block(&mut block);
        self.keystream.copy_from_slice(&block);
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    /// XOR `data` with the keystream, continuing the counter across calls.
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == 16 {
                self.refill();
            }
            *b ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }
}

/// `common.go:EncodeLength`.
pub(crate) fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

/// `common.go:DecodeLength`.
pub(crate) fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | b[1] as usize
}

/// `common.go:EncodeHeader`: `17 03 03 <len:2>`.
pub(crate) fn encode_header(h: &mut [u8], l: usize) {
    h[0] = 23;
    h[1] = 3;
    h[2] = 3;
    h[3] = (l >> 8) as u8;
    h[4] = l as u8;
}

/// `common.go:DecodeHeader`: validate the TLS record header and return the
/// ciphertext length (`17..=16640`, the TLS 1.3 maximum record).
pub(crate) fn decode_header(h: &[u8]) -> io::Result<usize> {
    let mut l = ((h[3] as usize) << 8) | (h[4] as usize);
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        l = 0;
    }
    if !(17..=16640).contains(&l) {
        return Err(io::Error::other(format!(
            "invalid record header: {:?}",
            &h[..5]
        )));
    }
    Ok(l)
}

/// `common.go:ParsePadding`.
pub(crate) fn parse_padding(padding: &str) -> Result<(Vec<[i64; 3]>, Vec<[i64; 3]>), String> {
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    if padding.is_empty() {
        return Ok((lens, gaps));
    }
    let mut max_len: i64 = 0;
    for (i, s) in padding.split('.').enumerate() {
        let x: Vec<&str> = s.split('-').collect();
        if x.len() < 3 || x[0].is_empty() || x[1].is_empty() || x[2].is_empty() {
            return Err(format!("invalid padding length/gap parameter: {}", s));
        }
        let mut y = [0i64; 3];
        for (j, v) in x.iter().take(3).enumerate() {
            y[j] = v
                .parse::<i64>()
                .map_err(|_| format!("invalid padding length/gap parameter: {}", s))?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err("first padding length must not be smaller than 35".to_string());
        }
        if i % 2 == 0 {
            max_len += y[1].max(y[2]);
            lens.push(y);
        } else {
            gaps.push(y);
        }
    }
    if max_len > 18 + 65535 {
        return Err("total padding length must not be larger than 65553".to_string());
    }
    Ok((lens, gaps))
}

/// `crypto.RandBetween`: random in `[from, to)`, returning `from` when the
/// interval is empty or a single value.
fn rand_between(from: i64, to: i64) -> i64 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    let d = to - from;
    if d <= 1 {
        return from;
    }
    from + (rand::random::<u64>() % d as u64) as i64
}

/// `common.go:CreatPadding`: the padding lengths and inter-write gaps for one
/// handshake. The defaults match the reference when no padding is configured.
pub(crate) fn create_padding(
    lens: &[[i64; 3]],
    gaps: &[[i64; 3]],
) -> (usize, Vec<usize>, Vec<Duration>) {
    let default_lens = [[100i64, 111, 1111], [50, 0, 3333]];
    let default_gaps = [[75i64, 0, 111]];
    // The reference only substitutes the defaults when *no* padding lengths
    // were configured at all (`common.go:CreatPadding`); a configured length
    // with no gap simply produces no sleeps.
    let (lens, gaps): (&[[i64; 3]], &[[i64; 3]]) = if lens.is_empty() {
        (&default_lens, &default_gaps)
    } else {
        (lens, gaps)
    };

    let mut length = 0usize;
    let mut out_lens = Vec::with_capacity(lens.len());
    for y in lens {
        let l = if y[0] >= rand_between(0, 100) {
            rand_between(y[1], y[2]).max(0) as usize
        } else {
            0
        };
        length += l;
        out_lens.push(l);
    }
    let mut out_gaps = Vec::with_capacity(gaps.len());
    for y in gaps {
        let g = if y[0] >= rand_between(0, 100) {
            rand_between(y[1], y[2]).max(0)
        } else {
            0
        };
        out_gaps.push(Duration::from_millis(g as u64));
    }
    (length, out_lens, out_gaps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    #[test]
    fn header_round_trip_and_bounds() {
        let mut h = [0u8; 5];
        for l in [17usize, 18, 1234, 16640] {
            encode_header(&mut h, l);
            assert_eq!(decode_header(&h).unwrap(), l);
        }
        encode_header(&mut h, 16);
        assert!(decode_header(&h).is_err());
        encode_header(&mut h, 16641);
        assert!(decode_header(&h).is_err());
        let mut bad = [23u8, 3, 4, 0, 17];
        assert!(decode_header(&bad).is_err());
        bad = [22, 3, 3, 0, 17];
        assert!(decode_header(&bad).is_err());
    }

    #[test]
    fn padding_grammar_matches_reference() {
        assert!(parse_padding("").unwrap().0.is_empty());
        // First entry must be at least 100/35/35.
        assert!(parse_padding("99-111-1111").is_err());
        assert!(parse_padding("100-34-1111").is_err());
        assert!(parse_padding("100-111-34").is_err());
        let (lens, gaps) = parse_padding("100-111-1111.50-0-3333").unwrap();
        assert_eq!(lens, vec![[100, 111, 1111]]);
        assert_eq!(gaps, vec![[50, 0, 3333]]);
        assert!(parse_padding("100-111").is_err());
        assert!(parse_padding("100-111-1111.x-0-3").is_err());
    }

    #[test]
    fn ctr_matches_go_ctr_style() {
        // AES-256-CTR keystream for a known key/IV is deterministic; compare
        // two increments against encrypting the counter block directly.
        let key = [7u8; 32];
        let iv = [3u8; 16];
        let mut ctr = AesCtr::new(&key, &iv);
        let mut buf = [0u8; 40];
        ctr.apply(&mut buf);

        let mut k = [0u8; 32];
        k.copy_from_slice(&derive_key(CTR_CONTEXT, &key));
        let cipher = <aes::Aes256 as aes::cipher::KeyInit>::new_from_slice(&k).unwrap();
        let mut expected = Vec::new();
        for block_idx in 0u128..3 {
            let counter = u128::from_be_bytes(iv).wrapping_add(block_idx);
            let mut b = aes::cipher::Block::<aes::Aes256>::default();
            b.copy_from_slice(&counter.to_be_bytes());
            cipher.encrypt_block(&mut b);
            expected.extend_from_slice(&b);
        }
        assert_eq!(&buf[..], &expected[..40]);
    }

    #[test]
    fn aead_round_trip_and_tamper() {
        for kind in [AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
            let mut sealer = Aead::new(b"ctx", b"key material", kind);
            let mut opener = Aead::new(b"ctx", b"key material", kind);
            let mut out = Vec::new();
            sealer.seal_into(&mut out, b"hello", b"aad");
            assert_eq!(opener.open(&out, b"aad").unwrap(), b"hello");
            let mut bad = out.clone();
            bad[0] ^= 1;
            assert!(opener.open(&bad, b"aad").is_none());
            // Wrong AAD fails closed.
            assert!(opener.open(&out, b"other").is_none());
            // Wrong context fails closed.
            let mut wrong = Aead::new(b"ctx2", b"key material", kind);
            assert!(wrong.open(&out, b"aad").is_none());
        }
    }
}
