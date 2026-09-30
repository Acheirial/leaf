//! VLESS encryption (`mlkem768x25519plus`).
//!
//! The scheme is Xray's `proxy/vless/encryption`: an ML-KEM-768 + X25519
//! hybrid handshake in front of the VLESS stream, with the VLESS header and
//! body carried as AEAD records.
//!
//! The configuration strings are the ones described by
//! `Xray-core/infra/conf/vless.go`:
//!
//! ```text
//! server (decryption): mlkem768x25519plus.{native|xorpub|random}.{N[s]|N-M[s]}.[padding.]{key}[.{key}]
//! client (encryption): mlkem768x25519plus.{native|xorpub|random}.{0rtt|1rtt}.[padding.]{key}[.{key}]
//! ```
//!
//! The server seconds field is `N`, `Ns`, `N-M` or `N-Ms`: a single trailing
//! `s` belongs to the whole field, not to each bound
//! (`Xray-core/infra/conf/vless.go:121`).
//!
//! # Key schedule
//!
//! Every handshake key is a BLAKE3 derive-key output over an arbitrary
//! *binary* context: Xray computes `blake3.DeriveKey(k, string(ctx), key)`
//! (`Xray-core/proxy/vless/encryption/common.go:157-159`) where `ctx` is the
//! 16 random IV bytes (`client.go:111`), an encrypted header
//! (`common.go:136`), the server's pre-write random (`server.go:229`) or an
//! 1120/1216-byte PFS public key. Go's `string([]byte)` is byte-for-byte, and
//! the `blake3` crate only exposes derive-key over a UTF-8 `&str` (building a
//! `&str` from non-UTF-8 bytes would be unsound), so the primitive lives in
//! `blake3_derive` and is pinned to the crate's own output by its tests.
//!
//! # Supported surface
//!
//! `native`, `xorpub` and `random` relay disguise, the `1rtt` client mode and
//! the full server ticket/`seconds` grammar are implemented. Two things are
//! deliberately *not* implemented and are reported as named errors rather than
//! silently downgraded:
//!
//! * the client `0rtt` mode (the ticket cache), and
//! * accepting a 0-RTT handshake on the server (a `length == 32` hello).
//!
//! Everything else fails closed: a malformed record, a mismatched key or a
//! truncated stream aborts instead of falling back to a plaintext connection.

mod blake3_derive;
mod client;
mod common;
mod scheme;
mod server;
mod stream;

pub use client::ClientInstance;
pub use scheme::{ClientScheme, ServerScheme, XorMode};
pub use server::ServerInstance;

/// Errors raised while parsing or configuring VLESS encryption. Every one of
/// them is a configuration error: an unsupported or malformed scheme must be
/// rejected up front, never silently downgraded to plaintext.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("unsupported VLESS encryption: {0}")]
    Unsupported(String),
    #[error("invalid VLESS encryption scheme: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ml_kem::KeyExport;
    use rand::{thread_rng, RngCore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn b64(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    /// Drives a full client/server handshake over an in-process duplex and
    /// exchanges a payload both ways. Covers the ML-KEM-768 + X25519 hybrid
    /// key exchange, the relay chain and the record layer for every disguise
    /// mode.
    async fn round_trip(mode: &str) {
        let mut rng = thread_rng();
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(ml_kem::Seed::from(seed));
        let ek = dk.encapsulation_key().to_bytes();
        let ek = ek[..].to_vec();
        let mut xsk = [0u8; 32];
        rng.fill_bytes(&mut xsk);
        let xpk = x25519_dalek::x25519(xsk, x25519_dalek::X25519_BASEPOINT_BYTES);

        let server = ServerInstance::from_decryption(&format!(
            "mlkem768x25519plus.{mode}.0s.{}.{}",
            b64(&seed),
            b64(&xsk)
        ))
        .expect("server scheme");
        let client = ClientInstance::from_encryption(&format!(
            "mlkem768x25519plus.{mode}.1rtt.{}.{}",
            b64(&ek),
            b64(&xpk)
        ))
        .expect("client scheme");

        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server_task = tokio::spawn(async move {
            let mut s = server
                .handshake(Box::new(server_io))
                .await
                .expect("server handshake");
            let mut payload = [0u8; 7];
            s.read_exact(&mut payload).await.expect("server read");
            assert_eq!(&payload, b"payload");
            s.write_all(b"ok").await.unwrap();
            s.flush().await.unwrap();
        });

        let mut c = client
            .handshake(Box::new(client_io))
            .await
            .expect("client handshake");
        c.write_all(b"payload").await.unwrap();
        c.flush().await.unwrap();
        let mut got = [0u8; 2];
        c.read_exact(&mut got).await.expect("client read");
        assert_eq!(&got, b"ok");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn hybrid_round_trip_native() {
        round_trip("native").await;
    }

    #[tokio::test]
    async fn hybrid_round_trip_xorpub() {
        round_trip("xorpub").await;
    }

    #[tokio::test]
    async fn hybrid_round_trip_random() {
        round_trip("random").await;
    }

    #[tokio::test]
    async fn client_0rtt_is_a_named_error() {
        let mut key = [0u8; 1184];
        key[0] = 1;
        let err = ClientInstance::from_encryption(&format!(
            "mlkem768x25519plus.native.0rtt.{}",
            b64(&key)
        ))
        .err()
        .expect("0rtt must be rejected")
        .to_string();
        assert!(err.contains("0rtt"), "{err}");
    }
}
