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
//! # Why the record layer is not implemented
//!
//! The handshake keys are BLAKE3 derive-key outputs: Xray computes
//! `blake3.DeriveKey(k, string(ctx), key)` (`Xray-core/proxy/vless/encryption/common.go:159`),
//! where `ctx` is an arbitrary byte slice — the 16 random bytes of the client IV
//! (`client.go:111`), an encrypted header (`common.go:136`), the server's
//! pre-write random (`server.go:229`), and so on. Go's `string([]byte)` is a
//! byte-for-byte conversion, so the derive-key *context* is binary. BLAKE3's
//! derive-key mode hashes that context under the `DERIVE_KEY_CONTEXT` flag; the
//! `blake3` crate only exposes it over a UTF-8 `&str` (`derive_key(&str, ..)`,
//! `Hasher::new_derive_key(&str)`, `hazmat::hash_derive_key_context(&str)`) and
//! its `hazmat`/`guts` primitives cannot run the flagged compression over a raw
//! byte slice (`guts::ChunkState` is pinned to the plain-hash IV/key-0
//! configuration). The binary context is therefore not representable with the
//! crates this build depends on, and the AEAD key schedule cannot be reproduced;
//! the scheme is rejected at configuration time instead of being silently
//! downgraded.
//!
//! Keys are base64url (no padding) encoded: a 32-byte X25519 key or a
//! 1184-byte ML-KEM-768 encapsulation key on the client; a 32-byte X25519
//! private key or a 64-byte ML-KEM-768 seed on the server.

use std::io;

use crate::proxy::AnyStream;

mod scheme;

pub use scheme::{ClientScheme, ServerScheme, XorMode};

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

/// The capability this build is missing, quoted verbatim in every rejection so
/// a misconfiguration is never mistaken for a silent downgrade.
///
/// Xray derives every handshake key with `blake3.DeriveKey(k, string(ctx), key)`
/// over an arbitrary *binary* context: the 16-byte IV
/// (`Xray-core/proxy/vless/encryption/client.go:111`), an encrypted header
/// (`common.go:136`), the server pre-write random (`server.go:229`), and so on
/// (`NewAEAD` in `common.go:159`, `NewCTR` in `xor.go:13`). The `blake3` crate
/// exposes derive-key only for a UTF-8 `&str` context (`derive_key`,
/// `Hasher::new_derive_key`, `hazmat::hash_derive_key_context`) and its
/// `hazmat`/`guts` modules cannot run the `DERIVE_KEY_CONTEXT`-flagged hash over
/// a raw byte slice, so those keys cannot be reproduced with the available
/// crates.
const UNSUPPORTED_REASON: &str = "the blake3 crate exposes BLAKE3 derive-key only for a UTF-8 \
     `&str` context, but the reference derives every AEAD/XOR key over raw binary contexts \
     (e.g. the 16-byte IV and the encrypted headers in proxy/vless/encryption/common.go); a \
     raw-byte DERIVE_KEY_CONTEXT hash is not reachable through the crate's public or hazmat API";

/// The client half of a VLESS encryption conversation.
pub struct ClientInstance {
    scheme: ClientScheme,
}

impl ClientInstance {
    /// Parses the outbound `encryption` setting.
    pub fn from_encryption(encryption: &str) -> anyhow::Result<Self> {
        let scheme = ClientScheme::parse(encryption)?;
        Err(anyhow::Error::new(EncryptionError::Unsupported(format!(
            "the {} handshake is not implemented in this build: {}",
            scheme_label(&scheme),
            UNSUPPORTED_REASON
        ))))
    }

    /// Performs the handshake and wraps `stream` in the record layer.
    pub async fn handshake(&self, _stream: AnyStream) -> io::Result<AnyStream> {
        Err(io::Error::other(format!(
            "VLESS encryption handshake is not implemented: {UNSUPPORTED_REASON}"
        )))
    }
}

/// The server half of a VLESS encryption conversation.
pub struct ServerInstance {
    scheme: ServerScheme,
}

impl ServerInstance {
    /// Parses the inbound `decryption` setting.
    pub fn from_decryption(decryption: &str) -> anyhow::Result<Self> {
        let scheme = ServerScheme::parse(decryption)?;
        Err(anyhow::Error::new(EncryptionError::Unsupported(format!(
            "the {} handshake is not implemented in this build: {}",
            scheme_label_server(&scheme),
            UNSUPPORTED_REASON
        ))))
    }

    /// Performs the handshake and wraps `stream` in the record layer.
    pub async fn handshake(&self, _stream: AnyStream) -> io::Result<AnyStream> {
        Err(io::Error::other(format!(
            "VLESS encryption handshake is not implemented: {UNSUPPORTED_REASON}"
        )))
    }
}

fn scheme_label(scheme: &ClientScheme) -> String {
    format!("mlkem768x25519plus.{:?}.{}rtt", scheme.mode, scheme.seconds)
}

fn scheme_label_server(scheme: &ServerScheme) -> String {
    format!("mlkem768x25519plus.{:?}", scheme.mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn key(n: usize) -> String {
        URL_SAFE_NO_PAD.encode(vec![0x11; n])
    }

    /// A configured scheme must be rejected *by name*: this build cannot
    /// reproduce Xray's binary BLAKE3 derive-key contexts with the `blake3`
    /// crate, and the error must say so rather than silently dropping the
    /// encryption layer.
    #[test]
    fn encryption_schemes_are_rejected_with_the_missing_primitive() {
        let client = format!("mlkem768x25519plus.native.0rtt.{}", key(32));
        let err = ClientInstance::from_encryption(&client)
            .err()
            .expect("the handshake is not implemented")
            .to_string();
        assert!(err.contains("blake3"), "{err}");

        let server = format!("mlkem768x25519plus.random.600-1200s.{}", key(32));
        let err = ServerInstance::from_decryption(&server)
            .err()
            .expect("the handshake is not implemented")
            .to_string();
        assert!(err.contains("blake3"), "{err}");
    }
}
