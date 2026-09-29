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
//! server (decryption): mlkem768x25519plus.{native|xorpub|random}.{N[s][-M[s]]}.[padding.]{key}[.{key}]
//! client (encryption): mlkem768x25519plus.{native|xorpub|random}.{0rtt|1rtt}.[padding.]{key}[.{key}]
//! ```
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

/// The client half of a VLESS encryption conversation.
pub struct ClientInstance {
    scheme: ClientScheme,
}

impl ClientInstance {
    /// Parses the outbound `encryption` setting.
    pub fn from_encryption(encryption: &str) -> anyhow::Result<Self> {
        let scheme = ClientScheme::parse(encryption)?;
        Err(anyhow::Error::new(EncryptionError::Unsupported(format!(
            "the {} handshake is not implemented in this build",
            scheme_label(&scheme)
        ))))
    }

    /// Performs the handshake and wraps `stream` in the record layer.
    pub async fn handshake(&self, _stream: AnyStream) -> io::Result<AnyStream> {
        Err(io::Error::other(
            "VLESS encryption handshake is not implemented",
        ))
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
            "the {} handshake is not implemented in this build",
            scheme_label_server(&scheme)
        ))))
    }

    /// Performs the handshake and wraps `stream` in the record layer.
    pub async fn handshake(&self, _stream: AnyStream) -> io::Result<AnyStream> {
        Err(io::Error::other(
            "VLESS encryption handshake is not implemented",
        ))
    }
}

fn scheme_label(scheme: &ClientScheme) -> String {
    format!("mlkem768x25519plus.{:?}.{}rtt", scheme.mode, scheme.seconds)
}

fn scheme_label_server(scheme: &ServerScheme) -> String {
    format!("mlkem768x25519plus.{:?}", scheme.mode)
}
