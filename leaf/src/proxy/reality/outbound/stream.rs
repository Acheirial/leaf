//! REALITY outbound (client) handler — aligned with Xray's `reality.UClient`.
//!
//! The authentication construction in [`super::super::stream::build_rustls_config`]
//! plus `RealityConnectionState::apply_reality` (in the `reality` crate) matches
//! Xray exactly:
//!
//! * `AuthKey = HKDF-SHA256(ikm = X25519(client_ephemeral, server_public_key),
//!   salt = ClientHello.random[0..20], info = "REALITY")`;
//! * `session_id = AES-256-GCM(AuthKey, nonce = random[20..32],
//!   plaintext = version[3] || 0 || unix_time[4] || short_id[8],
//!   aad = ClientHello handshake message with the session id zeroed)`;
//! * the server is verified through `HMAC-SHA512(AuthKey, ed25519_spki)` on the
//!   dummy certificate.
//!
//! ALPN is offered as `["h2", "http/1.1"]`, matching Xray's default uTLS
//! fingerprint ALPN set.
//!
//! Options Xray exposes that this runtime cannot express (see the wave report):
//! * `fingerprint` — reproducing a uTLS ClientHello preset requires a patched
//!   TLS stack; the patched rustls here generates its own ClientHello. The
//!   `tls` outbound handles the same limitation by rejecting non-`unsafe`
//!   fingerprints.
//! * `spiderX` — the post-handshake crawl of a "real certificate" server needs
//!   an HTTP/2 client (Xray uses net/http + http2); this crate has no HTTP
//!   client dependency, and the fallback `WebPkiServerVerifier` already fails
//!   the handshake on a non-REALITY certificate.
//! * `flow` — a VLESS payload option (`xtls-rprx-vision`), not a REALITY
//!   transport option; it belongs to the `vless` outbound.
//!
//! The hub-owned `RealityOutboundSettings` currently carries only
//! `server_name`/`public_key`/`short_id`, so none of the three can be sourced
//! from config without extending the proto/serde surface.
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use reality_rustls::pki_types::ServerName;

use super::super::stream::{build_rustls_config, create_reality_provider, RealityStream};
use crate::proxy::*;

pub struct Handler {
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
}

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;

        let server_name = ServerName::try_from(self.server_name.as_str())
            .map_err(|e| io::Error::other(format!("invalid server name: {}", e)))?
            .to_owned();

        let mut public_key_bytes = [0u8; 32];
        if !self.public_key.is_empty() {
            if let Ok(b) = hex::decode(&self.public_key) {
                if b.len() == 32 {
                    public_key_bytes.copy_from_slice(&b);
                } else {
                    return Err(io::Error::other("invalid public key length"));
                }
            } else if let Ok(b) = URL_SAFE_NO_PAD.decode(&self.public_key) {
                if b.len() == 32 {
                    public_key_bytes.copy_from_slice(&b);
                } else {
                    return Err(io::Error::other("invalid public key length"));
                }
            } else {
                return Err(io::Error::other("invalid public key"));
            }
        }

        let mut short_id_bytes = [0u8; 8];
        if !self.short_id.is_empty() {
            let padded_short_id = format!("{:0<16}", self.short_id); // 8 bytes is 16 hex chars, pad if needed
            hex::decode_to_slice(&padded_short_id[..16], &mut short_id_bytes)
                .map_err(|e| io::Error::other(format!("invalid short id: {}", e)))?;
        }

        let provider = create_reality_provider();
        let mut roots = reality_rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let verifier = reality_rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| io::Error::other(format!("failed to build verifier: {}", e)))?;

        let config = build_rustls_config(provider, verifier, public_key_bytes, short_id_bytes)
            .map_err(|e| io::Error::other(format!("failed to build rustls config: {}", e)))?;

        let mut reality_stream = RealityStream::new(
            config,
            server_name,
            stream,
            Some(sess.vision_read_raw.clone()),
        )
        .map_err(|e| io::Error::other(format!("failed to create reality stream: {}", e)))?;

        reality_stream.perform_handshake().await?;

        Ok(Box::new(reality_stream))
    }
}
