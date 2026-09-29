//! Custom rustls [`ServerCertVerifier`] implementing Xray's `pinnedPeerCertSha256`
//! and `verifyPeerCertByName` semantics for the TLS outbound handler.
//!
//! Reference: `transport/internet/tls/config.go` (`RandCarrier.verifyPeerCert`).
//!
//! Divergence from Xray: Xray additionally accepts a pinned *CA* (a non-leaf
//! certificate whose SHA-256 matches a pin replaces the root pool). Here a pin
//! only matches the leaf; a non-matching pin falls back to normal chain
//! verification against `serverName`, per the leaf contract.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
};

/// Parse a comma-separated list of hex-encoded SHA-256 hashes.
///
/// Mirrors Xray's `pinnedPeerCertSha256`: case-insensitive hex, 32 bytes per
/// entry, empty entries skipped, and (for OpenSSL format compatibility) `:`
/// separators are ignored. Any other malformed entry is a config error.
pub(super) fn parse_pins(spec: &str) -> Result<Vec<[u8; 32]>> {
    let mut pins = Vec::new();
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let compact = entry.replace(':', "");
        let bytes = hex::decode(&compact)
            .map_err(|e| anyhow!("invalid pinned_peer_cert_sha256 {entry:?}: {e}"))?;
        let hash: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow!(
                "invalid pinned_peer_cert_sha256 {entry:?}: expected 32 bytes, got {}",
                bytes.len()
            )
        })?;
        pins.push(hash);
    }
    Ok(pins)
}

/// Split a comma-separated `verifyPeerCertByName` list, trimming and dropping
/// empty entries.
pub(super) fn parse_verify_names(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether `value` is Xray's `FromMitM` sentinel (case-insensitive).
pub(super) fn is_from_mitm(value: &str) -> bool {
    value.eq_ignore_ascii_case("frommitm")
}

/// A [`ServerCertVerifier`] wrapping the regular webpki chain verifier.
///
/// Order of checks (matching the documented leaf contract):
/// 1. if the leaf certificate's SHA-256 matches any pin, accept;
/// 2. otherwise, if `verify_names` is non-empty, accept when the leaf is valid
///    for any of those names (chain building is still performed);
/// 3. otherwise fall back to the inner verifier against the connection's
///    `server_name`.
#[derive(Debug)]
pub(super) struct PinnedVerifier {
    pins: Vec<[u8; 32]>,
    verify_names: Vec<String>,
    inner: Arc<WebPkiServerVerifier>,
}

impl PinnedVerifier {
    pub(super) fn new(
        pins: Vec<[u8; 32]>,
        verify_names: Vec<String>,
        inner: Arc<WebPkiServerVerifier>,
    ) -> Self {
        Self {
            pins,
            verify_names,
            inner,
        }
    }

    /// Resolve `verifyPeerCertByName` entries, expanding the `FromMitM`
    /// sentinel to the tunnel destination name and its parent domains (the
    /// connection's `server_name`).
    fn resolved_names(&self, server_name: &ServerName<'_>) -> Vec<String> {
        let mut names = Vec::with_capacity(self.verify_names.len());
        let mitm = server_name.to_str().into_owned();
        for name in &self.verify_names {
            if !is_from_mitm(name) {
                names.push(name.clone());
                continue;
            }
            if mitm.is_empty() {
                continue;
            }
            names.push(mitm.clone());
            let mut rest = mitm.as_str();
            while let Some((_, tail)) = rest.split_once('.') {
                if !tail.contains('.') {
                    break;
                }
                names.push(tail.to_string());
                rest = tail;
            }
        }
        names
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !self.pins.is_empty() {
            let leaf = Sha256::digest(end_entity.as_ref());
            if self
                .pins
                .iter()
                .any(|pin| pin.as_slice() == leaf.as_slice())
            {
                return Ok(ServerCertVerified::assertion());
            }
        }

        if !self.verify_names.is_empty() {
            for name in self.resolved_names(server_name) {
                let Ok(name) = ServerName::try_from(name) else {
                    continue;
                };
                if self
                    .inner
                    .verify_server_cert(end_entity, intermediates, &name, ocsp_response, now)
                    .is_ok()
                {
                    return Ok(ServerCertVerified::assertion());
                }
            }
            return Err(Error::General(
                "peer certificate is not valid for any verifyPeerCertByName entry".into(),
            ));
        }

        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[cfg(test)]
mod tests {
    use super::{is_from_mitm, parse_pins, parse_verify_names};

    #[test]
    fn parse_pins_accepts_lower_and_upper_hex() {
        let lower = "aa".repeat(32);
        let upper = lower.to_uppercase();
        let pins = parse_pins(&format!("{lower}, {upper}")).unwrap();
        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0], pins[1]);
        assert_eq!(pins[0], [0xaa; 32]);
    }

    #[test]
    fn parse_pins_accepts_colon_separated_openssl_format() {
        let raw = "aa".repeat(32);
        let colon = raw
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_pins(&colon).unwrap(), vec![[0xaa; 32]]);
    }

    #[test]
    fn parse_pins_rejects_bad_hex_and_bad_length() {
        assert!(parse_pins("zz").is_err());
        assert!(parse_pins(&"aa".repeat(31)).is_err());
        assert!(parse_pins("").unwrap().is_empty());
    }

    #[test]
    fn parse_verify_names_trims_and_drops_empty() {
        assert_eq!(
            parse_verify_names(" a.com ,, b.com ,"),
            vec!["a.com".to_string(), "b.com".to_string()]
        );
    }

    #[test]
    fn from_mitm_is_case_insensitive() {
        assert!(is_from_mitm("FromMitM"));
        assert!(is_from_mitm("frommitm"));
        assert!(!is_from_mitm("example.com"));
    }
}
