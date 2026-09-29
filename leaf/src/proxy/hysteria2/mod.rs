//! Hysteria2: a QUIC based TCP/UDP proxy that masquerades as an HTTP/3 server
//! and optionally obfuscates its packets ("salamander").
//!
//! The wire format implemented here follows the reference implementation in
//! `/home/dev/hysteria` (`core/internal/protocol`, `core/client`,
//! `core/server`, `extras/obfs`).

#[cfg(feature = "inbound-hysteria2")]
pub mod inbound;
#[cfg(feature = "outbound-hysteria2")]
pub mod outbound;

pub mod congestion;
pub mod obfs;
pub mod protocol;

use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};

use crate::session::SocksAddr;

/// The ALPN protocol an HTTP/3 connection negotiates, and therefore the one
/// both sides of Hysteria2 use.
pub const ALPN_H3: &str = "h3";

/// Default port used when the configured server carries no port.
pub const DEFAULT_PORT: u16 = 443;

/// `Mbps` to bytes per second, matching the reference's `StringToBps` for the
/// `mbps` unit (megabit = 10^6 bits).
pub fn mbps_to_bps(mbps: u64) -> u64 {
    mbps.saturating_mul(125_000)
}

/// Parses a `host:port` string as it appears in the protocol's address fields.
pub fn parse_addr(s: &str) -> Result<SocksAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(SocksAddr::from(addr));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow!("invalid port in address {}", s))?;
            match host.parse::<IpAddr>() {
                Ok(ip) => Ok(SocksAddr::Ip(SocketAddr::new(ip, port))),
                Err(_) => Ok(SocksAddr::Domain(host.to_string(), port)),
            }
        }
        _ => Err(anyhow!("invalid address {}", s)),
    }
}

/// Splits the outbound's `server` setting into a host and a port, defaulting to
/// [`DEFAULT_PORT`] when the port is absent.
pub fn parse_server(s: &str) -> Result<(String, u16)> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.ends_with(']') => {
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow!("invalid port in server address {}", s))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((s.to_string(), DEFAULT_PORT)),
    }
}

/// The rustls crypto provider, following the crate's usual selection.
pub(crate) fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "rustls-tls-aws-lc")]
    let provider = rustls::crypto::aws_lc_rs::default_provider().into();
    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    let provider = rustls::crypto::ring::default_provider().into();
    provider
}

/// Loads a certificate chain and a private key, accepting either inline PEM or
/// a file path (DER or PEM).
pub(crate) fn load_certificate(
    certificate: &str,
    certificate_key: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = if certificate.contains("-----BEGIN") {
        certificate.as_bytes().to_vec()
    } else {
        fs::read(certificate)?
    };

    let key = if certificate_key.contains("-----BEGIN") {
        certificate_key.as_bytes().to_vec()
    } else {
        fs::read(certificate_key)?
    };

    let cert = if !certificate.contains("-----BEGIN")
        && Path::new(certificate).extension().and_then(|e| e.to_str()) == Some("der")
    {
        vec![CertificateDer::from(cert)]
    } else {
        certs(&mut io::BufReader::new(&*cert)).collect::<Result<Vec<_>, _>>()?
    };

    let key = if !certificate_key.contains("-----BEGIN")
        && Path::new(certificate_key)
            .extension()
            .and_then(|e| e.to_str())
            == Some("der")
    {
        PrivateKeyDer::Pkcs8(key.into())
    } else {
        let pkcs8 =
            pkcs8_private_keys(&mut io::BufReader::new(&*key)).collect::<Result<Vec<_>, _>>()?;
        match pkcs8.into_iter().next() {
            Some(x) => PrivateKeyDer::Pkcs8(x),
            None => {
                let rsa = rsa_private_keys(&mut io::BufReader::new(&*key))
                    .collect::<Result<Vec<_>, _>>()?;
                match rsa.into_iter().next() {
                    Some(x) => PrivateKeyDer::Pkcs1(x),
                    None => {
                        let ec =
                            ec_private_keys(&mut io::BufReader::new(&*key))
                                .collect::<Result<Vec<_>, _>>()?;
                        match ec.into_iter().next() {
                            Some(x) => PrivateKeyDer::Sec1(x),
                            None => {
                                return Err(anyhow!(
                                    "no private key found: expected a PKCS#8, PKCS#1 or SEC1 key"
                                ));
                            }
                        }
                    }
                }
            }
        }
    };

    Ok((cert, key))
}

/// Builds the QUIC transport configuration shared by both directions.
///
/// `mtu` is applied as the initial MTU when it falls inside the range quinn's
/// path MTU discovery can work with; quinn governs the MTU otherwise.
pub(crate) fn transport_config(
    max_idle_timeout_ms: u64,
    keep_alive_interval_ms: u64,
    mtu: Option<u32>,
    bandwidth_bps: u64,
) -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(
        *crate::option::QUIC_MAX_CONCURRENT_BIDI_STREAMS,
    ));
    transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        max_idle_timeout_ms.min(u32::MAX as u64) as u32,
    ))));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_millis(
        keep_alive_interval_ms,
    )));
    // Hysteria's UDP relay rides on QUIC datagrams.
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024);
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    if let Some(mtu) = mtu {
        match u16::try_from(mtu) {
            Ok(mtu) if (1200..=1452).contains(&mtu) => {
                transport_config.initial_mtu(mtu);
            }
            _ => {
                tracing::warn!(
                    "hysteria2: ignoring mtu {} outside the usable range 1200-1452",
                    mtu
                );
            }
        }
    }
    transport_config.congestion_controller_factory(congestion::factory(bandwidth_bps));
    transport_config
}
