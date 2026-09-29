use std::io;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::TryFutureExt;
use tracing::trace;

#[cfg(feature = "rustls-tls")]
use {
    std::sync::Arc,
    std::{fs::File, io::BufReader, io::Cursor},
    tokio_rustls::{
        rustls::{
            client::{ClientSessionMemoryCache, WebPkiServerVerifier},
            client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            crypto::{CryptoProvider, SupportedKxGroup},
            pki_types::{CertificateDer, ServerName, UnixTime},
            version, ClientConfig, DigitallySignedStruct, Error, KeyLogFile, Resumption,
            RootCertStore, SignatureScheme, SupportedProtocolVersion,
        },
        TlsConnector,
    },
};

#[cfg(all(feature = "rustls-tls", feature = "rustls-tls-aws-lc"))]
use tokio_rustls::rustls::client::{EchConfig, EchMode};
#[cfg(all(feature = "rustls-tls", feature = "rustls-tls-aws-lc"))]
use tokio_rustls::rustls::pki_types::{pem::PemObject, EchConfigListBytes};

#[cfg(feature = "openssl-tls")]
use {
    openssl::ssl::{Ssl, SslConnector, SslMethod, SslVersion},
    openssl::x509::X509,
    std::pin::Pin,
    std::sync::Once,
    tokio_openssl::SslStream,
};

use crate::config::TlsOutboundSettings;
use crate::{app::SyncDnsClient, proxy::*, session::Session};

#[cfg(feature = "rustls-tls")]
#[path = "../verify.rs"]
mod verify;

/// Whether `value` is Xray's `FromMitM` sentinel (case-insensitive).
fn is_from_mitm(value: &str) -> bool {
    value.eq_ignore_ascii_case("frommitm")
}

#[cfg(feature = "rustls-tls")]
mod dangerous {
    use tokio_rustls::rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, Error, SignatureScheme,
    };

    #[derive(Debug)]
    pub(super) struct NotVerified;

    impl ServerCertVerifier for NotVerified {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer,
            intermediates: &[CertificateDer],
            server_name: &ServerName,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> core::result::Result<ServerCertVerified, Error> {
            let _ = (end_entity, intermediates, server_name, ocsp_response, now);
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            let _ = (message, cert, dss);
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            let _ = (message, cert, dss);
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

/// Everything needed to (re)build a rustls client config for one connection.
#[cfg(feature = "rustls-tls")]
struct RustlsClientOptions {
    alpns: Vec<String>,
    roots: Arc<RootCertStore>,
    verifier: Option<Arc<dyn ServerCertVerifier>>,
    insecure: bool,
    versions: Option<Vec<&'static SupportedProtocolVersion>>,
    provider: Arc<CryptoProvider>,
    session_resumption: bool,
    key_log: bool,
}

pub struct Handler {
    server_name: String,
    #[cfg(feature = "rustls-tls")]
    alpns: Vec<String>,
    #[cfg(feature = "rustls-tls")]
    insecure: bool,
    #[cfg(feature = "rustls-tls")]
    fixed_ech_config_list: Option<String>,
    #[cfg(feature = "rustls-tls")]
    ech_disable_dns_lookup: bool,
    #[cfg(feature = "rustls-tls")]
    dns_client: SyncDnsClient,
    ech_enabled: bool,
    #[cfg(feature = "rustls-tls")]
    rustls_options: RustlsClientOptions,
    #[cfg(feature = "rustls-tls")]
    tls_config: Option<Arc<ClientConfig>>,
    #[cfg(feature = "openssl-tls")]
    ssl_connector: Option<SslConnector>,
}

/// Map Xray's `minVersion`/`maxVersion` strings onto the set of rustls
/// protocol versions to offer.
///
/// `None` means "use rustls defaults" (TLS 1.2 + 1.3). rustls cannot negotiate
/// TLS 1.0/1.1, so a min of "1.0"/"1.1" is clamped up to 1.2, while a max of
/// "1.0"/"1.1" is a hard config error.
#[cfg(feature = "rustls-tls")]
fn rustls_versions(
    min: Option<&str>,
    max: Option<&str>,
) -> Result<Option<Vec<&'static SupportedProtocolVersion>>> {
    fn rank(which: &str, value: &str) -> Result<u8> {
        match value {
            "1.0" => Ok(10),
            "1.1" => Ok(11),
            "1.2" => Ok(12),
            "1.3" => Ok(13),
            _ => Err(anyhow!("invalid tls {which}_version: {value:?}")),
        }
    }

    let min = min.map(str::trim).filter(|s| !s.is_empty());
    let max = max.map(str::trim).filter(|s| !s.is_empty());
    if min.is_none() && max.is_none() {
        return Ok(None);
    }

    let min_rank = match min {
        Some(value) => rank("min", value)?,
        None => 0,
    };
    let max_rank = match max {
        Some(value) => rank("max", value)?,
        None => 13,
    };
    if min_rank > max_rank {
        return Err(anyhow!(
            "tls min_version {:?} is greater than max_version {:?}",
            min.unwrap_or_default(),
            max.unwrap_or_default()
        ));
    }

    let mut versions: Vec<&'static SupportedProtocolVersion> = Vec::new();
    if min_rank <= 12 && max_rank >= 12 {
        versions.push(&version::TLS12);
    }
    if max_rank >= 13 {
        versions.push(&version::TLS13);
    }
    if versions.is_empty() {
        return Err(anyhow!(
            "tls max_version {:?} is below the minimum supported by rustls (1.2)",
            max.unwrap_or_default()
        ));
    }
    if min_rank > 0 && min_rank < 12 {
        trace!(
            "tls min_version {:?} is below the rustls minimum; offering TLS 1.2 and up",
            min.unwrap_or_default()
        );
    }
    Ok(Some(versions))
}

/// Restrict `provider.cipher_suites` to the requested TLS<=1.2 ciphers (Go/IANA
/// names), keeping the provider's TLS 1.3 suites. An unknown name is an error.
#[cfg(feature = "rustls-tls")]
fn apply_cipher_suites(provider: &mut CryptoProvider, spec: &str) -> Result<()> {
    let mut chosen = Vec::new();
    for name in spec.split(':') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        match provider
            .cipher_suites
            .iter()
            .find(|cs| format!("{:?}", cs.suite()) == name)
        {
            Some(cs) => chosen.push(cs.clone()),
            None => return Err(anyhow!("unknown tls cipher_suite: {name}")),
        }
    }

    let mut tls13 = Vec::new();
    for cs in &provider.cipher_suites {
        if format!("{:?}", cs.suite()).starts_with("TLS13_") {
            tls13.push(cs.clone());
        }
    }
    tls13.extend(chosen);
    provider.cipher_suites = tls13;
    Ok(())
}

/// Map an Xray `curvePreferences` name onto its rustls `NamedGroup` debug name.
#[cfg(feature = "rustls-tls")]
fn curve_named_group(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "curvep256" => Some("secp256r1"),
        "curvep384" => Some("secp384r1"),
        "curvep521" => Some("secp521r1"),
        "x25519" => Some("X25519"),
        "x25519mlkem768" => Some("X25519MLKEM768"),
        "secp256r1mlkem768" => Some("secp256r1MLKEM768"),
        "secp384r1mlkem1024" => Some("secp384r1MLKEM1024"),
        _ => None,
    }
}

/// Restrict `provider.kx_groups` to the requested curves, in order. A name that
/// is unknown or not provided by the linked rustls backend is an error.
#[cfg(feature = "rustls-tls")]
fn apply_curve_preferences(provider: &mut CryptoProvider, names: &[String]) -> Result<()> {
    let mut groups: Vec<&'static dyn SupportedKxGroup> = Vec::new();
    for name in names {
        let expected =
            curve_named_group(name).ok_or_else(|| anyhow!("unsupported tls curve_preference: {name}"))?;
        let group = provider
            .kx_groups
            .iter()
            .find(|g| format!("{:?}", g.name()).eq_ignore_ascii_case(expected))
            .ok_or_else(|| {
                anyhow!(
                    "unsupported tls curve_preference: {name} (not provided by the linked rustls crypto provider)"
                )
            })?;
        groups.push(*group);
    }
    provider.kx_groups = groups;
    Ok(())
}

/// Add PEM certificates from an inline PEM blob or a file path to a root store.
#[cfg(feature = "rustls-tls")]
fn load_cert_source(roots: &mut RootCertStore, source: &str) -> Result<()> {
    if source.contains("-----BEGIN") {
        let mut pem = BufReader::new(Cursor::new(source.as_bytes()));
        for cert in rustls_pemfile::certs(&mut pem) {
            roots.add(cert?)?;
        }
    } else {
        let mut pem = BufReader::new(File::open(source).map_err(|e| {
            anyhow!("load certificates from {source} failed: {e}")
        })?);
        for cert in rustls_pemfile::certs(&mut pem) {
            roots.add(cert?)?;
        }
    }
    Ok(())
}

/// Build the rustls client options from the outbound settings.
#[cfg(feature = "rustls-tls")]
fn build_rustls_options(
    settings: &TlsOutboundSettings,
    alpns: &[String],
    insecure: bool,
) -> Result<RustlsClientOptions> {
    let disable_system_root = settings.disable_system_root.unwrap_or(false);
    let mut roots = RootCertStore::empty();
    if !settings.certificates.is_empty() {
        for (idx, cert) in settings.certificates.iter().enumerate() {
            let usage = cert.usage.as_deref().unwrap_or("").trim();
            if !usage.eq_ignore_ascii_case("verify") {
                return Err(anyhow!(
                    "tls outbound certificates[{idx}].usage {usage:?} is not supported: only \"verify\" (a client root) is meaningful on an outbound"
                ));
            }
            for (entry_idx, entry) in cert.certificate.iter().enumerate() {
                if entry.trim().is_empty() {
                    continue;
                }
                load_cert_source(&mut roots, entry).map_err(|e| {
                    anyhow!("tls outbound certificates[{idx}].certificate[{entry_idx}]: {e}")
                })?;
            }
            if let Some(path) = cert
                .certificate_file
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                load_cert_source(&mut roots, path)
                    .map_err(|e| anyhow!("tls outbound certificates[{idx}].certificate_file: {e}"))?;
            }
        }
        if !disable_system_root {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    } else {
        let flat = settings.certificate.trim();
        if !flat.is_empty() {
            // Existing flat behaviour: the configured certificate(s) replace the
            // webpki root set entirely.
            load_cert_source(&mut roots, flat)?;
        } else if !disable_system_root {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }

    let pins = match settings.pinned_peer_cert_sha256.as_deref() {
        Some(spec) if !spec.trim().is_empty() => verify::parse_pins(spec)?,
        _ => Vec::new(),
    };
    let verify_names = match settings.verify_peer_cert_by_name.as_deref() {
        Some(spec) => verify::parse_verify_names(spec),
        None => Vec::new(),
    };

    let versions = rustls_versions(settings.min_version.as_deref(), settings.max_version.as_deref())?;

    #[cfg(feature = "rustls-tls-aws-lc")]
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(spec) = settings.cipher_suites.as_deref() {
        if !spec.trim().is_empty() {
            apply_cipher_suites(&mut provider, spec)?;
        }
    }
    if !settings.curve_preferences.is_empty() {
        apply_curve_preferences(&mut provider, &settings.curve_preferences)?;
    }
    let provider: Arc<CryptoProvider> = Arc::new(provider);

    let verifier = if !insecure && (!pins.is_empty() || !verify_names.is_empty()) {
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            provider.clone(),
        )
        .build()
        .map_err(|e| anyhow!("build tls outbound cert verifier failed: {e}"))?;
        Some(
            Arc::new(verify::PinnedVerifier::new(pins, verify_names, inner))
                as Arc<dyn ServerCertVerifier>,
        )
    } else {
        None
    };

    let master_key_log = settings.master_key_log.as_deref().unwrap_or("").trim();
    let explicit_key_log = !master_key_log.is_empty() && !master_key_log.eq_ignore_ascii_case("none");
    if explicit_key_log {
        match std::env::var_os("SSLKEYLOGFILE") {
            Some(path) if path == std::ffi::OsStr::new(master_key_log) => {}
            _ => tracing::warn!(
                "tls outbound master_key_log={master_key_log:?} cannot be opened directly by rustls; set SSLKEYLOGFILE={master_key_log:?} so rustls' KeyLogFile writes there"
            ),
        }
    }
    let key_log = explicit_key_log || std::env::var_os("SSLKEYLOGFILE").is_some();

    Ok(RustlsClientOptions {
        alpns: alpns.to_vec(),
        roots: Arc::new(roots),
        verifier,
        insecure,
        versions,
        provider,
        session_resumption: settings.enable_session_resumption.unwrap_or(false),
        key_log,
    })
}

impl Handler {
    #[cfg(feature = "rustls-tls")]
    fn build_rustls_config(
        options: &RustlsClientOptions,
        ech_config_list: Option<&str>,
    ) -> Result<Arc<ClientConfig>> {
        #[cfg(not(feature = "rustls-tls-aws-lc"))]
        if ech_config_list.is_some() {
            return Err(anyhow!(
                "tls outbound ech requires rustls-tls-aws-lc (ring backend has no hpke suites)"
            ));
        }

        let builder = ClientConfig::builder_with_provider(options.provider.clone());

        let builder = if let Some(ech_config_list) = ech_config_list {
            #[cfg(feature = "rustls-tls-aws-lc")]
            {
                if let Some(versions) = &options.versions {
                    if !versions
                        .iter()
                        .any(|v| std::ptr::eq(*v, &version::TLS13))
                    {
                        return Err(anyhow!(
                            "tls outbound ech requires TLS 1.3 but max_version excludes it"
                        ));
                    }
                }
                let ech_config_list = decode_ech_config_list(ech_config_list)?;
                let suites = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
                let ech_config = EchConfig::new(ech_config_list, suites)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
                builder
                    .with_ech(EchMode::Enable(ech_config))
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
            }
            #[cfg(not(feature = "rustls-tls-aws-lc"))]
            {
                let _ = ech_config_list;
                return Err(anyhow!(
                    "tls outbound ech requires rustls-tls-aws-lc (ring backend has no hpke suites)"
                ));
            }
        } else {
            match &options.versions {
                Some(versions) => builder
                    .with_protocol_versions(versions)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
                None => builder
                    .with_safe_default_protocol_versions()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
            }
        };

        let mut config = if options.insecure {
            let builder = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(dangerous::NotVerified));
            // FIXME: client authentication is not configured
            builder.with_no_client_auth()
        } else if let Some(verifier) = &options.verifier {
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(options.roots.clone())
                .with_no_client_auth()
        };

        // Session resumption: an in-memory cache when enabled, a no-op store
        // otherwise (Xray's `EnableSessionResumption` default is disabled).
        config.resumption = if options.session_resumption {
            Resumption::store(Arc::new(ClientSessionMemoryCache::new(128)))
        } else {
            Resumption::disabled()
        };
        if options.key_log {
            config.key_log = Arc::new(KeyLogFile::new());
        }
        for alpn in &options.alpns {
            config.alpn_protocols.push(alpn.as_bytes().to_vec());
        }
        Ok(Arc::new(config))
    }

    #[cfg(feature = "rustls-tls")]
    fn resolve_selected_ech_config_list(
        name: &str,
        fixed_ech_config_list: Option<&str>,
        auto_result: Option<anyhow::Result<String>>,
    ) -> io::Result<Option<String>> {
        match auto_result {
            Some(Ok(value)) => {
                trace!("ech source for {}: https/svcb dns record", name);
                Ok(Some(value))
            }
            Some(Err(err)) => {
                if let Some(fixed) = fixed_ech_config_list {
                    trace!(
                        "auto ech fetch failed for {}, fallback to fixed ech config: {}",
                        name,
                        err
                    );
                    Ok(Some(fixed.to_string()))
                } else {
                    trace!(
                        "auto ech fetch failed for {}, no fixed ech config available: {}",
                        name,
                        err
                    );
                    Err(io::Error::other(format!(
                        "auto ech fetch failed for {}: {}",
                        name, err
                    )))
                }
            }
            None => {
                if fixed_ech_config_list.is_some() {
                    trace!("ech source for {}: fixed ech config", name);
                } else {
                    trace!("ech source for {}: none", name);
                }
                Ok(fixed_ech_config_list.map(str::to_string))
            }
        }
    }

    #[cfg(all(feature = "rustls-tls", feature = "rustls-tls-aws-lc"))]
    fn should_skip_ech_dns_lookup_for_session(sess: &Session) -> bool {
        sess.inbound_tag == "dnsclient"
    }

    #[cfg(feature = "rustls-tls")]
    async fn select_ech_config_list(
        &self,
        name: &str,
        allow_dns_lookup: bool,
    ) -> io::Result<Option<String>> {
        if !self.ech_enabled {
            trace!("ech source for {}: none", name);
            return Ok(None);
        }
        if self.ech_disable_dns_lookup {
            if let Some(fixed) = self.fixed_ech_config_list.as_deref() {
                trace!("ech source for {}: fixed ech config", name);
                return Ok(Some(fixed.to_string()));
            }
            trace!("ech source for {}: none", name);
            return Ok(None);
        }
        let auto_result = if allow_dns_lookup {
            let dns_client = self.dns_client.read().await;
            Some(dns_client.lookup_ech_config_list(name).await)
        } else {
            trace!("ech source for {}: fixed-or-none (dns lookup skipped)", name);
            None
        };
        Self::resolve_selected_ech_config_list(
            name,
            self.fixed_ech_config_list.as_deref(),
            auto_result,
        )
    }

    /// Create a TLS outbound handler from the protobuf settings.
    ///
    /// # Divergences from Xray
    ///
    /// * `fingerprint`: only `"unsafe"` (or unset) is accepted; any other value
    ///   is rejected because rustls/openssl cannot reproduce uTLS ClientHello
    ///   presets. Xray silently falls back to its native TLS stack for unknown
    ///   fingerprints by default, but this handler refuses rather than ignoring
    ///   the option.
    /// * `masterKeyLog`: rustls' `KeyLogFile` writes to `$SSLKEYLOGFILE`, so a
    ///   configured path can only be honoured when the env var points at it (a
    ///   warning is logged otherwise).
    /// * `pinnedPeerCertSha256`: an unsynchronized pin matches the leaf only;
    ///   it does not support pinning an intermediate CA the way Xray does.
    pub fn new(settings: &TlsOutboundSettings, dns_client: SyncDnsClient) -> Result<Self> {
        let fingerprint = settings.fingerprint.as_deref().unwrap_or("").trim();
        if !fingerprint.is_empty() && !fingerprint.eq_ignore_ascii_case("unsafe") {
            return Err(anyhow!(
                "tls outbound fingerprint {fingerprint:?} is not supported: ClientHello fingerprinting requires a patched TLS stack (uTLS); only \"unsafe\" (the native TLS stack) is available"
            ));
        }

        // `FromMitM` means "use the tunnel destination name"; the handler falls
        // back to the session destination whenever `server_name` is empty.
        let mut server_name = settings.server_name.clone();
        if is_from_mitm(&server_name) {
            server_name.clear();
        }
        let mut alpns = settings.alpn.clone();
        if alpns.len() == 1 && is_from_mitm(&alpns[0]) {
            // Xray's non-`mitmAlpn11` fallback (leaf has no `mitmAlpn11` signal).
            alpns = vec!["h2".to_string(), "http/1.1".to_string()];
        } else if alpns.iter().any(|p| is_from_mitm(p)) {
            return Err(anyhow!(
                "tls outbound alpn: \"fromMitM\" is only allowed as the single alpn element"
            ));
        }

        let ech_enabled = settings.ech;
        let mut handler = Handler {
            server_name,
            #[cfg(feature = "rustls-tls")]
            alpns: alpns.clone(),
            #[cfg(feature = "rustls-tls")]
            insecure: settings.insecure,
            #[cfg(feature = "rustls-tls")]
            fixed_ech_config_list: if settings.ech_config_list.is_empty() {
                None
            } else {
                Some(settings.ech_config_list.clone())
            },
            #[cfg(feature = "rustls-tls")]
            ech_disable_dns_lookup: settings.ech_disable_dns_lookup,
            #[cfg(feature = "rustls-tls")]
            dns_client,
            ech_enabled,
            #[cfg(feature = "rustls-tls")]
            rustls_options: build_rustls_options(settings, &alpns, settings.insecure)?,
            #[cfg(feature = "rustls-tls")]
            tls_config: None,
            #[cfg(feature = "openssl-tls")]
            ssl_connector: None,
        };

        #[cfg(feature = "rustls-tls")]
        {
            if handler.ech_enabled {
                tracing::trace!("tls outbound ech configured");
            } else {
                tracing::trace!("tls outbound ech not configured");
            }
            let initial_ech_config = if handler.ech_enabled {
                #[cfg(feature = "rustls-tls-aws-lc")]
                {
                    handler.fixed_ech_config_list.as_deref()
                }
                #[cfg(not(feature = "rustls-tls-aws-lc"))]
                {
                    None
                }
            } else {
                None
            };
            handler.tls_config = Some(Self::build_rustls_config(
                &handler.rustls_options,
                initial_ech_config,
            )?);
        }

        #[cfg(feature = "openssl-tls")]
        {
            handler.ssl_connector = Some(Self::build_openssl_connector(settings, &alpns)?);
        }

        Ok(handler)
    }

    #[cfg(feature = "openssl-tls")]
    fn build_openssl_connector(
        settings: &TlsOutboundSettings,
        alpns: &[String],
    ) -> Result<SslConnector> {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| unsafe { openssl_probe::init_openssl_env_vars() });

        if settings
            .pinned_peer_cert_sha256
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            return Err(anyhow!(
                "tls outbound pinned_peer_cert_sha256 is not supported by the openssl backend"
            ));
        }
        if settings
            .verify_peer_cert_by_name
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            return Err(anyhow!(
                "tls outbound verify_peer_cert_by_name is not supported by the openssl backend"
            ));
        }
        if !settings.curve_preferences.is_empty() {
            return Err(anyhow!(
                "tls outbound curve_preferences is not supported by the openssl backend"
            ));
        }
        if settings.enable_session_resumption == Some(true) {
            return Err(anyhow!(
                "tls outbound enable_session_resumption is not supported by the openssl backend"
            ));
        }
        if settings
            .master_key_log
            .as_deref()
            .map(|s| !s.trim().is_empty() && !s.trim().eq_ignore_ascii_case("none"))
            .unwrap_or(false)
        {
            return Err(anyhow!(
                "tls outbound master_key_log is not supported by the openssl backend"
            ));
        }
        if settings.disable_system_root == Some(true) {
            return Err(anyhow!(
                "tls outbound disable_system_root is not supported by the openssl backend"
            ));
        }

        let mut builder =
            SslConnector::builder(SslMethod::tls()).expect("create ssl connector failed");

        if let Some(value) = settings.min_version.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            builder
                .set_min_proto_version(Some(openssl_version(value)?))
                .map_err(|e| anyhow!("invalid tls min_version {value:?}: {e}"))?;
        }
        if let Some(value) = settings.max_version.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            builder
                .set_max_proto_version(Some(openssl_version(value)?))
                .map_err(|e| anyhow!("invalid tls max_version {value:?}: {e}"))?;
        }
        if let Some(spec) = settings.cipher_suites.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            builder
                .set_cipher_list(spec)
                .map_err(|e| anyhow!("invalid tls cipher_suites {spec:?}: {e}"))?;
        }

        if !settings.certificates.is_empty() {
            for (idx, cert) in settings.certificates.iter().enumerate() {
                let usage = cert.usage.as_deref().unwrap_or("").trim();
                if !usage.eq_ignore_ascii_case("verify") {
                    return Err(anyhow!(
                        "tls outbound certificates[{idx}].usage {usage:?} is not supported: only \"verify\" (a client root) is meaningful on an outbound"
                    ));
                }
                for entry in &cert.certificate {
                    add_pem_to_openssl_roots(&mut builder, entry)?;
                }
                if let Some(path) = cert
                    .certificate_file
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    add_pem_to_openssl_roots(&mut builder, path)?;
                }
            }
        } else if !settings.certificate.trim().is_empty() {
            add_pem_to_openssl_roots(&mut builder, &settings.certificate)?;
        }

        if !alpns.is_empty() {
            let mut wire = Vec::new();
            for alpn in alpns.iter() {
                if alpn.len() > 255 {
                    return Err(anyhow!("tls outbound alpn protocol name too long: {}", alpn));
                }
                wire.push(alpn.len() as u8);
                wire.extend_from_slice(alpn.as_bytes());
            }
            builder.set_alpn_protos(&wire).expect("set alpn failed");
        }
        if settings.insecure {
            builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        }

        Ok(builder.build())
    }
}

/// Map an Xray version string onto an OpenSSL protocol version.
#[cfg(feature = "openssl-tls")]
fn openssl_version(value: &str) -> Result<SslVersion> {
    match value {
        "1.0" => Ok(SslVersion::TLS1),
        "1.1" => Ok(SslVersion::TLS1_1),
        "1.2" => Ok(SslVersion::TLS1_2),
        "1.3" => Ok(SslVersion::TLS1_3),
        _ => Err(anyhow!("invalid tls version: {value:?}")),
    }
}

/// Add PEM certificates (inline blob or file path) to the OpenSSL trust store.
#[cfg(feature = "openssl-tls")]
fn add_pem_to_openssl_roots(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    source: &str,
) -> Result<()> {
    let data = if source.contains("-----BEGIN") {
        source.as_bytes().to_vec()
    } else {
        std::fs::read(source)
            .map_err(|e| anyhow!("load certificates from {source} failed: {e}"))?
    };
    let certs = X509::stack_from_pem(&data)
        .map_err(|e| anyhow!("parse certificates from {source} failed: {e}"))?;
    for cert in certs {
        builder
            .cert_store_mut()
            .add_cert(cert)
            .map_err(|e| anyhow!("add certificate from {source} failed: {e}"))?;
    }
    Ok(())
}

#[cfg(all(feature = "rustls-tls", feature = "rustls-tls-aws-lc"))]
fn decode_ech_config_list(ech_config_list: &str) -> io::Result<EchConfigListBytes<'static>> {
    let ech_config_list = ech_config_list.trim();
    if ech_config_list.starts_with("-----BEGIN") {
        return EchConfigListBytes::from_pem_slice(ech_config_list.as_bytes())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
            .map(EchConfigListBytes::into_owned);
    }
    let decoded = decode_base64(ech_config_list)?;
    let (decoded, _) = ensure_ech_config_list_bytes(decoded);
    Ok(EchConfigListBytes::from(decoded))
}

#[cfg(all(feature = "rustls-tls", any(feature = "rustls-tls-aws-lc", test)))]
fn ensure_ech_config_list_bytes(mut decoded: Vec<u8>) -> (Vec<u8>, bool) {
    if decoded.len() >= 2 {
        let declared = u16::from_be_bytes([decoded[0], decoded[1]]) as usize;
        if declared == decoded.len().saturating_sub(2) {
            return (decoded, false);
        }
    }

    if decoded.len() >= 4 && decoded[0] == 0xfe && decoded[1] == 0x0d {
        let len = decoded.len();
        if u16::try_from(len).is_ok() {
            let mut wrapped = Vec::with_capacity(len + 2);
            wrapped.extend_from_slice(&(len as u16).to_be_bytes());
            wrapped.append(&mut decoded);
            return (wrapped, true);
        }
    }

    (decoded, false)
}

#[cfg(all(feature = "rustls-tls", any(feature = "rustls-tls-aws-lc", test)))]
fn decode_base64(data: &str) -> io::Result<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    fn decode_chunk(chunk: &[u8; 4], output: &mut Vec<u8>) -> io::Result<()> {
        if chunk[0] == 64 || chunk[1] == 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            ));
        }
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        match (chunk[2], chunk[3]) {
            (64, 64) => Ok(()),
            (64, _) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            )),
            (c2, 64) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                Ok(())
            }
            (c2, c3) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                output.push(((c2 & 0x03) << 6) | c3);
                Ok(())
            }
        }
    }

    let mut output = Vec::with_capacity(data.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut chunk_len = 0_usize;
    let mut seen_padding = false;

    for byte in data.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_padding = true;
            chunk[chunk_len] = 64;
            chunk_len += 1;
        } else if let Some(decoded) = value(byte) {
            if seen_padding {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid base64 padding",
                ));
            }
            chunk[chunk_len] = decoded;
            chunk_len += 1;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 character",
            ));
        }

        if chunk_len == 4 {
            decode_chunk(&chunk, &mut output)?;
            chunk = [0_u8; 4];
            chunk_len = 0;
        }
    }

    match chunk_len {
        0 => Ok(output),
        2 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            Ok(output)
        }
        3 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push(((chunk[1] & 0x0f) << 4) | (chunk[2] >> 2));
            Ok(output)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid base64 length",
        )),
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    #[allow(unreachable_code)]
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let _ = lhs;
        tracing::trace!("handling outbound stream");
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        if let Some(stream) = stream {
            #[cfg(feature = "rustls-tls")]
            {
                #[cfg(feature = "rustls-tls-aws-lc")]
                let mut ech_config_selected = false;
                #[cfg(not(feature = "rustls-tls-aws-lc"))]
                let ech_config_selected = false;
                #[cfg(feature = "rustls-tls-aws-lc")]
                let mut ech_dns_lookup_skipped = false;
                #[cfg(not(feature = "rustls-tls-aws-lc"))]
                let ech_dns_lookup_skipped = false;
                let tls_config = {
                    if self.ech_enabled {
                        #[cfg(not(feature = "rustls-tls-aws-lc"))]
                        {
                            return Err(io::Error::other(
                                "tls outbound ech requires rustls-tls-aws-lc (ring backend has no hpke suites)",
                            ));
                        }
                        #[cfg(feature = "rustls-tls-aws-lc")]
                        {
                            ech_dns_lookup_skipped =
                                Self::should_skip_ech_dns_lookup_for_session(sess);
                        }
                        let selected_ech = self
                            .select_ech_config_list(&name, !ech_dns_lookup_skipped)
                            .await?;
                        ech_config_selected = selected_ech.is_some();
                        Self::build_rustls_config(&self.rustls_options, selected_ech.as_deref())
                            .map_err(|e| io::Error::other(format!("build tls config failed: {}", e)))?
                    } else {
                        self.tls_config
                            .as_ref()
                            .cloned()
                            .ok_or_else(|| io::Error::other("no tls backend available"))?
                    }
                };
                trace!(
                    "handling TLS {} with rustls, ech_enabled={}, ech_config_selected={}, ech_dns_lookup_skipped={}",
                    &name,
                    self.ech_enabled,
                    ech_config_selected,
                    ech_dns_lookup_skipped
                );
                let connector = TlsConnector::from(tls_config);
                let domain = ServerName::try_from(name.as_str()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid tls server name {}: {}", &name, e),
                    )
                })?;
                let tls_stream = connector
                    .connect(domain.to_owned(), stream)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("connect tls failed: {}", e),
                        )
                    })
                    .await?;
                // FIXME check negotiated alpn
                return Ok(Box::new(tls_stream));
            }
            #[cfg(feature = "openssl-tls")]
            if let Some(ssl_connector) = self.ssl_connector.as_ref() {
                if self.ech_enabled {
                    return Err(io::Error::other(
                        "tls outbound ech is not supported with current openssl backend",
                    ));
                }
                let mut ssl = Ssl::new(ssl_connector.context()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("new ssl failed: {}", e),
                    )
                })?;
                ssl.set_hostname(&name).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("set tls name failed: {}", e),
                    )
                })?;
                trace!(
                    "handling TLS {} with openssl, ech_enabled={}",
                    &name,
                    self.ech_enabled
                );
                let mut stream = SslStream::new(ssl, stream).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("new ssl stream failed: {}", e),
                    )
                })?;
                Pin::new(&mut stream)
                    .connect()
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("connect ssl stream failed: {}", e),
                        )
                    })
                    .await?;
                return Ok(Box::new(stream));
            }
            Err(io::Error::other("no tls backend available"))
        } else {
            Err(io::Error::other("invalid tls input"))
        }
    }
}

#[cfg(all(test, feature = "rustls-tls"))]
mod tests {
    use anyhow::anyhow;
    use std::sync::Arc;

    use protobuf::MessageField;
    use tokio::sync::RwLock;

    use crate::app::{dns::DnsClient, SyncDnsClient};
    use crate::config::TlsOutboundSettings;
    #[cfg(feature = "rustls-tls-aws-lc")]
    use crate::session::Session;

    use super::{
        decode_base64, ensure_ech_config_list_bytes, rustls_versions, Handler, RustlsClientOptions,
    };

    fn new_test_dns_client() -> SyncDnsClient {
        let mut dns = crate::config::Dns::new();
        dns.servers.push("1.1.1.1".to_string());
        let dns = MessageField::some(dns);
        Arc::new(RwLock::new(DnsClient::new(&dns).unwrap()))
    }

    fn test_rustls_options() -> RustlsClientOptions {
        let settings = TlsOutboundSettings::new();
        super::build_rustls_options(&settings, &[], false).unwrap()
    }

    #[test]
    fn test_decode_base64_standard_and_urlsafe() {
        assert_eq!(decode_base64("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_base64("AQI=").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("AQI").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("-_8=").unwrap(), vec![251, 255]);
    }

    #[test]
    fn test_decode_base64_invalid_input() {
        assert!(decode_base64("A").is_err());
        assert!(decode_base64("AA=A").is_err());
        assert!(decode_base64("AA$A").is_err());
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_wrap_single_config() {
        let input = vec![0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input);
        assert!(wrapped);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x04);
        assert_eq!(&out[2..], &[0xfe, 0x0d, 0x00, 0x41]);
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_keep_existing_list() {
        let input = vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input.clone());
        assert!(!wrapped);
        assert_eq!(out, input);
    }

    #[test]
    fn test_rustls_versions_defaults_to_none() {
        assert!(rustls_versions(None, None).unwrap().is_none());
        assert_eq!(rustls_versions(Some("1.2"), None).unwrap().unwrap().len(), 2);
        assert_eq!(rustls_versions(None, Some("1.2")).unwrap().unwrap().len(), 1);
        assert_eq!(rustls_versions(Some("1.3"), None).unwrap().unwrap().len(), 1);
    }

    #[test]
    fn test_rustls_versions_rejects_bad_ranges() {
        assert!(rustls_versions(Some("1.4"), None).is_err());
        assert!(rustls_versions(None, Some("1.1")).is_err());
        assert!(rustls_versions(Some("1.3"), Some("1.2")).is_err());
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_success() {
        let result = Handler::resolve_selected_ech_config_list(
            "example.com",
            Some("AQI="),
            Some(Ok("AQID".to_string())),
        )
        .unwrap();
        assert_eq!(result, Some("AQID".to_string()));
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_failed_fallback() {
        let result = Handler::resolve_selected_ech_config_list(
            "example.com",
            Some("AQI="),
            Some(Err(anyhow!("dns failed"))),
        )
        .unwrap();
        assert_eq!(result, Some("AQI=".to_string()));
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_failed_without_fallback() {
        let err = Handler::resolve_selected_ech_config_list(
            "example.com",
            None,
            Some(Err(anyhow!("dns failed"))),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("auto ech fetch failed for example.com: dns failed"));
    }

    #[cfg(any(feature = "openssl-tls", feature = "rustls-tls-aws-lc"))]
    #[test]
    fn test_should_skip_ech_dns_lookup_for_dnsclient_session() {
        let mut sess = Session::default();
        sess.inbound_tag = "dnsclient".to_string();
        assert!(Handler::should_skip_ech_dns_lookup_for_session(&sess));
        sess.inbound_tag = "socks".to_string();
        assert!(!Handler::should_skip_ech_dns_lookup_for_session(&sess));
    }

    #[test]
    fn test_new_with_invalid_ech_config_list_fails() {
        let mut settings = TlsOutboundSettings::new();
        settings.server_name = "localhost".to_string();
        settings.ech = true;
        settings.ech_config_list = "$$$".to_string();
        assert!(Handler::new(&settings, new_test_dns_client()).is_err());
    }

    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    #[test]
    fn test_new_with_ech_on_ring_does_not_fail_startup() {
        let mut settings = TlsOutboundSettings::new();
        settings.server_name = "localhost".to_string();
        settings.ech = true;
        assert!(Handler::new(&settings, new_test_dns_client()).is_ok());
    }

    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    #[test]
    fn test_build_rustls_config_with_ech_on_ring_returns_connection_error() {
        let err =
            Handler::build_rustls_config(&test_rustls_options(), Some("AQID")).unwrap_err();
        assert!(err.to_string().contains("requires rustls-tls-aws-lc"));
    }
}
