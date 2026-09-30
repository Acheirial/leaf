#[cfg(feature = "rustls-tls")]
use {std::fs::File, std::io, std::io::BufReader, std::path::Path};

use anyhow::Result;

#[cfg(feature = "rustls-tls")]
use {
    rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys},
    std::{collections::HashMap, sync::Arc},
    tokio_rustls::rustls::{
        crypto::CryptoProvider,
        pki_types::{CertificateDer, PrivateKeyDer},
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
        version::{TLS12, TLS13},
        ServerConfig, SupportedCipherSuite, SupportedProtocolVersion,
    },
    tokio_rustls::TlsAcceptor,
};

use crate::{config::internal::TlsInboundSettings, proxy::*, session::Session};

#[cfg(feature = "rustls-tls")]
use crate::config::internal::TlsCertificate;

pub struct Handler {
    #[cfg(feature = "rustls-tls")]
    acceptor: TlsAcceptor,
}

#[cfg(feature = "rustls-tls")]
fn load_certs(certificate: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    if certificate.contains("-----BEGIN") {
        let mut reader = BufReader::new(io::Cursor::new(certificate.as_bytes()));
        certs(&mut reader).collect()
    } else {
        let mut reader = BufReader::new(File::open(Path::new(certificate))?);
        certs(&mut reader).collect()
    }
}

#[cfg(feature = "rustls-tls")]
fn load_keys(certificate_key: &str) -> io::Result<Vec<PrivateKeyDer<'static>>> {
    let mut keys = Vec::new();
    if certificate_key.contains("-----BEGIN") {
        let mut reader = BufReader::new(io::Cursor::new(certificate_key.as_bytes()));
        for key in pkcs8_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Pkcs8(key?));
        }
        let mut reader = BufReader::new(io::Cursor::new(certificate_key.as_bytes()));
        for key in rsa_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Pkcs1(key?));
        }
        let mut reader = BufReader::new(io::Cursor::new(certificate_key.as_bytes()));
        for key in ec_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Sec1(key?));
        }
    } else {
        let path = Path::new(certificate_key);
        let mut reader = BufReader::new(File::open(path)?);
        for key in pkcs8_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Pkcs8(key?));
        }
        let mut reader = BufReader::new(File::open(path)?);
        for key in rsa_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Pkcs1(key?));
        }
        let mut reader = BufReader::new(File::open(path)?);
        for key in ec_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Sec1(key?));
        }
    }
    Ok(keys)
}

impl Handler {
    pub fn new(settings: &TlsInboundSettings) -> Result<Self> {
        #[cfg(feature = "rustls-tls")]
        {
            Ok(Self {
                acceptor: build_acceptor(settings)?,
            })
        }
        #[cfg(all(not(feature = "rustls-tls"), feature = "openssl-tls"))]
        {
            let _ = settings;
            Err(anyhow::anyhow!(
                "tls inbound requires the rustls-tls feature"
            ))
        }
        #[cfg(all(not(feature = "rustls-tls"), not(feature = "openssl-tls")))]
        {
            let _ = settings;
            Err(anyhow::anyhow!("no tls feature enabled"))
        }
    }
}

#[cfg(feature = "rustls-tls")]
fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(feature = "rustls-tls")]
fn default_crypto_provider() -> CryptoProvider {
    #[cfg(feature = "rustls-tls-aws-lc")]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    {
        rustls::crypto::ring::default_provider()
    }
}

#[cfg(feature = "rustls-tls")]
fn build_acceptor(settings: &TlsInboundSettings) -> Result<TlsAcceptor> {
    // Legacy `echConfig`/`echKey` pair: inbound ECH is not available, keep rejecting it.
    let ech_config = non_empty(&settings.ech_config);
    let ech_key = non_empty(&settings.ech_key);
    if load_ech(ech_config, ech_key)?.is_some() {
        tracing::error!(
            "tls inbound ech is configured but inbound ech is not supported by current rustls implementation"
        );
        return Err(anyhow::anyhow!(
            "tls inbound ech is not supported yet; remove echConfig and echKey"
        ));
    }

    // New `echServerKeys`: the linked rustls only implements the ECH *client*; there is no
    // server-side ECH API, so this cannot be served. Reject explicitly instead of ignoring it.
    if let Some(ech_server_keys) = settings.ech_server_keys.as_deref().and_then(non_empty) {
        tracing::error!("tls inbound ech_server_keys is configured but not supported");
        return Err(anyhow::anyhow!(
            "invalid \"echServerKeys\" ({}): the linked rustls implementation has no ECH server support; remove echServerKeys",
            ech_server_keys
        ));
    }

    let mut provider = default_crypto_provider();
    if let Some(cipher_suites) = settings.cipher_suites.as_deref() {
        apply_cipher_suites(&mut provider, cipher_suites)?;
    }
    let versions = rustls_versions(
        settings.min_version.as_deref(),
        settings.max_version.as_deref(),
    )?;

    let certificates = load_server_certificates(settings, &provider)?;
    let (default_certificate, by_name) = build_sni_index(certificates);

    let builder = ServerConfig::builder_with_provider(Arc::new(provider));
    let builder = match versions {
        Some(versions) => builder
            .with_protocol_versions(&versions)
            .map_err(|err| anyhow::anyhow!("invalid tls protocol versions: {}", err))?,
        None => builder
            .with_safe_default_protocol_versions()
            .map_err(|err| anyhow::anyhow!("invalid tls protocol versions: {}", err))?,
    };
    let config = builder
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniCertResolver {
            by_name,
            default: default_certificate,
            reject_unknown_sni: settings.reject_unknown_sni.unwrap_or(false),
        }));
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Map the configured `minVersion`/`maxVersion` onto the rustls protocol versions.
///
/// Mirrors the outbound agent's mapping: `None` means the rustls safe default (TLS 1.2 + TLS 1.3).
/// rustls cannot negotiate TLS 1.0/1.1, so a min of `1.0`/`1.1` is clamped up to 1.2 (offering
/// *more* than the configured floor is safe), while a max of `1.0`/`1.1` is a named config error —
/// the requested ceiling cannot be expressed and must never be silently raised. A min above the
/// max is rejected as well, as is any unrecognised version string.
#[cfg(feature = "rustls-tls")]
fn rustls_versions(
    min_version: Option<&str>,
    max_version: Option<&str>,
) -> Result<Option<Vec<&'static SupportedProtocolVersion>>> {
    if min_version.is_none() && max_version.is_none() {
        return Ok(None);
    }

    let min_rank = match min_version {
        Some(value) => version_rank(value, "min")?,
        None => 0,
    };
    let max_rank = match max_version {
        Some(value) => version_rank(value, "max")?,
        None => 13,
    };

    if min_rank > max_rank {
        return Err(anyhow::anyhow!(
            "tls min_version {:?} is greater than max_version {:?}",
            min_version,
            max_version
        ));
    }

    let mut versions = Vec::new();
    if min_rank <= 12 && max_rank >= 12 {
        versions.push(&TLS12);
    }
    if max_rank >= 13 {
        versions.push(&TLS13);
    }
    if versions.is_empty() {
        return Err(anyhow::anyhow!(
            "tls max_version {:?} is below the minimum supported by rustls (1.2)",
            max_version
        ));
    }
    if min_rank > 0 && min_rank < 12 {
        tracing::trace!(
            "tls min_version {:?} clamped to 1.2 (rustls minimum)",
            min_version
        );
    }
    Ok(Some(versions))
}

#[cfg(feature = "rustls-tls")]
fn version_rank(value: &str, which: &str) -> Result<u8> {
    match value.trim() {
        "1.0" => Ok(10),
        "1.1" => Ok(11),
        "1.2" => Ok(12),
        "1.3" => Ok(13),
        other => Err(anyhow::anyhow!(
            "invalid tls {}_version: {:?}",
            which,
            other
        )),
    }
}

/// Restrict the provider's TLS 1.2 cipher suites to the configured Go/IANA names.
///
/// Mirrors the outbound agent's mapping: names are `:`-separated, matched against the rustls
/// cipher-suite names; TLS 1.3 suites are kept untouched (the option only applies to TLS <= 1.2).
/// Unknown names are a config error.
#[cfg(feature = "rustls-tls")]
fn apply_cipher_suites(provider: &mut CryptoProvider, cipher_suites: &str) -> Result<()> {
    let names: Vec<&str> = cipher_suites
        .split(':')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        return Ok(());
    }

    let mut selected = Vec::with_capacity(names.len());
    for name in names {
        let cipher_suite = provider
            .cipher_suites
            .iter()
            .find(|cipher_suite| cipher_suite.suite().as_str() == Some(name))
            .ok_or_else(|| anyhow::anyhow!("unknown tls cipher_suite: {}", name))?;
        selected.push(*cipher_suite);
    }

    let mut suites: Vec<SupportedCipherSuite> = provider
        .cipher_suites
        .iter()
        .filter(|cipher_suite| cipher_suite.tls13().is_some())
        .copied()
        .collect();
    suites.extend(selected);
    provider.cipher_suites = suites;
    Ok(())
}

/// Load every configured server certificate, falling back to the legacy flat fields.
#[cfg(feature = "rustls-tls")]
fn load_server_certificates(
    settings: &TlsInboundSettings,
    provider: &CryptoProvider,
) -> Result<Vec<(Arc<CertifiedKey>, Vec<String>)>> {
    if settings.certificates.is_empty() {
        return load_flat_certificate(settings, provider);
    }

    let mut certificates = Vec::with_capacity(settings.certificates.len());
    for entry in settings.certificates.iter() {
        check_certificate_options(entry)?;
        let certificate = certificate_material(entry)?;
        let certificate_key = key_material(entry)?;
        certificates.push(load_certified_key(
            &certificate,
            &certificate_key,
            provider,
        )?);
    }
    if certificates.is_empty() {
        return Err(anyhow::anyhow!(
            "tls inbound requires at least one certificate"
        ));
    }
    Ok(certificates)
}

/// Legacy flat `certificate`/`certificate_key` fields, used when `certificates[]` is empty.
#[cfg(feature = "rustls-tls")]
fn load_flat_certificate(
    settings: &TlsInboundSettings,
    provider: &CryptoProvider,
) -> Result<Vec<(Arc<CertifiedKey>, Vec<String>)>> {
    if settings.certificate.is_empty() {
        return Err(anyhow::anyhow!("tls inbound requires a certificate"));
    }
    if settings.certificate_key.is_empty() {
        return Err(anyhow::anyhow!("tls inbound requires a certificate key"));
    }
    Ok(vec![load_certified_key(
        &settings.certificate,
        &settings.certificate_key,
        provider,
    )?])
}

#[cfg(feature = "rustls-tls")]
fn load_certified_key(
    certificate: &str,
    certificate_key: &str,
    provider: &CryptoProvider,
) -> Result<(Arc<CertifiedKey>, Vec<String>)> {
    let certs = load_certs(certificate)
        .map_err(|e| anyhow::anyhow!("load certificates from {} failed: {}", certificate, e))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in {}", certificate));
    }
    let mut keys = load_keys(certificate_key)
        .map_err(|e| anyhow::anyhow!("load keys from {} failed: {}", certificate_key, e))?;
    if keys.is_empty() {
        return Err(anyhow::anyhow!(
            "no private key found in {}",
            certificate_key
        ));
    }
    let certified = CertifiedKey::from_der(certs, keys.remove(0), provider)
        .map_err(|e| anyhow::anyhow!("build certificate failed: {}", e))?;
    let names = certified
        .cert
        .first()
        .map(|leaf| certificate_dns_names(leaf.as_ref()))
        .unwrap_or_default();
    Ok((Arc::new(certified), names))
}

/// Reject certificate options that cannot be honoured by this implementation.
#[cfg(feature = "rustls-tls")]
fn check_certificate_options(entry: &TlsCertificate) -> Result<()> {
    let usage = entry.usage.as_deref().unwrap_or("").to_ascii_lowercase();
    match usage.as_str() {
        "" | "encipherment" => {}
        "verify" | "issue" => {
            return Err(anyhow::anyhow!(
                "invalid \"certificates\": usage \"{}\" is not supported as a server certificate by this rustls implementation; only \"encipherment\" (or unset) is supported",
                usage
            ))
        }
        other => {
            return Err(anyhow::anyhow!(
                "invalid \"certificates\": unknown usage \"{}\"; expected \"encipherment\"",
                other
            ))
        }
    }

    if matches!(entry.ocsp_stapling, Some(value) if value != 0) {
        return Err(anyhow::anyhow!(
            "invalid \"certificates\": ocspStapling is configured but OCSP stapling is not supported by this implementation; remove ocspStapling"
        ));
    }

    if entry.build_chain == Some(true) {
        return Err(anyhow::anyhow!(
            "invalid \"certificates\": buildChain only applies to authority-issue certificates, which are not supported; remove buildChain"
        ));
    }

    let from_file = entry
        .certificate_file
        .as_deref()
        .map_or(false, |path| !path.is_empty())
        || entry
            .key_file
            .as_deref()
            .map_or(false, |path| !path.is_empty());
    // Inline certificate/key material is always loaded once (as Xray forces). File-backed
    // entries would be hot-reloaded by Xray unless `oneTimeLoading` is set, which is not
    // implemented here, so require the caller to opt into one-time loading explicitly.
    if from_file && entry.one_time_loading != Some(true) {
        return Err(anyhow::anyhow!(
            "invalid \"certificates\": certificate hot reload is not supported; set oneTimeLoading to true"
        ));
    }

    Ok(())
}

#[cfg(feature = "rustls-tls")]
fn certificate_material(entry: &TlsCertificate) -> Result<String> {
    resolve_material(
        entry.certificate_file.as_deref(),
        &entry.certificate,
        "certificate",
    )
}

#[cfg(feature = "rustls-tls")]
fn key_material(entry: &TlsCertificate) -> Result<String> {
    resolve_material(entry.key_file.as_deref(), &entry.key, "key")
}

#[cfg(feature = "rustls-tls")]
fn resolve_material(file: Option<&str>, inline: &[String], name: &str) -> Result<String> {
    if let Some(path) = file {
        if !path.is_empty() {
            return Ok(path.to_string());
        }
    }
    if !inline.is_empty() {
        return Ok(inline.join("\n"));
    }
    Err(anyhow::anyhow!(
        "invalid \"certificates\": missing {} (set {}File or {})",
        name,
        name,
        name
    ))
}

/// Build the SNI index: the first certificate is the default, every certificate is also indexed
/// by the DNS names (SAN, plus common name) it presents.
#[cfg(feature = "rustls-tls")]
fn build_sni_index(
    certificates: Vec<(Arc<CertifiedKey>, Vec<String>)>,
) -> (Arc<CertifiedKey>, HashMap<String, Arc<CertifiedKey>>) {
    let default = certificates[0].0.clone();
    let mut by_name = HashMap::new();
    for (certificate, names) in certificates.iter() {
        for name in names {
            by_name
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| certificate.clone());
        }
    }
    (default, by_name)
}

#[cfg(feature = "rustls-tls")]
#[derive(Debug)]
struct SniCertResolver {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Arc<CertifiedKey>,
    reject_unknown_sni: bool,
}

#[cfg(feature = "rustls-tls")]
impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            let server_name = server_name.to_ascii_lowercase();
            if let Some(certificate) = self.by_name.get(&server_name) {
                return Some(certificate.clone());
            }
            if let Some(index) = server_name.find('.') {
                let wildcard = format!("*{}", &server_name[index..]);
                if let Some(certificate) = self.by_name.get(&wildcard) {
                    return Some(certificate.clone());
                }
            }
        }
        // Unknown SNI: reject (rustls turns `None` into a fatal handshake alert) when configured,
        // otherwise fall back to the first configured certificate.
        if self.reject_unknown_sni {
            None
        } else {
            Some(self.default.clone())
        }
    }
}

/// Extract the DNS names (subjectAltName dNSName entries, falling back to the subject common
/// name) from a DER-encoded X.509 leaf certificate.
#[cfg(feature = "rustls-tls")]
fn certificate_dns_names(der: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let Some(tbs) = certificate_tbs_certificate(der) else {
        return names;
    };

    let mut cursor = Der::new(tbs);
    if cursor.peek_tag() == Some(0xa0) {
        // version [0] EXPLICIT
        let _ = cursor.read_tlv();
    }
    let _ = cursor.read_tlv(); // serialNumber
    let _ = cursor.read_tlv(); // signature
    let _ = cursor.read_tlv(); // issuer
    let _ = cursor.read_tlv(); // validity
    let Some((_tag, subject)) = cursor.read_tlv() else {
        return names;
    };
    let _ = cursor.read_tlv(); // subjectPublicKeyInfo

    let mut extensions = None;
    while let Some((tag, value)) = cursor.read_tlv() {
        if tag == 0xa3 {
            // extensions [3] EXPLICIT
            extensions = Some(value);
            break;
        }
    }

    if let Some(common_name) = subject_common_name(subject) {
        names.push(common_name);
    }
    if let Some(extensions) = extensions {
        names.extend(subject_alt_names(extensions));
    }
    names
}

#[cfg(feature = "rustls-tls")]
fn certificate_tbs_certificate(der: &[u8]) -> Option<&[u8]> {
    let mut outer = Der::new(der);
    let (tag, certificate) = outer.read_tlv()?;
    if tag != 0x30 {
        return None;
    }
    let mut inner = Der::new(certificate);
    let (tag, tbs) = inner.read_tlv()?;
    if tag != 0x30 {
        return None;
    }
    Some(tbs)
}

#[cfg(feature = "rustls-tls")]
fn subject_common_name(subject: &[u8]) -> Option<String> {
    const COMMON_NAME_OID: &[u8] = &[0x55, 0x04, 0x03];
    let mut name = Der::new(subject);
    while let Some((tag, rdn)) = name.read_tlv() {
        if tag != 0x31 {
            continue;
        }
        let mut set = Der::new(rdn);
        while let Some((tag, atv)) = set.read_tlv() {
            if tag != 0x30 {
                continue;
            }
            let mut attribute = Der::new(atv);
            let Some((_tag, oid)) = attribute.read_tlv() else {
                continue;
            };
            if oid == COMMON_NAME_OID {
                if let Some((_tag, value)) = attribute.read_tlv() {
                    return Some(String::from_utf8_lossy(value).into_owned());
                }
            }
        }
    }
    None
}

#[cfg(feature = "rustls-tls")]
fn subject_alt_names(extensions: &[u8]) -> Vec<String> {
    const SUBJECT_ALT_NAME_OID: &[u8] = &[0x55, 0x1d, 0x11];
    let mut names = Vec::new();
    // `extensions` is the content of the `[3] EXPLICIT` field, i.e. the DER of
    // `SEQUENCE OF Extension`; strip that outer SEQUENCE first.
    let mut outer = Der::new(extensions);
    let Some((_tag, extensions)) = outer.read_tlv() else {
        return names;
    };
    let mut extensions = Der::new(extensions);
    while let Some((tag, extension)) = extensions.read_tlv() {
        if tag != 0x30 {
            continue;
        }
        let mut extension = Der::new(extension);
        let Some((_tag, oid)) = extension.read_tlv() else {
            continue;
        };
        if oid != SUBJECT_ALT_NAME_OID {
            continue;
        }
        let mut value = extension.read_tlv();
        if let Some((0x01, _)) = value {
            // critical BOOLEAN
            value = extension.read_tlv();
        }
        let Some((0x04, san)) = value else {
            continue;
        };
        // The OCTET STRING wraps `GeneralNames ::= SEQUENCE OF GeneralName`.
        let mut san = Der::new(san);
        let Some((_tag, san)) = san.read_tlv() else {
            continue;
        };
        let mut general_names = Der::new(san);
        while let Some((tag, name)) = general_names.read_tlv() {
            if tag == 0x82 {
                // dNSName
                names.push(String::from_utf8_lossy(name).into_owned());
            }
        }
    }
    names
}

/// Minimal DER reader used to extract the leaf certificate's names.
#[cfg(feature = "rustls-tls")]
struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

#[cfg(feature = "rustls-tls")]
impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.data.get(self.pos)?;
        let first = *self.data.get(self.pos + 1)?;
        let mut pos = self.pos + 2;
        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > std::mem::size_of::<usize>() {
                return None;
            }
            let mut length = 0usize;
            for _ in 0..count {
                length = (length << 8) | *self.data.get(pos)? as usize;
                pos += 1;
            }
            length
        };
        let end = pos.checked_add(length)?;
        let value = self.data.get(pos..end)?;
        self.pos = end;
        Some((tag, value))
    }
}

#[cfg(feature = "rustls-tls")]
fn load_ech(
    ech_config: Option<&str>,
    ech_key: Option<&str>,
) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    match (ech_config, ech_key) {
        (None, None) => Ok(None),
        (Some(config), Some(key)) => {
            let config = decode_ech_blob(config)?;
            let key = decode_ech_blob(key)?;
            if config.is_empty() || key.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid ech config or key",
                ));
            }
            Ok(Some((config, key)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ech config and key must be set together",
        )),
    }
}

#[cfg(feature = "rustls-tls")]
fn decode_ech_blob(input: &str) -> io::Result<Vec<u8>> {
    let value = input.trim();
    if value.starts_with("-----BEGIN") {
        let mut encoded = String::new();
        for line in value.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("-----BEGIN") || line.starts_with("-----END") {
                continue;
            }
            encoded.push_str(line);
        }
        if encoded.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ech pem",
            ));
        }
        return decode_base64(&encoded);
    }
    decode_base64(value)
}

#[cfg(feature = "rustls-tls")]
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
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        #[cfg(feature = "rustls-tls")]
        {
            let tls = self.acceptor.accept(stream).await?;
            let mut sess = sess;
            {
                // The outer connection state is what VLESS fallbacks select on;
                // it is available as soon as the handshake completes.
                let (_, conn) = tls.get_ref();
                sess.outer_sni = conn.server_name().map(|name| name.to_ascii_lowercase());
                sess.outer_alpn = conn
                    .alpn_protocol()
                    .map(|alpn| String::from_utf8_lossy(alpn).into_owned());
            }
            Ok(InboundTransport::Stream(Box::new(tls), sess))
        }

        #[cfg(all(not(feature = "rustls-tls"), feature = "openssl-tls"))]
        {
            let _ = (sess, stream);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tls inbound requires the rustls-tls feature",
            ))
        }
        #[cfg(all(not(feature = "rustls-tls"), not(feature = "openssl-tls")))]
        {
            let _ = (sess, stream);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "no tls feature enabled",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_base64, decode_ech_blob, load_ech};

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
    fn test_decode_ech_blob_pem() {
        let value = "-----BEGIN ECH-----\nAQID\n-----END ECH-----";
        assert_eq!(decode_ech_blob(value).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_load_ech_pair() {
        assert!(load_ech(None, None).unwrap().is_none());
        assert!(load_ech(Some("AQID"), Some("AQID")).unwrap().is_some());
        assert!(load_ech(Some("AQID"), None).is_err());
    }

    #[cfg(feature = "rustls-tls")]
    fn self_signed(name: &str) -> (String, String, Vec<u8>) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        (cert.pem(), key_pair.serialize_pem(), cert.der().to_vec())
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_certificate_dns_names() {
        let (_cert_pem, _key_pem, der) = self_signed("localhost");
        let names = super::certificate_dns_names(&der);
        assert!(names.iter().any(|name| name == "localhost"), "{:?}", names);
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_new_with_flat_certificate() {
        use crate::config::internal::TlsInboundSettings;
        let (cert_pem, key_pem, _der) = self_signed("localhost");
        let settings = TlsInboundSettings {
            certificate: cert_pem,
            certificate_key: key_pem,
            ..Default::default()
        };
        assert!(super::Handler::new(&settings).is_ok());
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_new_with_ech_rejected() {
        use crate::config::internal::TlsInboundSettings;
        let (cert_pem, key_pem, _der) = self_signed("localhost");
        let settings = TlsInboundSettings {
            certificate: cert_pem,
            certificate_key: key_pem,
            ech_config: "AQID".to_string(),
            ech_key: "BAUG".to_string(),
            ..Default::default()
        };
        assert!(super::Handler::new(&settings).is_err());
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_new_with_ech_server_keys_rejected() {
        use crate::config::internal::TlsInboundSettings;
        let (cert_pem, key_pem, _der) = self_signed("localhost");
        let settings = TlsInboundSettings {
            certificate: cert_pem,
            certificate_key: key_pem,
            ech_server_keys: Some("AQID".to_string()),
            ..Default::default()
        };
        let err = super::Handler::new(&settings)
            .err()
            .expect("Handler::new should reject this configuration")
            .to_string();
        assert!(err.contains("echServerKeys"), "{}", err);
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_unsupported_usage_rejected() {
        use crate::config::internal::{TlsCertificate, TlsInboundSettings};
        let (cert_pem, key_pem, _der) = self_signed("localhost");
        let settings = TlsInboundSettings {
            certificates: vec![TlsCertificate {
                certificate: vec![cert_pem],
                key: vec![key_pem],
                usage: Some("issue".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = super::Handler::new(&settings)
            .err()
            .expect("Handler::new should reject this configuration")
            .to_string();
        assert!(err.contains("issue"), "{}", err);
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_unknown_cipher_suite_rejected() {
        use crate::config::internal::TlsInboundSettings;
        let (cert_pem, key_pem, _der) = self_signed("localhost");
        let settings = TlsInboundSettings {
            certificate: cert_pem,
            certificate_key: key_pem,
            cipher_suites: Some("TLS_NOT_A_REAL_SUITE".to_string()),
            ..Default::default()
        };
        let err = super::Handler::new(&settings)
            .err()
            .expect("Handler::new should reject this configuration")
            .to_string();
        assert!(err.contains("unknown tls cipher_suite"), "{}", err);
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_versions_mapping() {
        assert!(super::rustls_versions(None, None).unwrap().is_none());
        assert_eq!(
            super::rustls_versions(Some("1.2"), Some("1.2"))
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            super::rustls_versions(Some("1.1"), Some("1.3"))
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert!(super::rustls_versions(Some("1.3"), Some("1.2")).is_err());
        assert!(super::rustls_versions(None, Some("1.1")).is_err());
        assert!(super::rustls_versions(None, Some("1.0")).is_err());
        assert!(super::rustls_versions(Some("2.0"), None).is_err());

        // A max below rustls' floor is a *named* error, not a silent raise of the ceiling.
        let err = super::rustls_versions(None, Some("1.1"))
            .err()
            .expect("max 1.1 is not expressible by rustls")
            .to_string();
        assert!(err.contains("1.2"), "{}", err);

        // A min below the floor is still clamped up (offering more than the floor is safe).
        assert_eq!(
            super::rustls_versions(Some("1.1"), None)
                .unwrap()
                .unwrap()
                .len(),
            2
        );
    }
}
