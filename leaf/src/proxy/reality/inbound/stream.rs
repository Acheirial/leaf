//! REALITY inbound (server) handler.
//!
//! This is a from-scratch Rust implementation of the REALITY server side
//! (`xtls/reality` `Server()`), built on the patched `rustls` fork that ships
//! the client half. For every incoming connection it:
//!
//! 1. reads and parses the cleartext `ClientHello` itself (the patched rustls
//!    `server::Acceptor` deliberately does not expose the `random`, the
//!    `session_id` or the raw handshake bytes, which are exactly the fields
//!    REALITY authenticates);
//! 2. derives the shared `AuthKey` from the X25519 key share carried in the
//!    `ClientHello` (group `x25519`, or the X25519 half of `X25519MLKEM768`)
//!    and the configured `privateKey`, then opens the 32-byte `session_id` with
//!    AES-256-GCM;
//! 3. **authenticated** — completes a normal TLS 1.3 handshake with a
//!    self-signed Ed25519 certificate whose signature field is
//!    `HMAC-SHA512(AuthKey, spki_public_key)` (the REALITY server certificate
//!    marker), and hands the decrypted stream to the inbound chain;
//! 4. **unauthenticated** — the "steal" path: dials `dest`/`target`, replays
//!    the bytes already consumed and splices both directions verbatim, so the
//!    client sees the real target's certificate.
//!
//! Wire format reproduced from `xtls/reality` / Xray-core:
//!
//! * `AuthKey = HKDF-SHA256(ikm = X25519(server_priv, client_pub),
//!   salt = random[0..20], info = "REALITY")`.
//! * `session_id = AES-256-GCM(AuthKey, nonce = random[20..32],
//!   plaintext = version[3] || 0 || unix_time_be[4] || short_id[8],
//!   aad = raw ClientHello handshake message with bytes 39..71 zeroed)`.
//! * certificate signature check is HMAC-SHA512 over the Ed25519 SubjectPublicKeyInfo.

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use reality_rustls::crypto::ring::{default_provider, sign::any_supported_type};
use reality_rustls::crypto::CryptoProvider;
use reality_rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use reality_rustls::server::{ClientHello, ResolvesServerCert, ServerConfig, ServerConnection};
use reality_rustls::sign::{CertifiedKey, SigningKey};

use crate::{config::internal::RealityInboundSettings, proxy::*, session::Session};

/// A throwaway self-signed Ed25519 certificate (DER). Its signature field is
/// replaced per connection by `HMAC-SHA512(AuthKey, spki_public_key)`, which is
/// the only thing the REALITY client checks; the SPKI and private key stay
/// fixed so the server can sign `CertificateVerify`.
const DUMMY_CERT_DER_HEX: &str = "3082013a3081eda00302010202145215e25a2beff981e1fa355139ef55497d8383fa300506032b657030123110300e06035504030c077265616c6974793020170d3236303932393133303934305a180f32313236303930353133303934305a30123110300e06035504030c077265616c697479302a300506032b6570032100f41c2d5de4a4ebd0e9f38830939b098158337953cdb90e0de0a2c69e61d8ca7ea3533051301d0603551d0e04160414726cdfd579e57e0acf18a96a045a22e7550fce49301f0603551d23041830168014726cdfd579e57e0acf18a96a045a22e7550fce49300f0603551d130101ff040530030101ff300506032b6570034100b7d90393822921fe1536c4a6903671aadc639d76990e81d02aa37a0f0101cac69f6ec4fbf5a3e6ed001d8898ccff31fc0e4d237d40bc2a332a67954d36951605";
/// PKCS#8 DER of the Ed25519 key matching [`DUMMY_CERT_DER_HEX`].
const DUMMY_KEY_PKCS8_HEX: &str =
    "302e020100300506032b657004220420152433cf575959d9bf0a4d290d18b53e6526273040c9f6803483b419fb6f9a67";
/// The 32-byte Ed25519 public key of [`DUMMY_CERT_DER_HEX`] (the SPKI payload).
const DUMMY_PUBKEY_HEX: &str = "f41c2d5de4a4ebd0e9f38830939b098158337953cdb90e0de0a2c69e61d8ca7e";

const REALITY_INFO: &[u8] = b"REALITY";
/// Offset of the REALITY `session_id` inside the raw `ClientHello` handshake
/// message (`type(1) || len(3) || version(2) || random(32) || sid_len(1)`).
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;
const TLS13_VERSION: u16 = 0x0304;
const GROUP_X25519: u16 = 29;
const GROUP_X25519_MLKEM768: u16 = 4588;
/// X25519 component length inside an `X25519MLKEM768` key share.
const MLKEM768_PUBKEY_LEN: usize = 1184;

pub struct Handler {
    private_key: [u8; 32],
    server_names: Vec<String>,
    short_ids: Vec<[u8; 8]>,
    max_time_diff_ms: Option<u64>,
    show: bool,
    dest: Option<String>,
    xver: u8,
    cert_der: Vec<u8>,
    ed25519_pubkey: [u8; 32],
    signing_key: Arc<dyn SigningKey>,
    provider: Arc<CryptoProvider>,
    alpn: Vec<Vec<u8>>,
}

impl Handler {
    /// Build the handler from the inbound REALITY settings.
    ///
    /// Fails when `privateKey`, `serverNames`, `shortIds` or `dest`/`target`
    /// are missing or malformed, matching Xray's `REALITYConfig.Build`
    /// validation. `xver` is limited to the PROXY protocol versions Xray
    /// accepts (0, 1, 2).
    pub fn new(settings: &RealityInboundSettings) -> Result<Self> {
        let private_key = decode_private_key(settings.private_key.as_deref())?;

        let server_names: Vec<String> = settings
            .server_names
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if server_names.is_empty() {
            return Err(anyhow!("reality inbound requires a non-empty serverNames"));
        }

        let short_ids = parse_short_ids(&settings.short_ids)?;
        if short_ids.is_empty() {
            return Err(anyhow!("reality inbound requires a non-empty shortIds"));
        }

        let dest = settings
            .dest
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| settings.target.first().cloned().filter(|s| !s.is_empty()));
        if dest.is_none() {
            return Err(anyhow!("reality inbound requires dest or target"));
        }

        let xver = settings.xver.unwrap_or(0);
        if xver > 2 {
            return Err(anyhow!(
                "reality inbound invalid xver {xver}: only 0, 1, 2 are accepted"
            ));
        }

        let cert_der = hex::decode(DUMMY_CERT_DER_HEX)
            .map_err(|e| anyhow!("reality inbound embedded certificate is invalid: {e}"))?;
        let pkcs8 = hex::decode(DUMMY_KEY_PKCS8_HEX)
            .map_err(|e| anyhow!("reality inbound embedded key is invalid: {e}"))?;
        let ed25519_pubkey: [u8; 32] = hex::decode(DUMMY_PUBKEY_HEX)
            .map_err(|e| anyhow!("reality inbound embedded public key is invalid: {e}"))?
            .try_into()
            .map_err(|_| anyhow!("reality inbound embedded public key has the wrong length"))?;

        let signing_key = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8,
        )))
        .map_err(|e| anyhow!("reality inbound failed to load the Ed25519 signing key: {e}"))?;

        let provider = Arc::new(default_provider());

        Ok(Self {
            private_key,
            server_names,
            short_ids,
            max_time_diff_ms: settings.max_time_diff_ms.map(u64::from),
            show: settings.show.unwrap_or(false),
            dest,
            xver: xver as u8,
            cert_der,
            ed25519_pubkey,
            signing_key,
            provider,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        })
    }

    fn sni_allowed(&self, sni: Option<&str>) -> bool {
        match sni {
            Some(sni) => self
                .server_names
                .iter()
                .any(|n| n == &sni.to_ascii_lowercase()),
            None => false,
        }
    }

    fn short_id_allowed(&self, short_id: &[u8; 8]) -> bool {
        self.short_ids.iter().any(|s| s == short_id)
    }

    /// Build a per-connection `ServerConfig` presenting the REALITY certificate
    /// carrying `hmac` as its signature.
    fn server_config(&self, hmac: &[u8]) -> Result<Arc<ServerConfig>> {
        let mut cert = self.cert_der.clone();
        if cert.len() < 64 || hmac.len() != 64 {
            return Err(anyhow!("reality inbound cannot sign the certificate"));
        }
        let n = cert.len();
        cert[n - 64..].copy_from_slice(hmac);

        let certified =
            CertifiedKey::new(vec![CertificateDer::from(cert)], self.signing_key.clone());
        let resolver = Arc::new(FixedResolver(Arc::new(certified)));
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!("reality inbound rustls config failed: {e}"))?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = self.alpn.clone();
        Ok(Arc::new(config))
    }
}

/// A certificate resolver handing the same per-connection key to every
/// `ClientHello`; the key already encodes the connection's `AuthKey` HMAC.
#[derive(Debug)]
struct FixedResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound reality stream");
        let mut stream = stream;

        // The patched rustls `Acceptor` never exposes `random`/`session_id`/raw
        // handshake bytes, so read and parse the ClientHello here, then hand the
        // very same record bytes to rustls.
        //
        // Every byte consumed here is replayed to `dest` on the steal path, so a
        // first record that is not a ClientHello at all (plain HTTP, a TLS
        // 1.0/1.1 handshake, any probe) and even a read error are relayed
        // verbatim instead of being closed. The reference reaches its forward
        // path for *any* read/parse failure (`reality-ref/tls.go:212`, whose
        // `MirrorConn` forwards every byte, and `282-286`).
        let mut records = Vec::with_capacity(1024);
        let message = match read_client_hello(&mut stream, &mut records).await {
            Ok(message) => Some(message),
            Err(e) => {
                tracing::debug!("reality: not a TLS ClientHello, relaying to dest: {e}");
                None
            }
        };
        let hello = message.as_deref().and_then(parse_client_hello);

        let authenticated = match (message.as_deref(), hello.as_ref()) {
            (Some(message), Some(hello))
                if hello.tls13 && self.sni_allowed(hello.sni.as_deref()) =>
            {
                match self.authenticate(message, hello) {
                    Some(auth) => {
                        if self.show {
                            tracing::info!(
                                "REALITY {} authenticated: sni={:?} short_id={:?} time_diff_ms={}",
                                sess.source,
                                hello.sni,
                                auth.short_id,
                                auth.time_diff_ms
                            );
                        }
                        Some(auth)
                    }
                    None => {
                        if self.show {
                            tracing::info!(
                                "REALITY {} not authenticated: sni={:?}",
                                sess.source,
                                hello.sni
                            );
                        }
                        None
                    }
                }
            }
            _ => {
                if self.show {
                    match hello.as_ref() {
                        Some(hello) => tracing::info!(
                            "REALITY {} rejected ClientHello: tls13={} sni={:?}",
                            sess.source,
                            hello.tls13,
                            hello.sni
                        ),
                        None => tracing::info!(
                            "REALITY {} rejected: first record is not a TLS ClientHello",
                            sess.source
                        ),
                    }
                }
                None
            }
        };

        if let Some(auth) = authenticated {
            let config = self
                .server_config(&auth.hmac)
                .map_err(|e| io::Error::other(format!("reality: {e}")))?;
            let conn = ServerConnection::new(config)
                .map_err(|e| io::Error::other(format!("reality: server connection: {e}")))?;
            let mut inbound = InboundStream::new(conn, stream);
            inbound.handshake(&records).await?;

            // Expose the outer connection's SNI/ALPN on the session: the VLESS
            // fallbacks must select on the *outer* TLS/REALITY parameters, not
            // on the inner sniffing the dispatcher does later (`Session`:
            // `outer_sni`, `outer_alpn`). SNI is lowercased; ALPN is kept
            // verbatim. Both are `None` when absent. The steal path never
            // reaches VLESS and leaves them unset.
            sess.outer_sni = hello
                .as_ref()
                .and_then(|hello| hello.sni.as_ref())
                .map(|sni| sni.to_ascii_lowercase());
            sess.outer_alpn = inbound
                .conn
                .alpn_protocol()
                .map(|alpn| String::from_utf8_lossy(alpn).into_owned());
            return Ok(InboundTransport::Stream(Box::new(inbound), sess));
        }

        // Steal path: relay the raw byte stream, verbatim, to the configured
        // target. The target answers with its own TLS and the client sees that
        // certificate.
        self.relay(&sess, stream, &records).await?;
        Ok(InboundTransport::Empty)
    }
}

impl Handler {
    /// Verify the REALITY authentication embedded in `message`/`hello`.
    ///
    /// Returns the HMAC-SHA512 certificate signature together with the decoded
    /// short id and timestamp when every check passes (`maxTimeDiff`, short id
    /// membership); `None` otherwise.
    fn authenticate(&self, message: &[u8], hello: &ClientHelloInfo) -> Option<AuthResult> {
        if hello.session_id.len() != SESSION_ID_LEN {
            return None;
        }
        let peer_pub = hello.x25519_public_key()?;

        let shared = x25519_dalek::x25519(self.private_key, peer_pub);
        if shared.iter().all(|b| *b == 0) {
            return None;
        }

        let hkdf = Hkdf::<Sha256>::new(Some(&hello.random[..20]), &shared);
        let mut auth_key = [0u8; 32];
        hkdf.expand(REALITY_INFO, &mut auth_key).ok()?;

        // AD: the raw ClientHello handshake message with the session id zeroed.
        if message.len() < SESSION_ID_OFFSET + SESSION_ID_LEN {
            return None;
        }
        let mut aad = message.to_vec();
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);

        let cipher = Aes256Gcm::new_from_slice(&auth_key).ok()?;
        let nonce = &hello.random[20..32];
        let mut plain = hello.session_id.clone();
        cipher
            .decrypt_in_place(Nonce::from_slice(nonce), &aad, &mut plain)
            .ok()?;
        if plain.len() != 16 {
            return None;
        }

        let client_time = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]);
        let mut short_id = [0u8; 8];
        short_id.copy_from_slice(&plain[8..16]);

        if !self.short_id_allowed(&short_id) {
            return None;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let time_diff_ms = now.abs_diff(u64::from(client_time)) * 1000;
        // `maxTimeDiffMs: 0` disables the freshness check, exactly like
        // `config.MaxTimeDiff == 0 || time.Since(...).Abs() <= config.MaxTimeDiff`
        // (`reality-ref/tls.go:270`).
        if let Some(max) = self.max_time_diff_ms.filter(|max| *max != 0) {
            if time_diff_ms > max {
                return None;
            }
        }

        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key).ok()?;
        mac.update(&self.ed25519_pubkey);
        let mut hmac = [0u8; 64];
        hmac.copy_from_slice(&mac.finalize().into_bytes());

        Some(AuthResult {
            hmac,
            short_id,
            time_diff_ms,
        })
    }

    /// Byte-transparent relay of the (already partially consumed) client stream
    /// to `dest`, optionally prefixed with a PROXY protocol header.
    ///
    /// The dial and the replay of the consumed bytes happen inline so a failure
    /// still surfaces to the caller; the bidirectional splice then runs in the
    /// background for the connection's lifetime, exactly like the reference's
    /// `io.Copy` goroutines (`reality-ref/tls.go:212,282-286`) and the VLESS
    /// fallback (`vless/inbound/stream.rs:135-141`). Awaiting the splice here
    /// would pin the relay to the listener's accept timeout and kill every
    /// relayed connection after the timeout elapses.
    async fn relay(&self, sess: &Session, mut stream: AnyStream, records: &[u8]) -> io::Result<()> {
        let dest = self
            .dest
            .as_deref()
            .ok_or_else(|| io::Error::other("reality: no dest configured"))?
            .to_owned();
        let mut target = tokio::net::TcpStream::connect(&dest)
            .await
            .map_err(|e| io::Error::other(format!("reality: dial dest {dest} failed: {e}")))?;

        if self.xver == 1 || self.xver == 2 {
            let header = proxy_protocol_header(self.xver, sess.source, sess.local_addr);
            target.write_all(&header).await?;
        }
        target.write_all(records).await?;
        target.flush().await?;

        // The accept path only waits for the ClientHello; splice the steal path
        // in the background so the connection can live as long as either side.
        tokio::spawn(async move {
            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut target).await {
                tracing::debug!("reality steal path ended: {}", e);
            }
        });
        Ok(())
    }
}

struct AuthResult {
    hmac: [u8; 64],
    short_id: [u8; 8],
    time_diff_ms: u64,
}

/// Parsed pieces of a `ClientHello` REALITY needs.
struct ClientHelloInfo {
    random: [u8; 32],
    session_id: Vec<u8>,
    sni: Option<String>,
    tls13: bool,
    key_shares: Vec<(u16, Vec<u8>)>,
}

impl ClientHelloInfo {
    /// The X25519 public key to use for the REALITY ECDH, following the
    /// selection in `reality-ref/tls.go:216-236`:
    ///
    /// * an `X25519MLKEM768` key share (exactly `1184 + 32` bytes) contributes
    ///   its X25519 half (`keyShare.data[EncapsulationKeySize768:]`);
    /// * a plain `X25519` key share is only honoured when it appears after the
    ///   hybrid — the reference breaks at the first plain share and rejects the
    ///   ClientHello when no hybrid was seen before it (`break // ensure order`);
    /// * a duplicate share of either group fails the ClientHello
    ///   (`peerPub2 = nil // ensure fail`).
    ///
    /// The reference also rejects a ClientHello that has no hybrid share at all
    /// ("reject outdated/strange Client Hello that doesn't have
    /// X25519MLKEM768"). leaf deliberately still accepts a lone plain `X25519`
    /// share: its own outbound offers only that, because the ring provider has
    /// no `X25519MLKEM768` group, so requiring the hybrid would break every
    /// leaf-to-leaf connection. Duplicate and misordered shares are still
    /// rejected and take the steal path.
    fn x25519_public_key(&self) -> Option<[u8; 32]> {
        let mut peer_pub: Option<[u8; 32]> = None; // plain `X25519`
        let mut peer_pub2: Option<[u8; 32]> = None; // X25519 half of `X25519MLKEM768`
        for (group, data) in &self.key_shares {
            match *group {
                GROUP_X25519_MLKEM768 if data.len() == MLKEM768_PUBKEY_LEN + 32 => {
                    if peer_pub2.is_some() {
                        // Duplicate hybrid share: the reference forces a failure.
                        return None;
                    }
                    if peer_pub.is_some() {
                        // Plain X25519 before the hybrid: misordered, rejected by
                        // the reference's `break // ensure order`.
                        return None;
                    }
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&data[MLKEM768_PUBKEY_LEN..]);
                    peer_pub2 = Some(out);
                }
                GROUP_X25519 if data.len() == 32 => {
                    if peer_pub.is_some() {
                        // Duplicate X25519 share: the reference forces a failure.
                        return None;
                    }
                    let mut out = [0u8; 32];
                    out.copy_from_slice(data);
                    peer_pub = Some(out);
                }
                _ => {}
            }
        }
        // Prefer the plain share when present, otherwise the hybrid's X25519
        // half (`reality-ref/tls.go:233-235`).
        peer_pub.or(peer_pub2)
    }
}

/// Decode an Xray `privateKey`: `base64url` without padding, or hex.
fn decode_private_key(private_key: Option<&str>) -> Result<[u8; 32]> {
    let private_key = private_key
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("reality inbound requires a non-empty privateKey"))?;
    let bytes = if let Ok(bytes) = URL_SAFE_NO_PAD.decode(private_key) {
        bytes
    } else if let Ok(bytes) = hex::decode(private_key) {
        bytes
    } else {
        return Err(anyhow!("reality inbound invalid privateKey: {private_key}"));
    };
    bytes
        .try_into()
        .map_err(|_| anyhow!("reality inbound privateKey must be 32 bytes"))
}

/// Decode the hex `shortIds`, zero-padded to 8 bytes like Xray.
fn parse_short_ids(short_ids: &[String]) -> Result<Vec<[u8; 8]>> {
    let mut out = Vec::with_capacity(short_ids.len());
    for s in short_ids {
        if s.len() > 16 {
            return Err(anyhow!("reality inbound shortId too long: {s}"));
        }
        if s.len() % 2 != 0 {
            return Err(anyhow!("reality inbound invalid shortId {s}: odd length"));
        }
        let mut id = [0u8; 8];
        if !s.is_empty() {
            let padded = format!("{s:0<16}");
            hex::decode_to_slice(&padded[..16], &mut id)
                .map_err(|e| anyhow!("reality inbound invalid shortId {s}: {e}"))?;
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// `read_exact`, but appends every byte read to `records` — including a short
/// read that ends in an error — so the steal path can replay partially consumed
/// records verbatim (`reality-ref/tls.go:282-286` forwards bytes as they
/// arrive, never discarding what it has already read).
async fn read_exact_recording<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
    records: &mut Vec<u8>,
) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]).await {
            Ok(0) => {
                records.extend_from_slice(&buf[..filled]);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "reality: eof while reading a TLS record",
                ));
            }
            Ok(n) => filled += n,
            Err(e) => {
                records.extend_from_slice(&buf[..filled]);
                return Err(e);
            }
        }
    }
    records.extend_from_slice(buf);
    Ok(())
}

/// Read TLS records off `stream` until the first handshake message (the
/// ClientHello) is complete, appending every byte read to `records`.
///
/// The consumed bytes are appended even when an error is returned, so the
/// caller can replay the whole stream verbatim on the steal path — the
/// reference's `MirrorConn` forwards every byte it has read regardless of how
/// the handshake turns out (`reality-ref/tls.go:212,282-286`).
async fn read_client_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
    records: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut handshake = Vec::with_capacity(512);
    let mut header = [0u8; 5];
    loop {
        read_exact_recording(stream, &mut header, records).await?;
        let content_type = header[0];
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if content_type != 22 {
            // A first flight is handshake-only (possibly preceded by a
            // compatibility ChangeCipherSpec record).
            if content_type == 20 {
                let mut body = vec![0u8; len];
                read_exact_recording(stream, &mut body, records).await?;
                continue;
            }
            return Err(io::Error::other(format!(
                "reality: unexpected record type {content_type} before ClientHello"
            )));
        }
        let mut body = vec![0u8; len];
        read_exact_recording(stream, &mut body, records).await?;
        handshake.extend_from_slice(&body);

        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Err(io::Error::other(format!(
                    "reality: expected ClientHello, got handshake type {}",
                    handshake[0]
                )));
            }
            let msg_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if handshake.len() >= 4 + msg_len {
                handshake.truncate(4 + msg_len);
                return Ok(handshake);
            }
        }
        if records.len() > 64 * 1024 {
            return Err(io::Error::other("reality: ClientHello too large"));
        }
    }
}

/// Parse the fields REALITY needs out of a `ClientHello` handshake message.
fn parse_client_hello(message: &[u8]) -> Option<ClientHelloInfo> {
    if message.len() < 4 || message[0] != 1 {
        return None;
    }
    let body = &message[4..];

    // legacy_version(2) + random(32)
    if body.len() < 34 {
        return None;
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[2..34]);
    let mut p = 34usize;

    // session_id
    let sid_len = *body.get(p)? as usize;
    p += 1;
    if body.len() < p + sid_len {
        return None;
    }
    let session_id = body[p..p + sid_len].to_vec();
    p += sid_len;

    // cipher_suites
    let cs_len = read_u16(body, p)? as usize;
    p += 2 + cs_len;

    // compression_methods
    let cm_len = *body.get(p)? as usize;
    p += 1 + cm_len;

    let mut info = ClientHelloInfo {
        random,
        session_id,
        sni: None,
        tls13: false,
        key_shares: Vec::new(),
    };

    // extensions
    if p + 2 <= body.len() {
        let ext_len = read_u16(body, p)? as usize;
        p += 2;
        let end = (p + ext_len).min(body.len());
        while p + 4 <= end {
            let ext_type = read_u16(body, p)?;
            let ext_size = read_u16(body, p + 2)? as usize;
            p += 4;
            if p + ext_size > body.len() {
                break;
            }
            let ext = &body[p..p + ext_size];
            match ext_type {
                0 => info.sni = parse_sni(ext),
                43 => info.tls13 = parse_supported_versions(ext),
                51 => info.key_shares = parse_key_shares(ext),
                _ => {}
            }
            p += ext_size;
        }
    }

    Some(info)
}

fn parse_sni(ext: &[u8]) -> Option<String> {
    // server_name_list(2) || name_type(1) || name_len(2) || name
    if ext.len() < 5 {
        return None;
    }
    let name_type = ext[2];
    let name_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
    if name_type != 0 || ext.len() < 5 + name_len {
        return None;
    }
    String::from_utf8(ext[5..5 + name_len].to_vec()).ok()
}

fn parse_supported_versions(ext: &[u8]) -> bool {
    let len = match ext.first() {
        Some(len) => *len as usize,
        None => return false,
    };
    let mut p = 1;
    while p + 2 <= ext.len() && p - 1 < len {
        let version = u16::from_be_bytes([ext[p], ext[p + 1]]);
        if version == TLS13_VERSION {
            return true;
        }
        p += 2;
    }
    false
}

fn parse_key_shares(ext: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    if ext.len() < 2 {
        return out;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    let mut p = 2;
    let end = (2 + list_len).min(ext.len());
    while p + 4 <= end {
        let group = u16::from_be_bytes([ext[p], ext[p + 1]]);
        let len = u16::from_be_bytes([ext[p + 2], ext[p + 3]]) as usize;
        p += 4;
        if p + len > ext.len() {
            break;
        }
        out.push((group, ext[p..p + len].to_vec()));
        p += len;
    }
    out
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    if buf.len() < at + 2 {
        return None;
    }
    Some(u16::from_be_bytes([buf[at], buf[at + 1]]))
}

/// The 12-byte PROXY protocol v2 signature.
const PROXY_V2_MAGIC: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

/// Build a PROXY protocol header (v1 ASCII or v2 binary).
///
/// Mirrors `proxyproto.HeaderProxyFromAddrs` (called at
/// `reality-ref/tls.go:176-180`) for the addresses an accepted TCP socket can
/// have. The v2 address-length field counts only the address block, so it is
/// 12 bytes for `AF_INET` (4 + 4 + 2 + 2) and 36 for `AF_INET6`; leaf's own
/// VLESS fallback writes the same `0x0C`
/// (`vless/inbound/fallback.rs`).
fn proxy_protocol_header(
    xver: u8,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
) -> Vec<u8> {
    match (src, dst) {
        (std::net::SocketAddr::V4(s), std::net::SocketAddr::V4(d)) => {
            if xver == 1 {
                format!(
                    "PROXY TCP4 {} {} {} {}\r\n",
                    s.ip(),
                    d.ip(),
                    s.port(),
                    d.port()
                )
                .into_bytes()
            } else {
                let mut v = Vec::with_capacity(28);
                v.extend_from_slice(&PROXY_V2_MAGIC);
                v.push(0x21); // version 2, command PROXY
                v.push(0x11); // AF_INET, STREAM
                v.extend_from_slice(&(12u16).to_be_bytes());
                v.extend_from_slice(&s.ip().octets());
                v.extend_from_slice(&d.ip().octets());
                v.extend_from_slice(&s.port().to_be_bytes());
                v.extend_from_slice(&d.port().to_be_bytes());
                v
            }
        }
        (std::net::SocketAddr::V6(s), std::net::SocketAddr::V6(d)) => {
            if xver == 1 {
                format!(
                    "PROXY TCP6 {} {} {} {}\r\n",
                    s.ip(),
                    d.ip(),
                    s.port(),
                    d.port()
                )
                .into_bytes()
            } else {
                let mut v = Vec::with_capacity(52);
                v.extend_from_slice(&PROXY_V2_MAGIC);
                v.push(0x21);
                v.push(0x21); // AF_INET6, STREAM
                v.extend_from_slice(&(36u16).to_be_bytes());
                v.extend_from_slice(&s.ip().octets());
                v.extend_from_slice(&d.ip().octets());
                v.extend_from_slice(&s.port().to_be_bytes());
                v.extend_from_slice(&d.port().to_be_bytes());
                v
            }
        }
        _ => {
            // A mixed v4/v6 pair cannot be expressed in the PROXY header, so
            // the reference's `HeaderProxyFromAddrs` leaves it "unspecified":
            // a v2 LOCAL command with the UNSPEC address family and a zero
            // length (`\x20\x00\x00\x00` after the signature), or the v1
            // `PROXY UNKNOWN` line. `src`/`dst` come from one accepted socket
            // and so always share a family, making this arm unreachable in
            // practice.
            if xver == 1 {
                b"PROXY UNKNOWN\r\n".to_vec()
            } else {
                let mut v = Vec::with_capacity(16);
                v.extend_from_slice(&PROXY_V2_MAGIC);
                v.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
                v
            }
        }
    }
}

/// An authenticated REALITY connection: a `ServerConnection` driven over the
/// underlying async stream.
struct InboundStream<S> {
    conn: ServerConnection,
    stream: S,
}

struct TlsBridge<'a, 'b, S> {
    stream: Pin<&'a mut S>,
    cx: &'a mut Context<'b>,
}

impl<'a, 'b, S: AsyncRead> Read for TlsBridge<'a, 'b, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match self.stream.as_mut().poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<'a, 'b, S: AsyncWrite> Write for TlsBridge<'a, 'b, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.as_mut().poll_write(self.cx, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.stream.as_mut().poll_flush(self.cx) {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> InboundStream<S> {
    fn new(conn: ServerConnection, stream: S) -> Self {
        Self { conn, stream }
    }

    /// Feed the already-read records and drive the handshake to completion.
    async fn handshake(&mut self, records: &[u8]) -> io::Result<()> {
        if !records.is_empty() {
            let mut cursor = std::io::Cursor::new(records);
            self.conn.read_tls(&mut cursor)?;
            self.conn
                .process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS: {e}")))?;
        }
        std::future::poll_fn(|cx| {
            let mut progress = false;
            while self.conn.is_handshaking() {
                while self.conn.wants_write() {
                    let mut bridge = TlsBridge {
                        stream: Pin::new(&mut self.stream),
                        cx,
                    };
                    match self.conn.write_tls(&mut bridge) {
                        Ok(n) if n > 0 => progress = true,
                        Ok(_) => break,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                if self.conn.wants_read() {
                    let mut bridge = TlsBridge {
                        stream: Pin::new(&mut self.stream),
                        cx,
                    };
                    match self.conn.read_tls(&mut bridge) {
                        Ok(0) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed during reality handshake",
                            )))
                        }
                        Ok(_) => {
                            if let Err(e) = self.conn.process_new_packets() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("TLS: {e}"),
                                )));
                            }
                            progress = true;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                if !progress {
                    return Poll::Pending;
                }
                progress = false;
            }
            Poll::Ready(Ok(()))
        })
        .await
    }

    fn pump_read(&mut self, cx: &mut Context<'_>) -> io::Result<usize> {
        if self.conn.wants_read() {
            let mut bridge = TlsBridge {
                stream: Pin::new(&mut self.stream),
                cx,
            };
            match self.conn.read_tls(&mut bridge) {
                Ok(0) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")),
                Ok(n) => {
                    self.conn.process_new_packets().map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("TLS: {e}"))
                    })?;
                    Ok(n)
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(e),
            }
        } else {
            Ok(0)
        }
    }

    fn pump_write(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        while self.conn.wants_write() {
            let mut bridge = TlsBridge {
                stream: Pin::new(&mut self.stream),
                cx,
            };
            match self.conn.write_tls(&mut bridge) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for InboundStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let _ = this.pump_write(cx)?;

        loop {
            let slice = buf.initialize_unfilled();
            match this.conn.reader().read(slice) {
                Ok(n) if n > 0 => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                _ => {
                    if this.conn.wants_read() {
                        let n = this.pump_read(cx)?;
                        if n == 0 {
                            return Poll::Pending;
                        }
                    } else if this.conn.wants_write() {
                        let _ = this.pump_write(cx)?;
                        return Poll::Pending;
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for InboundStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = this.conn.writer().write(buf)?;
        let _ = this.pump_write(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.writer().flush()?;
        if !this.pump_write(cx)? {
            return Poll::Pending;
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.send_close_notify();
        let _ = this.pump_write(cx)?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
