use reality::{RealityConnectionState, X25519RealityGroup};
#[cfg(feature = "rustls-tls-aws-lc")]
use reality_rustls::crypto::aws_lc_rs::{default_provider, kx_group::MLKEM768};
#[cfg(not(feature = "rustls-tls-aws-lc"))]
use reality_rustls::crypto::ring::default_provider;
#[cfg(feature = "rustls-tls-aws-lc")]
use reality_rustls::crypto::{ActiveKeyExchange, SharedSecret};
use reality_rustls::crypto::{CryptoProvider, SupportedKxGroup};
use reality_rustls::pki_types::ServerName;
use reality_rustls::{ClientConfig, ClientConnection, NamedGroup};
use std::io::{ErrorKind, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Base certificate verifier for the REALITY client.
///
/// The REALITY HMAC check lives in `RealityConnectionState::verify_server_cert`,
/// which returns `Ok` for a matching dummy certificate and only falls through to
/// this verifier otherwise. Signature verification is delegated here (the dummy
/// certificate is authenticated by its HMAC signature field, never by a chain),
/// but `verify_server_cert` always fails: a peer that presents a certificate
/// chaining to a public root is an attack, and Xray aborts on it after the
/// handshake (`Xray-core/.../reality/reality.go:208-299`, `uConn.Verified`).
/// Accepting such a certificate would let a non-REALITY peer complete the
/// handshake and receive application data.
#[derive(Debug)]
struct FailClosedVerifier(Arc<dyn reality_rustls::client::danger::ServerCertVerifier>);

impl reality_rustls::client::danger::ServerCertVerifier for FailClosedVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &reality_rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[reality_rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: reality_rustls::pki_types::UnixTime,
    ) -> Result<reality_rustls::client::danger::ServerCertVerified, reality_rustls::Error> {
        Err(reality_rustls::Error::General(format!(
            "reality: server certificate for {server_name:?} does not carry a matching REALITY HMAC"
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &reality_rustls::pki_types::CertificateDer<'_>,
        dss: &reality_rustls::DigitallySignedStruct,
    ) -> Result<reality_rustls::client::danger::HandshakeSignatureValid, reality_rustls::Error>
    {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &reality_rustls::pki_types::CertificateDer<'_>,
        dss: &reality_rustls::DigitallySignedStruct,
    ) -> Result<reality_rustls::client::danger::HandshakeSignatureValid, reality_rustls::Error>
    {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<reality_rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[reality_rustls::DistinguishedName]> {
        self.0.root_hint_subjects()
    }
}

/// Length of the ML-KEM-768 ciphertext, the first element of an
/// `X25519MLKEM768` *server* key share. (The client sends an encapsulation key
/// of 1184 bytes; the server answers with a 1088-byte ciphertext.)
#[cfg(feature = "rustls-tls-aws-lc")]
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// Length of the X25519 public key, the second element of an `X25519MLKEM768`
/// key share.
#[cfg(feature = "rustls-tls-aws-lc")]
const X25519_PUBLIC_KEY_LEN: usize = 32;

/// An `X25519MLKEM768` key exchange whose X25519 half is REALITY-capable.
///
/// The stock `X25519MLKEM768` group hides its X25519 secret inside the hybrid,
/// so `ActiveKeyExchange::extract_reality_key` cannot reach it and the REALITY
/// `AuthKey` (`X25519(client_ephemeral, server_public_key)`) cannot be derived.
/// This group combines the stock ML-KEM-768 group with [`X25519RealityGroup`]'s
/// X25519 key pair:
///
/// * the wire key share is `ML-KEM-768 encapsulation key (1184) || X25519 public
///   key (32)`, exactly the layout `reality-ref` decodes
///   (`reality-ref/tls.go:216-236`);
/// * the X25519 half backs both the REALITY ECDH and, when the server selects
///   the classical group, the TLS key exchange itself.
///
/// This is what makes leaf's ClientHello look like Xray's (`X25519MLKEM768`
/// first, followed by a plain `X25519`), instead of the ring provider's lone
/// plain `X25519` that REALITY servers reject into the steal path.
#[cfg(feature = "rustls-tls-aws-lc")]
#[derive(Debug)]
struct X25519MlKem768RealityGroup;

#[cfg(feature = "rustls-tls-aws-lc")]
impl SupportedKxGroup for X25519MlKem768RealityGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, reality_rustls::Error> {
        let post_quantum = MLKEM768.start()?;
        let classical = X25519RealityGroup.start()?;
        let mut combined_pub_key =
            Vec::with_capacity(post_quantum.pub_key().len() + classical.pub_key().len());
        combined_pub_key.extend_from_slice(post_quantum.pub_key());
        combined_pub_key.extend_from_slice(classical.pub_key());
        Ok(Box::new(ActiveX25519MlKem768Reality {
            post_quantum,
            classical,
            combined_pub_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(feature = "rustls-tls-aws-lc")]
struct ActiveX25519MlKem768Reality {
    post_quantum: Box<dyn ActiveKeyExchange>,
    classical: Box<dyn ActiveKeyExchange>,
    combined_pub_key: Vec<u8>,
}

#[cfg(feature = "rustls-tls-aws-lc")]
impl ActiveKeyExchange for ActiveX25519MlKem768Reality {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, reality_rustls::Error> {
        if peer_pub_key.len() != MLKEM768_CIPHERTEXT_LEN + X25519_PUBLIC_KEY_LEN {
            return Err(reality_rustls::Error::PeerMisbehaved(
                reality_rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }
        let (post_quantum_share, classical_share) = peer_pub_key.split_at(MLKEM768_CIPHERTEXT_LEN);
        let post_quantum_secret = self.post_quantum.complete(post_quantum_share)?;
        let classical_secret = self.classical.complete(classical_share)?;
        // `X25519MLKEM768` places the post-quantum element first in both the key
        // share and the combined secret (`crypto/aws_lc_rs/pq/hybrid.rs`'s
        // `Layout` with `post_quantum_first = true`).
        let mut secret = Vec::with_capacity(
            post_quantum_secret.secret_bytes().len() + classical_secret.secret_bytes().len(),
        );
        secret.extend_from_slice(post_quantum_secret.secret_bytes());
        secret.extend_from_slice(classical_secret.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    fn extract_reality_key(&self, server_pub_key: &[u8]) -> Option<Vec<u8>> {
        self.classical.extract_reality_key(server_pub_key)
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, reality_rustls::Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// Build the [`CryptoProvider`] for REALITY outbound connections.
///
/// The key exchange groups are ordered to reproduce Xray's ClientHello:
/// `X25519MLKEM768` first, then a plain `X25519`. `reality-ref` rejects a
/// ClientHello without an `X25519MLKEM768` key share before the optional
/// `X25519` one (`reality-ref/tls.go:216-236`), so the stock ring provider's
/// lone plain `X25519` share is routed to the steal path by Xray servers.
///
/// With the `default-aws-lc` feature (leaf's default) the aws-lc-rs provider
/// supplies ML-KEM-768 and the hybrid is offered. The `default-ring` provider
/// has no ML-KEM at all, so REALITY outbound then cannot interoperate with an
/// Xray/REALITY server — it still works leaf-to-leaf, because leaf's inbound
/// deliberately accepts a lone plain `X25519` share (see
/// `proxy::reality::inbound::stream`). That degradation is reported below and
/// documented in `docs/src/protocols/reality.md`.
pub fn create_reality_provider() -> Arc<CryptoProvider> {
    let mut provider = default_provider();
    let mut kx_groups: Vec<&'static dyn SupportedKxGroup> = Vec::new();
    #[cfg(feature = "rustls-tls-aws-lc")]
    kx_groups.push(&X25519MlKem768RealityGroup);
    kx_groups.push(&X25519RealityGroup);
    for group in provider.kx_groups.iter() {
        match group.name() {
            // Replaced above with the REALITY-aware variant.
            NamedGroup::X25519 => {}
            #[cfg(feature = "rustls-tls-aws-lc")]
            NamedGroup::X25519MLKEM768 => {}
            _ => kx_groups.push(*group),
        }
    }

    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "REALITY outbound was built without the `default-aws-lc` feature: the ring \
                 provider cannot offer an X25519MLKEM768 key share, so an Xray/REALITY server \
                 treats this connection as a probe and steals it. Build with `default-aws-lc` \
                 (and without `default-ring`) for Xray interoperability."
            );
        });
    }

    provider.kx_groups = kx_groups;
    Arc::new(provider)
}

/// Build the REALITY client configuration.
///
/// `signature_verifier` supplies the TLS signature-verification primitives
/// (e.g. a `WebPkiServerVerifier`); its chain validation is never consulted,
/// because [`FailClosedVerifier`] rejects every certificate the REALITY HMAC
/// check did not vouch for.
pub fn build_rustls_config(
    provider_arc: Arc<reality_rustls::crypto::CryptoProvider>,
    signature_verifier: Arc<dyn reality_rustls::client::danger::ServerCertVerifier>,
    server_public_key: [u8; 32],
    short_id: [u8; 8],
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let reality_state = Arc::new(RealityConnectionState::new(
        server_public_key,
        short_id,
        Arc::new(FailClosedVerifier(signature_verifier)),
    ));

    let mut config = ClientConfig::builder_with_provider(provider_arc)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(reality_state.clone())
        .with_no_client_auth();

    config.reality_callback = Some(reality_state);
    config.alpn_protocols = vec![b"h2".to_vec().into(), b"http/1.1".to_vec().into()];

    Ok(Arc::new(config))
}

pub struct RealityStream<S> {
    conn: ClientConnection,
    stream: S,
    read_raw: bool,
    shared_read_raw: Option<Arc<std::sync::atomic::AtomicBool>>,
}

struct TlsBridge<'a, 'b, S> {
    stream: Pin<&'a mut S>,
    cx: &'a mut Context<'b>,
    safe_byte_read: bool,
}

impl<'a, 'b, S: AsyncRead> Read for TlsBridge<'a, 'b, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let read_len = if self.safe_byte_read { 1 } else { buf.len() };
        let mut read_buf = ReadBuf::new(&mut buf[..read_len]);
        match self.stream.as_mut().poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                Ok(n)
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<'a, 'b, S: AsyncWrite> Write for TlsBridge<'a, 'b, S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.stream.as_mut().poll_write(self.cx, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.stream.as_mut().poll_flush(self.cx) {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RealityStream<S> {
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        stream: S,
        shared_read_raw: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<Self, reality_rustls::Error> {
        let conn = ClientConnection::new(config, name)?;
        Ok(Self {
            conn,
            stream,
            read_raw: false,
            shared_read_raw,
        })
    }

    pub fn set_read_raw(&mut self, raw: bool) {
        self.read_raw = raw;
    }

    pub fn get_conn_mut(&mut self) -> &mut ClientConnection {
        &mut self.conn
    }

    pub fn get_stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub async fn perform_handshake(&mut self) -> std::io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut progress = false;
            while self.conn.is_handshaking() {
                while self.conn.wants_write() {
                    let mut bridge = TlsBridge {
                        stream: Pin::new(&mut self.stream),
                        cx,
                        safe_byte_read: false,
                    };
                    match self.conn.write_tls(&mut bridge) {
                        Ok(n) if n > 0 => {
                            progress = true;
                        }
                        Ok(_) => break,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                if self.conn.wants_read() {
                    let mut bridge = TlsBridge {
                        stream: Pin::new(&mut self.stream),
                        cx,
                        safe_byte_read: false,
                    };
                    match self.conn.read_tls(&mut bridge) {
                        Ok(0) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "Connection closed during Reality handshake",
                            )));
                        }
                        Ok(_) => {
                            if let Err(e) = self.conn.process_new_packets() {
                                return Poll::Ready(Err(std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    format!("TLS Error: {}", e),
                                )));
                            }
                            progress = true;
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
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

    fn pump_read(&mut self, cx: &mut Context<'_>) -> std::io::Result<usize> {
        if self.conn.wants_read() {
            let mut bridge = TlsBridge {
                stream: Pin::new(&mut self.stream),
                cx,
                safe_byte_read: true,
            };
            match self.conn.read_tls(&mut bridge) {
                Ok(0) => return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "EOF")),
                Ok(n) => {
                    self.conn.process_new_packets().map_err(|e| {
                        std::io::Error::new(ErrorKind::InvalidData, format!("TLS Error: {}", e))
                    })?;
                    return Ok(n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(0),
                Err(e) => return Err(e),
            }
        }
        Ok(0)
    }

    fn pump_write(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        while self.conn.wants_write() {
            let mut bridge = TlsBridge {
                stream: Pin::new(&mut self.stream),
                cx,
                safe_byte_read: false,
            };
            match self.conn.write_tls(&mut bridge) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let mut read_raw = this.read_raw;
        if !read_raw {
            if let Some(shared) = &this.shared_read_raw {
                read_raw = shared.load(std::sync::atomic::Ordering::Relaxed);
                if read_raw {
                    this.read_raw = true; // Cache it
                }
            }
        }

        if read_raw {
            return Pin::new(&mut this.stream).poll_read(cx, buf);
        }

        // Ensure any pending writes are flushed to network
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
                            return Poll::Pending; // Awaits socket read wake
                        }
                    } else if this.conn.wants_write() {
                        let _ = this.pump_write(cx)?;
                        // wait for writes to clear, though want_read was false so it might still be pending
                        return Poll::Pending;
                    } else {
                        // Reached EOF and cleanly terminated TLS?
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let n = this.conn.writer().write(buf)?;
        let _ = this.pump_write(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.writer().flush()?;
        if !this.pump_write(cx)? {
            return Poll::Pending;
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.send_close_notify();
        let _ = this.pump_write(cx)?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
