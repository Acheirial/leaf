#![allow(dead_code)]

mod common;

#[cfg(any(feature = "rustls-tls-aws-lc", feature = "rustls-tls-ring"))]
use std::sync::Arc;

// REALITY inbound + outbound, in-process, with the REALITY TLS layer:
// app(socks) -> client(chain(reality+socks)) -> server(chain(reality+socks))(direct) -> echo.
//
// The REALITY server keypair is the RFC 7748 X25519 test vector:
//   privateKey = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
//   publicKey  = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
const REALITY_PRIVATE_KEY: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";
const REALITY_PUBLIC_KEY: &str = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
const REALITY_SHORT_ID: &str = "0123456789abcdef";

#[cfg(all(
    feature = "inbound-reality",
    feature = "outbound-reality",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "inbound-chain",
    feature = "outbound-chain",
    feature = "outbound-direct",
))]
#[test]
fn test_reality_authenticated_round_trip() -> anyhow::Result<()> {
    let client = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{ "protocol": "socks", "address": "127.0.0.1", "port": 5201 }}
        ],
        "outbounds": [
            {{
                "protocol": "chain",
                "settings": {{ "actors": ["reality", "socks"] }}
            }},
            {{
                "protocol": "reality",
                "tag": "reality",
                "settings": {{
                    "serverName": "localhost",
                    "publicKey": "{REALITY_PUBLIC_KEY}",
                    "shortId": "{REALITY_SHORT_ID}"
                }}
            }},
            {{
                "protocol": "socks",
                "tag": "socks",
                "settings": {{ "address": "127.0.0.1", "port": 5202 }}
            }}
        ]
    }}
    "#
    );

    let server = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 5202,
                "settings": {{ "actors": ["reality", "socks"] }}
            }},
            {{
                "protocol": "reality",
                "tag": "reality",
                "settings": {{
                    "dest": "127.0.0.1:1",
                    "serverNames": ["localhost"],
                    "privateKey": "{REALITY_PRIVATE_KEY}",
                    "shortIds": ["{REALITY_SHORT_ID}"],
                    "maxTimeDiffMs": 120000,
                    "show": true
                }}
            }},
            {{ "protocol": "socks", "tag": "socks" }}
        ],
        "outbounds": [ {{ "protocol": "direct" }} ]
    }}
    "#
    );

    let configs = vec![client, server];
    common::test_data_transfering_reliability_on_configs(configs, "127.0.0.1", 5201)
}

// REALITY inbound, in-process: a plain TLS client (stock rustls, custom
// verifier capturing the presented certificate) reaches the REALITY listener,
// is refused authentication and must be relayed verbatim to the configured
// `dest` — observing *that* target's certificate.
#[cfg(all(
    feature = "inbound-reality",
    any(feature = "rustls-tls-aws-lc", feature = "rustls-tls-ring"),
))]
#[test]
fn test_reality_steal_relay() -> anyhow::Result<()> {
    use std::time::Duration;

    use parking_lot::Mutex;
    use rustls::pki_types::ServerName;
    use tokio::io::AsyncReadExt;
    use tokio::runtime::Builder;
    use tokio::time::timeout;
    use tokio_rustls::TlsAcceptor;

    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;

    // The steal target: a genuine TLS server presenting its own certificate.
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["example.com".into()])
            .map_err(|e| anyhow::anyhow!("generate cert failed: {}", e))?;
    let target_cert: Vec<u8> = cert.der().to_vec();

    let (target_shutdown, _target_addr) = rt.block_on(async {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:5209")
            .await
            .map_err(|e| anyhow::anyhow!("bind target failed: {}", e))?;
        let addr = listener
            .local_addr()
            .map_err(|e| anyhow::anyhow!("target local addr failed: {}", e))?;

        let config = server_config(cert.der(), &key_pair.serialize_der())?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            if let Ok(mut tls) = acceptor.accept(stream).await {
                                let mut buf = [0u8; 1024];
                                // Keep the session open until the peer closes it.
                                while let Ok(n) = tls.read(&mut buf).await {
                                    if n == 0 { break }
                                }
                            }
                        });
                    }
                }
            }
        });
        Ok::<_, anyhow::Error>((tx, addr))
    })?;

    // leaf: a REALITY inbound that steals everything it cannot authenticate.
    let reality_server = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{
                "protocol": "reality",
                "address": "127.0.0.1",
                "port": 5208,
                "settings": {{
                    "dest": "127.0.0.1:5209",
                    "serverNames": ["example.com"],
                    "privateKey": "{REALITY_PRIVATE_KEY}",
                    "shortIds": ["{REALITY_SHORT_ID}"],
                    "show": true
                }}
            }}
        ],
        "outbounds": [ {{ "protocol": "direct" }} ]
    }}
    "#
    );
    let leaf_ids = common::run_leaf_instances(&rt, vec![reality_server])?;

    // A plain TLS client that records whatever certificate it is shown.
    let seen = Arc::new(Mutex::new(None::<Vec<u8>>));
    let client_config = Arc::new(client_config(seen.clone())?);

    let result = rt.block_on(async {
        use tokio::net::TcpStream;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let stream = TcpStream::connect("127.0.0.1:5208")
            .await
            .map_err(|e| anyhow::anyhow!("connect reality failed: {}", e))?;
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let name = ServerName::try_from("example.com")
            .map_err(|e| anyhow::anyhow!("server name failed: {}", e))?
            .to_owned();
        let tls = timeout(Duration::from_secs(5), connector.connect(name, stream))
            .await
            .map_err(|e| anyhow::anyhow!("plain tls connect timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("plain tls connect failed: {}", e))?;
        drop(tls);
        Ok::<_, anyhow::Error>(())
    });

    for id in leaf_ids {
        leaf::shutdown(id);
    }
    let _ = target_shutdown.send(());

    result?;

    let observed = seen.lock().clone();
    match observed {
        Some(cert) if cert == target_cert => Ok(()),
        Some(cert) => Err(anyhow::anyhow!(
            "reality steal path presented the wrong certificate: {} bytes, expected {} bytes",
            cert.len(),
            target_cert.len()
        )),
        None => Err(anyhow::anyhow!(
            "reality steal path completed without presenting any certificate"
        )),
    }
}

#[cfg(any(feature = "rustls-tls-aws-lc", feature = "rustls-tls-ring"))]
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "rustls-tls-aws-lc")]
    {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }
    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    {
        Arc::new(rustls::crypto::ring::default_provider())
    }
}

#[cfg(any(feature = "rustls-tls-aws-lc", feature = "rustls-tls-ring"))]
fn server_config(
    cert: &rustls::pki_types::CertificateDer<'static>,
    key: &[u8],
) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
    rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("server versions failed: {}", e))?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .map_err(|e| anyhow::anyhow!("server cert failed: {}", e))
}

#[cfg(any(feature = "rustls-tls-aws-lc", feature = "rustls-tls-ring"))]
#[derive(Debug)]
struct CapturingVerifier {
    seen: Arc<parking_lot::Mutex<Option<Vec<u8>>>>,
    schemes: Vec<rustls::SignatureScheme>,
}

#[cfg(any(feature = "rustls-tls-aws-lc", feature = "rustls-tls-ring"))]
impl rustls::client::danger::ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.seen.lock() = Some(end_entity.as_ref().to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(any(feature = "rustls-tls-aws-lc", feature = "rustls-tls-ring"))]
fn client_config(
    seen: Arc<parking_lot::Mutex<Option<Vec<u8>>>>,
) -> anyhow::Result<rustls::ClientConfig> {
    let provider = provider();
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let verifier = Arc::new(CapturingVerifier { seen, schemes });
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("client versions failed: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}
