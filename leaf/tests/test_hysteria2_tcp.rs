//! Hysteria2 TCP: an in-process inbound/outbound pair carrying a 2 MiB
//! verified payload, with and without salamander obfuscation.

mod common;

/// Escapes a PEM block so it can be embedded in a JSON string.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "")
        .replace('\n', "\\n")
}

/// The hysteria2 client half: a socks inbound whose default outbound is the
/// hysteria2 server.
fn client_config(socks_port: u16, server_port: u16, obfs: bool) -> String {
    let mut fields = vec![
        format!(r#""server": "127.0.0.1:{}""#, server_port),
        r#""password": "test-password""#.to_string(),
        r#""sni": "localhost""#.to_string(),
        r#""insecure": true"#.to_string(),
        r#""upMbps": 100"#.to_string(),
        r#""downMbps": 100"#.to_string(),
    ];
    if obfs {
        fields.push(r#""obfs": "salamander""#.to_string());
        fields.push(r#""obfsPassword": "obfs-secret""#.to_string());
    }
    format!(
        r#"{{
    "inbounds": [
        {{
            "protocol": "socks",
            "address": "127.0.0.1",
            "port": {socks_port}
        }}
    ],
    "outbounds": [
        {{
            "protocol": "hysteria2",
            "settings": {{ {fields} }}
        }}
    ]
}}"#,
        fields = fields.join(", "),
    )
}

/// The hysteria2 server half: a hysteria2 inbound and a direct outbound.
fn server_config(server_port: u16, cert_pem: &str, key_pem: &str, obfs: bool) -> String {
    let mut fields = vec![
        r#""password": "test-password""#.to_string(),
        format!(r#""certificate": "{}""#, json_escape(cert_pem)),
        format!(r#""certificateKey": "{}""#, json_escape(key_pem)),
    ];
    if obfs {
        fields.push(r#""obfs": "salamander""#.to_string());
        fields.push(r#""obfsPassword": "obfs-secret""#.to_string());
    }
    format!(
        r#"{{
    "inbounds": [
        {{
            "protocol": "hysteria2",
            "address": "127.0.0.1",
            "port": {server_port},
            "settings": {{ {fields} }}
        }}
    ],
    "outbounds": [
        {{
            "protocol": "direct"
        }}
    ]
}}"#,
        fields = fields.join(", "),
    )
}

#[cfg(all(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_hysteria2_tcp() -> anyhow::Result<()> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| anyhow::anyhow!("generate cert failed: {}", e))?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // A plain QUIC pair, then the same pair with salamander obfuscation.
    let configs = vec![
        client_config(5401, 5402, false),
        server_config(5402, &cert_pem, &key_pem, false),
    ];
    common::test_configs_tcp_only(configs.clone(), "127.0.0.1", 5401)?;
    common::test_data_transfering_reliability_on_configs(configs, "127.0.0.1", 5401)?;

    let configs = vec![
        client_config(5403, 5404, true),
        server_config(5404, &cert_pem, &key_pem, true),
    ];
    common::test_configs_tcp_only(configs.clone(), "127.0.0.1", 5403)?;
    common::test_data_transfering_reliability_on_configs(configs, "127.0.0.1", 5403)?;

    Ok(())
}
