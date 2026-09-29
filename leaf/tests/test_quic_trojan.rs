mod common;

// app(socks) -> (socks)client(chain(quic+socks)) -> (chain(quic+socks))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-quic",
    feature = "inbound-quic",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_quic_trojan() -> anyhow::Result<()> {
    let config1 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1086
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "quic",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "serverName": "localhost",
                    "certificate": "cert.der",
                    "alpn": [
                        "http/1.1",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "socks",
                "tag": "socks"
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "tag": "quic-in",
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "quic",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "certificate": "cert.der",
                    "certificateKey": "key.der",
                    "alpn": [
                        "http/1.1",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "socks",
                "tag": "socks"
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let config3 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1087
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "quic",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "serverName": "localhost",
                    "certificate": "cert.pem"
                }
            },
            {
                "protocol": "socks",
                "tag": "socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002
                }
            }
        ]
    }
    "#;

    let config4 = r#"
    {
        "inbounds": [
            {
                "tag": "quic-in",
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3002,
                "settings": {
                    "actors": [
                        "quic",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem"
                }
            },
            {
                "protocol": "socks",
                "tag": "socks"
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    std::env::set_var("TCP_DOWNLINK_TIMEOUT", "3");
    std::env::set_var("TCP_UPLINK_TIMEOUT", "3");

    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| anyhow::anyhow!("generate cert failed: {}", e))?;
    std::fs::write(&path.join("key.der"), &key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("write key.der failed: {}", e))?;
    std::fs::write(&path.join("cert.der"), &cert.der().to_vec())
        .map_err(|e| anyhow::anyhow!("write cert.der failed: {}", e))?;
    std::fs::write(&path.join("key.pem"), &key_pair.serialize_pem())
        .map_err(|e| anyhow::anyhow!("write key.pem failed: {}", e))?;
    std::fs::write(&path.join("cert.pem"), &cert.pem())
        .map_err(|e| anyhow::anyhow!("write cert.pem failed: {}", e))?;

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086)?;

    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1087)?;

    let config5 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1089
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "quic",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3004,
                    "serverName": "localhost",
                    "certificate": "cert.pem",
                    "alpn": [
                        "http/1.1"
                    ]
                }
            },
            {
                "protocol": "socks",
                "tag": "socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3004
                }
            }
        ]
    }
    "#;
    let config6 = r#"
    {
        "inbounds": [
            {
                "tag": "quic-in",
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3004,
                "settings": {
                    "actors": [
                        "quic",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem",
                    "alpn": [
                        "http/1.1"
                    ]
                }
            },
            {
                "protocol": "socks",
                "tag": "socks"
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;
    let configs = vec![config5.to_string(), config6.to_string()];
    common::test_configs(configs, "127.0.0.1", 1089)
}
