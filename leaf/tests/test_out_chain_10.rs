mod common;

// app(socks) -> (socks)client(chain(chain(amux(ws)+socks)+socks)) -> (chain(amux(ws)+socks))server1(direct) -> (socks)server2(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-amux",
    feature = "outbound-ws",
    feature = "inbound-amux",
    feature = "inbound-ws",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_out_chain_10() -> anyhow::Result<()> {
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
                "tag": "out",
                "settings": {
                    "actors": [
                        "chain-amux-ws-socks",
                        "socks2"
                    ]
                }
            },
            {
                "protocol": "chain",
                "tag": "chain-amux-ws-socks",
                "settings": {
                    "actors": [
                        "amux",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "amux",
                "tag": "amux",
                "settings": {
                    "actors": [
                        "ws"
                    ],
                    "address": "127.0.0.1",
                    "port": 3001,
                    "maxAccepts": 16,
                    "concurrency": 1
                }
            },
            {
                "protocol": "ws",
                "tag": "ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "socks",
                "tag": "socks"
            },
            {
                "protocol": "socks",
                "tag": "socks2",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "tag": "in",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "amux",
                        "socks"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "amux",
                "tag": "amux",
                "settings": {
                    "actors": [
                        "ws"
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
                "port": 3002
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086)
}
