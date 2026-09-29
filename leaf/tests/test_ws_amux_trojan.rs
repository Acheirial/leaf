mod common;

// app(socks) -> (socks)client(chain(amux(ws)+socks)) -> (chain(amux(ws)+socks))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-amux",
    feature = "inbound-ws",
    feature = "inbound-amux",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_ws_amux_trojan() -> anyhow::Result<()> {
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
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
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
                "protocol": "amux",
                "tag": "amux",
                "settings": {
                    "actors": [
                        "ws"
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)
}
