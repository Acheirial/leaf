mod common;

// app(socks) -> (socks)client(chain(ws+socks)) -> (chain(ws+socks))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "inbound-ws",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_ws_trojan() -> anyhow::Result<()> {
    let config1 = r#"
    {
        "log": {
            "level": "trace"
        },
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
                        "ws",
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
                "protocol": "socks",
                "tag": "socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "log": {
            "level": "trace"
        },
        "inbounds": [
            {
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "ws",
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
    common::test_configs_tcp_only(configs, "127.0.0.1", 1086)
}
