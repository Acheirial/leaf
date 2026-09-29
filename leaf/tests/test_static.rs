mod common;

// app(socks) -> (socks)client(static(socks)) -> (socks)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-static",
))]
#[test]
fn test_static() -> anyhow::Result<()> {
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
                "protocol": "static",
                "settings": {
                    "actors": [
                        "socks_out"
                    ],
                    "method": "rr"
                }
            },
            {
                "protocol": "socks",
                "tag": "socks_out",
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
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1086
            }
        ],
        "outbounds": [
            {
                "protocol": "static",
                "settings": {
                    "actors": [
                        "socks_out"
                    ],
                    "method": "random"
                }
            },
            {
                "protocol": "socks",
                "tag": "socks_out",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001
                }
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
                "port": 3001
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let configs = vec![config1.to_string(), config3.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)?;
    let configs = vec![config2.to_string(), config3.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)
}
