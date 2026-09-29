mod common;

// app(socks) -> (socks)client(chain(ws+socks+socks+ws+socks)) -> (chain(ws+socks))server1(direct) -> (socks)server2(direct) -> (chain(ws+socks))server3(direct) -> echo
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
fn test_out_chain_8() -> anyhow::Result<()> {
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
                "tag": "chain-server1-server2",
                "settings": {
                    "actors": [
                        "server1-ws",
                        "server1-socks",
                        "server2",
                        "server3-ws",
                        "server3-socks"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "server1-ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "socks",
                "tag": "server1-socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001
                }
            },
            {
                "protocol": "socks",
                "tag": "server2",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002
                }
            },
            {
                "protocol": "ws",
                "tag": "server3-ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "socks",
                "tag": "server3-socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3003
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
                "tag": "server1",
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

    let config4 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "tag": "server1",
                "address": "127.0.0.1",
                "port": 3003,
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
        config4.to_string(),
    ];
    common::test_configs_tcp_only(configs, "127.0.0.1", 1086)
}
