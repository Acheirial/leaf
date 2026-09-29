mod common;

// app(socks) -> (socks)client(chain(socks+socks)) -> (socks)server1(direct) -> (socks)server2(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-chain",
))]
#[test]
fn test_out_chain_2() -> anyhow::Result<()> {
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
                        "server1",
                        "server2"
                    ]
                }
            },
            {
                "protocol": "socks",
                "tag": "server1",
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
    common::test_configs_tcp_only(configs, "127.0.0.1", 1086)
}
