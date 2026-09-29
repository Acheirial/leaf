mod common;

// app(socks) -> (socks)client(failover(socks)) -> (socks)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-failover",
))]
#[test]
fn test_failover() -> anyhow::Result<()> {
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
                "protocol": "failover",
                "settings": {
                    "actors": [
                        "socks_out"
                    ]
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)
}
