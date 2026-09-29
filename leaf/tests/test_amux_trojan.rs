mod common;

// app(socks) -> (socks)client(chain(amux(tcp)+socks)) -> (chain(amux(tcp)+socks))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-amux",
    feature = "inbound-amux",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_amux_trojan() -> anyhow::Result<()> {
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
                    "address": "127.0.0.1",
                    "port": 3001
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
                "tag": "amux"
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086)
}
