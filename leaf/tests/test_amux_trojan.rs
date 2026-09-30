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
    common::test_configs_tcp_only(configs.clone(), "127.0.0.1", 1086)?;
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086)?;
    // Over TCP only, and not because it is convenient. The payload of this
    // chain is socks, whose UDP needs a sock5 server address of its own, while
    // the transport under it is amux, which carries streams: a chain of the
    // two cannot carry a datagram. The server side cannot even receive one --
    // `app::inbound::manager` gives a chain inbound a datagram half only when
    // its first actor has one, and amux does not. Upstream could run UDP here
    // because the payload was trojan, which frames a datagram inside the
    // stream it opens; the equivalent coverage, a vless payload with `cmd=2`
    // inside a chain, is `test_vless_udp_chain.rs`.
    common::test_tcp_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086)
}
