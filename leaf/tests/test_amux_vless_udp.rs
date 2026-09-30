mod common;

// app(socks) -> (socks)client(chain(amux+vless)) -> (chain(amux+vless))server(direct) -> echo
//
// The shape of the amux chain over a socks payload, which cannot carry a
// datagram, over a payload that can: VLESS tunnels UDP inside the stream it
// opens with `cmd=2`, and amux carries that stream. This is the "UDP over a
// chain, over a mux" case, and the only one of the three the amux transport
// has.
#[cfg(all(
    feature = "outbound-vless",
    feature = "inbound-vless",
    feature = "outbound-amux",
    feature = "inbound-amux",
    feature = "outbound-chain",
    feature = "inbound-chain",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "config-json",
))]
#[test]
fn test_amux_vless_udp() -> anyhow::Result<()> {
    let uuid = "e6b0a0e0-9e5f-4b0a-9f0f-1a2b3c4d5e6f";

    let config1 = format!(
        r#"
    {{
        "inbounds": [
            {{
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1091
            }}
        ],
        "outbounds": [
            {{
                "protocol": "chain",
                "settings": {{
                    "actors": [
                        "amux",
                        "vless"
                    ]
                }}
            }},
            {{
                "protocol": "amux",
                "tag": "amux",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": 3101
                }}
            }},
            {{
                "protocol": "vless",
                "tag": "vless",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": 3101,
                    "uuid": "{uuid}"
                }}
            }}
        ]
    }}
    "#
    );

    let config2 = format!(
        r#"
    {{
        "inbounds": [
            {{
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3101,
                "settings": {{
                    "actors": [
                        "amux",
                        "vless"
                    ]
                }}
            }},
            {{
                "protocol": "amux",
                "tag": "amux"
            }},
            {{
                "protocol": "vless",
                "tag": "vless",
                "settings": {{
                    "users": [
                        {{
                            "id": "{uuid}"
                        }}
                    ]
                }}
            }}
        ],
        "outbounds": [
            {{
                "protocol": "direct"
            }}
        ]
    }}
    "#
    );

    let configs = vec![config1, config2];
    common::test_configs(configs, "127.0.0.1", 1091)
}
