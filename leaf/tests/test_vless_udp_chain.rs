mod common;

// app(socks) -> (socks)client(chain(ws+vless)) -> (chain(ws+vless))server(direct) -> echo
//
// VLESS carries UDP inside the stream it opens with `cmd=2`, so unlike a
// chain that ends in a socks payload this one can tunnel a datagram through
// the chained transports.
#[cfg(all(
    feature = "outbound-vless",
    feature = "inbound-vless",
    feature = "outbound-ws",
    feature = "inbound-ws",
    feature = "outbound-chain",
    feature = "inbound-chain",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "config-json",
))]
#[test]
fn test_vless_udp_chain() -> anyhow::Result<()> {
    let config_server = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 5012,
                "settings": {
                    "actors": [
                        "ws",
                        "vless"
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
                "protocol": "vless",
                "tag": "vless",
                "settings": {
                    "users": [
                        {
                            "id": "e6b0a0e0-9e5f-4b0a-9f0f-1a2b3c4d5e6f"
                        }
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let config_client = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 5011
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "ws",
                        "vless"
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
                "protocol": "vless",
                "tag": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 5012,
                    "uuid": "e6b0a0e0-9e5f-4b0a-9f0f-1a2b3c4d5e6f"
                }
            }
        ]
    }
    "#;

    let configs = vec![config_server.to_string(), config_client.to_string()];
    common::test_configs(configs, "127.0.0.1", 5011)
}
