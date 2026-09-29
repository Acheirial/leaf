mod common;

// app(socks) -> (socks)client(vless) -> (vless)server(direct) -> echo
#[cfg(all(
    feature = "outbound-vless",
    feature = "inbound-vless",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "config-json",
))]
#[test]
fn test_vless() -> anyhow::Result<()> {
    let config_server = r#"
    {
        "inbounds": [
            {
                "protocol": "vless",
                "address": "127.0.0.1",
                "port": 5002,
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
                "port": 5001
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 5002,
                    "uuid": "e6b0a0e0-9e5f-4b0a-9f0f-1a2b3c4d5e6f"
                }
            }
        ]
    }
    "#;

    let configs = vec![config_server.to_string(), config_client.to_string()];

    // TCP and UDP round trips.
    common::test_configs(configs.clone(), "127.0.0.1", 5001)?;

    // A 2 MiB transfer, verified by SHA-256 on both ends.
    common::test_data_transfering_reliability_on_configs(configs, "127.0.0.1", 5001)
}
