use protobuf::Message;

#[test]
fn test_config() {
    let json_str = r#"
    {
        "api": {
            "address": "127.0.0.1",
            "port": 9991
        },
        "log": {
            "level": "trace",
            "output": "leaf.log"
        },
        "dns": {
            "servers": [
                "8.8.8.8",
                "8.8.4.4"
            ],
            "hosts": {
                "example.com": [
                    "192.168.0.1",
                    "192.168.0.2"
                ]
            }
        },
        "inbounds": [
            {
                "tag": "socks_in",
                "address": "127.0.0.1",
                "port": 1086,
                "protocol": "socks"
            }
        ],
        "outbounds": [
            {
                "protocol": "direct",
                "tag": "direct_out"
            }
        ],
        "router": {
            "domainResolve": true,
            "rules": [
                {
                    "ip": [
                        "8.8.8.8",
                        "8.8.4.4"
                    ],
                    "target": "direct_out"
                },
                {
                    "portRange": [
                        "22-22",
                        "1024-65535"
                    ],
                    "target": "direct_out"
                },
                {
                    "domain": [
                        "www.google.com"
                    ],
                    "target": "direct_out"
                },
                {
                    "domainSuffix": [
                        "google.com"
                    ],
                    "target": "direct_out"
                },
                {
                    "domainKeyword": [
                        "google"
                    ],
                    "target": "direct_out"
                },
                {
                    "external": [
                        "site:cn"
                    ],
                    "target": "direct_out"
                },
                {
                    "external": [
                        "mmdb:cn"
                    ],
                    "target": "direct_out"
                }
            ]
        }
    }
    "#;

    assert!(crate::config::json::json_from_string(json_str).is_ok());
}

#[test]
fn test_invalid_config() {
    // Missing protocol
    let json_str = r#"
    {
        "inbounds": [
            {
                "tag": "socks_in",
                "address": "127.0.0.1",
                "port": 1086
            }
        ]
    }
    "#;
    assert!(crate::config::json::json_from_string(json_str).is_err());

    // Invalid port
    let json_str = r#"
    {
        "inbounds": [
            {
                "tag": "socks_in",
                "address": "127.0.0.1",
                "port": 70000,
                "protocol": "socks"
            }
        ]
    }
    "#;
    assert!(crate::config::json::json_from_string(json_str).is_err());
}

#[test]
fn test_dns_config() {
    let json_str = r#"
    {
        "dns": {
            "servers": ["1.1.1.1"],
            "hosts": {
                "google.com": ["127.0.0.1"]
            }
        }
    }
    "#;
    let config = crate::config::json::json_from_string(json_str).unwrap();
    let dns = config.dns.as_ref().unwrap();
    assert_eq!(dns.servers.as_ref().unwrap().len(), 1);
    assert_eq!(
        dns.servers.as_ref().unwrap()[0],
        crate::config::common::DnsServer::Address("1.1.1.1".to_string())
    );
}

#[test]
fn test_dns_server_object_form_and_expect_ips_alias() {
    let json_str = r#"
    {
        "dns": {
            "servers": [
                "1.1.1.1",
                {
                    "address": "8.8.8.8",
                    "port": 53,
                    "expectIPs": ["10.0.0.0/8"],
                    "finalQuery": true,
                    "disableCache": true
                }
            ],
            "disableCache": true,
            "useSystemHosts": true
        }
    }
    "#;

    let config = crate::config::json::json_from_string(json_str).unwrap();
    let dns = config.dns.as_ref().unwrap();
    let servers = dns.servers.as_ref().unwrap();
    assert_eq!(servers.len(), 2);
    // The plain string form is accepted.
    assert_eq!(
        servers[0],
        crate::config::common::DnsServer::Address("1.1.1.1".to_string())
    );
    // The object form is accepted, and Xray's `expectIPs` spelling is an alias
    // for `expectedIPs`.
    match &servers[1] {
        crate::config::common::DnsServer::Server(server) => {
            assert_eq!(server.address, "8.8.8.8");
            assert_eq!(server.port, Some(53));
            assert_eq!(
                server.expected_ips.as_deref(),
                Some(&["10.0.0.0/8".to_string()][..])
            );
            assert_eq!(server.final_query, Some(true));
            assert_eq!(server.disable_cache, Some(true));
        }
        other => panic!("expected an object dns server, got {:?}", other),
    }
    assert_eq!(dns.disable_cache, Some(true));
    assert_eq!(dns.use_system_hosts, Some(true));

    // The mapping carries the new fields into the internal config.
    let internal = crate::config::json::from_string(json_str).unwrap();
    assert_eq!(internal.dns.servers[0].address, "1.1.1.1");
    assert_eq!(internal.dns.servers[1].address, "8.8.8.8");
    assert_eq!(internal.dns.servers[1].port, Some(53));
    assert_eq!(
        internal.dns.servers[1].expected_ips,
        vec!["10.0.0.0/8".to_string()]
    );
    assert_eq!(internal.dns.servers[1].final_query, Some(true));
    assert_eq!(internal.dns.disable_cache, Some(true));
    assert_eq!(internal.dns.use_system_hosts, Some(true));
}

#[test]
fn test_env_config_sets_process_env() {
    let key = "LEAF_JSON_ENV_TEST_KEY";
    std::env::remove_var(key);
    let json_str = r#"
    {
        "env": {
            "LEAF_JSON_ENV_TEST_KEY": "json-env-value"
        }
    }
    "#;
    let _ = crate::config::json::json_from_string(json_str).unwrap();
    assert_eq!(std::env::var(key).unwrap(), "json-env-value");
    std::env::remove_var(key);
}

#[test]
fn test_tls_outbound_ech_config_mapping() {
    let json_str = r#"
    {
        "outbounds": [
            {
                "protocol": "tls",
                "tag": "tls_out",
                "settings": {
                    "serverName": "example.com",
                    "ech": true,
                    "echConfigList": "test-ech-config-list"
                }
            }
        ]
    }
    "#;

    let config = crate::config::json::from_string(json_str).unwrap();
    let outbound =
        crate::config::TlsOutboundSettings::parse_from_bytes(&config.outbounds[0].settings)
            .unwrap();
    assert!(outbound.ech);
    assert_eq!(outbound.ech_config_list, "test-ech-config-list");
}

#[test]
fn test_tls_outbound_ech_config_mapping_aliases() {
    let json_str = r#"
    {
        "outbounds": [
            {
                "protocol": "tls",
                "tag": "tls_out",
                "settings": {
                    "server_name": "example.com",
                    "ech": true,
                    "ech_config_list": "alias-ech-config-list"
                }
            }
        ]
    }
    "#;

    let config = crate::config::json::from_string(json_str).unwrap();
    let outbound =
        crate::config::TlsOutboundSettings::parse_from_bytes(&config.outbounds[0].settings)
            .unwrap();
    assert!(outbound.ech);
    assert_eq!(outbound.ech_config_list, "alias-ech-config-list");
}

#[test]
fn test_tls_inbound_ech_validation() {
    let json_str = r#"
    {
        "inbounds": [
            {
                "tag": "tls_in",
                "protocol": "tls",
                "address": "127.0.0.1",
                "port": 1443,
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem",
                    "echConfig": "only-config"
                }
            }
        ]
    }
    "#;

    assert!(crate::config::json::from_string(json_str).is_err());
}

#[test]
fn test_tls_inbound_ech_unsupported() {
    let json_str = r#"
    {
        "inbounds": [
            {
                "tag": "tls_in",
                "protocol": "tls",
                "address": "127.0.0.1",
                "port": 1443,
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem",
                    "echConfig": "AQID",
                    "echKey": "BAUG"
                }
            }
        ]
    }
    "#;
    let err = crate::config::json::from_string(json_str).unwrap_err();
    assert!(err.to_string().contains("inbound ECH is not supported yet"));
}

#[test]
fn test_tls_outbound_ech_validation() {
    let json_str = r#"
    {
        "outbounds": [
            {
                "protocol": "tls",
                "tag": "tls_out",
                "settings": {
                    "serverName": "example.com",
                    "echConfigList": "   "
                }
            }
        ]
    }
    "#;

    assert!(crate::config::json::from_string(json_str).is_err());
}

#[test]
fn test_tls_ech_fallback_mapping() {
    let json_str = r#"
    {
        "dns": {
            "servers": ["1.1.1.1"]
        },
        "outbounds": [
            {
                "protocol": "tls",
                "tag": "tls_out",
                "settings": {
                    "serverName": "example.com",
                    "ech": true,
                    "echConfigList": "AQI="
                }
            }
        ]
    }
    "#;

    let config = crate::config::json::from_string(json_str).unwrap();
    let outbound =
        crate::config::TlsOutboundSettings::parse_from_bytes(&config.outbounds[0].settings)
            .unwrap();
    assert!(outbound.ech);
    assert_eq!(outbound.ech_config_list, "AQI=");
}

#[test]
fn test_tls_ech_disable_dns_lookup_mapping() {
    let json_str = r#"
    {
        "outbounds": [
            {
                "protocol": "tls",
                "tag": "tls_out",
                "settings": {
                    "ech": true,
                    "echDisableDnsLookup": true,
                    "echConfigList": "AQI="
                }
            }
        ]
    }
    "#;
    let config = crate::config::json::from_string(json_str).unwrap();
    let outbound =
        crate::config::TlsOutboundSettings::parse_from_bytes(&config.outbounds[0].settings)
            .unwrap();
    assert!(outbound.ech);
    assert!(outbound.ech_disable_dns_lookup);
    assert_eq!(outbound.ech_config_list, "AQI=");
}
