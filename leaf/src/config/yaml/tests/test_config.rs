const YAML_CONFIG: &str = r#"
log:
  level: trace
  output: leaf.log
dns:
  servers:
    - 8.8.8.8
    - 8.8.4.4
  hosts:
    example.com:
      - 192.168.0.1
      - 192.168.0.2
inbounds:
  - tag: socks_in
    address: 127.0.0.1
    port: 1086
    protocol: socks
outbounds:
  - protocol: direct
    tag: direct_out
router:
  domainResolve: true
  rules:
    - ip:
        - 8.8.8.8
      target: direct_out
"#;

const JSON_CONFIG: &str = r#"
{
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
                    "8.8.8.8"
                ],
                "target": "direct_out"
            }
        ]
    }
}
"#;

const CONF_CONFIG: &str = r#"
[General]
loglevel = info
dns-server = 8.8.8.8

[Proxy]
Direct = direct
"#;

#[cfg(feature = "config-json")]
#[test]
fn test_yaml_matches_json() {
    let yaml = crate::config::yaml::from_string(YAML_CONFIG).expect("yaml config should parse");
    let json = crate::config::json::from_string(JSON_CONFIG).expect("json config should parse");

    assert_eq!(yaml.inbounds.len(), json.inbounds.len());
    assert_eq!(yaml.outbounds.len(), json.outbounds.len());
    assert_eq!(yaml.inbounds.len(), 1);
    assert_eq!(yaml.outbounds.len(), 1);

    for (y, j) in yaml.inbounds.iter().zip(json.inbounds.iter()) {
        assert_eq!(y.protocol, j.protocol);
        assert_eq!(y.tag, j.tag);
        assert_eq!(y.address, j.address);
        assert_eq!(y.port, j.port);
    }
    for (y, j) in yaml.outbounds.iter().zip(json.outbounds.iter()) {
        assert_eq!(y.protocol, j.protocol);
        assert_eq!(y.tag, j.tag);
    }

    assert_eq!(yaml.inbounds[0].protocol, "socks");
    assert_eq!(yaml.inbounds[0].tag, "socks_in");
    assert_eq!(yaml.inbounds[0].address, "127.0.0.1");
    assert_eq!(yaml.outbounds[0].protocol, "direct");
    assert_eq!(yaml.outbounds[0].tag, "direct_out");

    assert_eq!(yaml.dns.servers, json.dns.servers);
    assert!(!yaml.dns.servers.is_empty());
}

#[cfg(all(feature = "config-json", feature = "config-conf"))]
#[test]
fn test_from_string_routes_each_format() {
    // A YAML document is dispatched to the yaml parser.
    let routed = crate::config::from_string(YAML_CONFIG).expect("yaml config should route");
    let direct = crate::config::yaml::from_string(YAML_CONFIG).expect("yaml config should parse");
    assert_eq!(routed.inbounds[0].protocol, "socks");
    assert_eq!(routed, direct);

    // A JSON document is dispatched to the json parser.
    let routed = crate::config::from_string(JSON_CONFIG).expect("json config should route");
    let direct = crate::config::json::from_string(JSON_CONFIG).expect("json config should parse");
    assert_eq!(routed, direct);

    // A clash-style `.conf` body is dispatched to the conf parser, not swallowed
    // by the YAML parser even though `[General]` and `[Proxy]` parse as YAML.
    let routed = crate::config::from_string(CONF_CONFIG).expect("conf config should route");
    let direct = crate::config::conf::from_string(CONF_CONFIG).expect("conf config should parse");
    assert_eq!(routed, direct);
}

#[test]
fn test_malformed_yaml_errors() {
    let malformed = "inbounds:\n  - tag: \"unterminated\n    port: 1086\n";

    let result = crate::config::yaml::from_string(malformed);
    assert!(result.is_err(), "malformed yaml should not parse");
}
