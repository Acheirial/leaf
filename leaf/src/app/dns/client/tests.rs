#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{
        DomainRule, DnsClient, IpMatcher, IpOption, NsClient, QueryStrategy, Resolver,
    };

    fn dns_server(address: &str) -> crate::config::DnsServer {
        let mut server = crate::config::DnsServer::new();
        server.address = address.to_string();
        server
    }

    fn new_client(servers: Vec<&str>) -> DnsClient {
        new_client_with(servers, false, false)
    }

    fn new_client_with(
        servers: Vec<&str>,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
    ) -> DnsClient {
        let mut dns = crate::config::Dns::new();
        dns.servers = servers.into_iter().map(dns_server).collect();
        dns.disable_fallback = if disable_fallback { Some(true) } else { None };
        dns.disable_fallback_if_match = if disable_fallback_if_match {
            Some(true)
        } else {
            None
        };
        DnsClient::new(&protobuf::MessageField::some(dns)).unwrap()
    }

    fn load_servers(dns: &crate::config::Dns) -> Vec<NsClient> {
        DnsClient::load_servers(dns, "dnsclient").unwrap()
    }

    fn make_ns(
        addr: &str,
        domains: &[&str],
        skip_fallback: bool,
        final_query: bool,
    ) -> NsClient {
        NsClient {
            resolver: DnsClient::parse_server(addr).unwrap(),
            domains: domains
                .iter()
                .map(|d| DomainRule::parse(d).unwrap())
                .collect(),
            expected: None,
            unexpected: None,
            act_prior: false,
            act_unprior: false,
            strategy: None,
            tag: "dnsclient".to_owned(),
            timeout: Duration::from_secs(4),
            disable_cache: false,
            serve_stale: false,
            serve_expired_ttl: 0,
            final_query,
            skip_fallback,
            policy_key: addr.to_owned(),
        }
    }

    fn names(clients: &[&NsClient]) -> Vec<String> {
        clients.iter().map(|c| c.display_name()).collect()
    }

    // -------------------------------------------------------------- grammar

    #[test]
    fn parse_server_supports_udp_host_and_port() {
        match DnsClient::parse_server("1.1.1.1").unwrap() {
            Resolver::Server(addr, false) => assert_eq!(
                addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
            ),
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("1.1.1.1:5353").unwrap() {
            Resolver::Server(addr, false) => assert_eq!(addr.port(), 5353),
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("udp://8.8.8.8:53").unwrap() {
            Resolver::Server(addr, false) => assert_eq!(
                addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
            ),
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("direct:1.1.1.1").unwrap() {
            Resolver::Server(_, true) => {}
            other => panic!("unexpected resolver {:?}", other),
        }
    }

    #[test]
    fn parse_server_supports_system_aliases() {
        match DnsClient::parse_server("localhost").unwrap() {
            Resolver::System(false) => {}
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("system").unwrap() {
            Resolver::System(false) => {}
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("direct:system").unwrap() {
            Resolver::System(true) => {}
            other => panic!("unexpected resolver {:?}", other),
        }
    }

    #[test]
    fn parse_server_supports_fakedns() {
        match DnsClient::parse_server("fakedns").unwrap() {
            Resolver::FakeDns => {}
            other => panic!("unexpected resolver {:?}", other),
        }
    }

    #[test]
    fn parse_server_supports_tcp_forms() {
        match DnsClient::parse_server("tcp://9.9.9.9").unwrap() {
            Resolver::Tcp(addr, false) => assert_eq!(addr.port(), 53),
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("tcp+local://9.9.9.9:5300").unwrap() {
            Resolver::Tcp(addr, true) => assert_eq!(addr.port(), 5300),
            other => panic!("unexpected resolver {:?}", other),
        }
    }

    #[cfg(feature = "dns-tls")]
    #[test]
    fn parse_server_supports_https_forms() {
        match DnsClient::parse_server("https://dns.example.com/dns-query").unwrap() {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "dns.example.com");
                assert_eq!(doh.path, "/dns-query");
                assert_eq!(doh.port, 443);
                assert!(!doh.is_h2c);
                assert!(!doh.is_direct);
            }
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("https+local://dns.example.com").unwrap() {
            Resolver::DoH(doh) => {
                assert!(doh.is_direct);
                assert!(!doh.is_h2c);
                assert_eq!(doh.path, "/dns-query");
            }
            other => panic!("unexpected resolver {:?}", other),
        }
    }

    #[test]
    fn parse_server_supports_h2c_forms() {
        match DnsClient::parse_server("h2c://dns.example.com/dns").unwrap() {
            Resolver::DoH(doh) => {
                assert!(doh.is_h2c);
                assert!(!doh.is_direct);
                assert_eq!(doh.port, 80);
                assert_eq!(doh.path, "/dns");
            }
            other => panic!("unexpected resolver {:?}", other),
        }
        match DnsClient::parse_server("h2c+local://dns.example.com:8080").unwrap() {
            Resolver::DoH(doh) => {
                assert!(doh.is_h2c);
                assert!(doh.is_direct);
                assert_eq!(doh.port, 8080);
            }
            other => panic!("unexpected resolver {:?}", other),
        }
    }

    #[cfg(feature = "dns-quic")]
    #[test]
    fn parse_server_supports_quic_local() {
        match DnsClient::parse_server("quic+local://dns.example.com").unwrap() {
            Resolver::Quic(quic) => {
                assert_eq!(quic.host, "dns.example.com");
                assert_eq!(quic.port, 853);
            }
            other => panic!("unexpected resolver {:?}", other),
        }
    }

    #[test]
    fn parse_server_rejects_unknown_scheme() {
        assert!(DnsClient::parse_server("tls://1.1.1.1").is_err());
    }

    // ---------------------------------------------------------- load/servers

    #[test]
    fn load_servers_supports_legacy_and_doh_with_ip() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![
            dns_server("1.1.1.1"),
            dns_server("direct:system"),
            dns_server("doh:example.com@9.9.9.9"),
            dns_server("direct:doh:example.com@8.8.8.8"),
            dns_server("doh:example.net"),
        ];
        let servers = load_servers(&dns);

        match &servers[0].resolver {
            Resolver::Server(addr, false) => assert_eq!(
                *addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
            ),
            _ => panic!("unexpected resolver"),
        }
        match &servers[1].resolver {
            Resolver::System(true) => {}
            _ => panic!("unexpected resolver"),
        }
        match &servers[2].resolver {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.com");
                assert_eq!(doh.bootstrap_ip, Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
                assert!(!doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
        match &servers[3].resolver {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.com");
                assert_eq!(doh.bootstrap_ip, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
                assert!(doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
        match &servers[4].resolver {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.net");
                assert_eq!(doh.bootstrap_ip, None);
                assert!(!doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
    }

    #[test]
    fn load_servers_ignores_invalid_values_if_any_valid_server_exists() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![
            dns_server("tls://1.1.1.1"),
            dns_server("https://"),
            dns_server("not-an-ip"),
            dns_server("1.1.1.1"),
        ];
        let servers = load_servers(&dns);
        assert_eq!(servers.len(), 1);
        match &servers[0].resolver {
            Resolver::Server(addr, false) => assert_eq!(
                *addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
            ),
            _ => panic!("unexpected resolver"),
        }
    }

    #[test]
    fn load_servers_rejects_when_all_servers_invalid() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![
            dns_server("tls://1.1.1.1"),
            dns_server("https://"),
            dns_server("not-an-ip"),
        ];
        let err = DnsClient::load_servers(&dns, "dnsclient").unwrap_err();
        assert!(err.to_string().contains("no dns servers"));
    }

    #[test]
    fn load_servers_honors_dns_server_port_override() {
        let mut dns = crate::config::Dns::new();
        let mut server = dns_server("1.1.1.1");
        server.port = Some(5300);
        dns.servers = vec![server];
        let servers = load_servers(&dns);
        match &servers[0].resolver {
            Resolver::Server(addr, false) => assert_eq!(addr.port(), 5300),
            _ => panic!("unexpected resolver"),
        }
    }

    fn collect_server_strings(client: &DnsClient, is_direct: bool) -> Vec<String> {
        client
            .collect_servers(is_direct)
            .into_iter()
            .map(|server| server.to_string())
            .collect()
    }

    #[test]
    fn collect_servers_includes_direct_doh_for_direct_lookup() {
        let client = new_client(vec![
            "1.1.1.1",
            "doh:normal.example",
            "direct:doh:direct.example@8.8.8.8",
        ]);
        let selected = collect_server_strings(&client, true);
        assert_eq!(selected, vec!["direct:doh:direct.example@8.8.8.8"]);
    }

    #[test]
    fn collect_servers_fallback_to_normal_keeps_non_direct_doh() {
        let client = new_client(vec!["doh:normal.example", "1.1.1.1", "system"]);
        let selected = collect_server_strings(&client, true);
        assert_eq!(
            selected,
            vec![
                "doh:normal.example".to_string(),
                "1.1.1.1:53".to_string(),
                "system".to_string()
            ]
        );
    }

    // ------------------------------------------------------ response parsing

    #[test]
    fn parse_doh_http_body_supports_content_length() {
        let body = b"\x01\x02\x03\x04";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut raw = response.into_bytes();
        raw.extend_from_slice(body);

        let parsed = DnsClient::parse_doh_http_body(&raw).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn parse_doh_http_body_supports_chunked() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nABCD\r\n2\r\nEF\r\n0\r\n\r\n";
        let parsed = DnsClient::parse_doh_http_body(response).unwrap();
        assert_eq!(parsed, b"ABCDEF");
    }

    #[test]
    fn parse_doh_http_body_rejects_non_200() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nbad".to_vec();
        let err = DnsClient::parse_doh_http_body(&response).unwrap_err();
        assert!(err
            .to_string()
            .contains("doh server returned http status 503"));
    }

    // ---------------------------------------------------------- domain rules

    #[test]
    fn domain_rules_match_like_xray() {
        assert!(DomainRule::parse("full:example.com")
            .unwrap()
            .matches("example.com"));
        assert!(!DomainRule::parse("full:example.com")
            .unwrap()
            .matches("www.example.com"));
        assert!(DomainRule::parse("domain:example.com")
            .unwrap()
            .matches("www.example.com"));
        assert!(DomainRule::parse("domain:example.com")
            .unwrap()
            .matches("example.com"));
        assert!(!DomainRule::parse("domain:example.com")
            .unwrap()
            .matches("notexample.com"));
        assert!(DomainRule::parse("keyword:ample")
            .unwrap()
            .matches("example.com"));
        // Bare rules are `Domain_Substr`.
        assert!(DomainRule::parse("ample").unwrap().matches("example.com"));
        assert!(DomainRule::Dotless.matches("myhost"));
        assert!(!DomainRule::Dotless.matches("myhost.example.com"));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn regexp_domain_rule_matches() {
        let rule = DomainRule::parse("regexp:^ads\\.").unwrap();
        assert!(rule.matches("ads.example.com"));
        assert!(!rule.matches("example.com"));
    }

    // -------------------------------------------------------------- ip rules

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ip_matcher_cidr_filters() {
        let (matcher, all) = IpMatcher::parse(&["192.168.0.0/16".to_string()]).unwrap();
        assert!(!all);
        let matcher = matcher.unwrap();
        let (matched, unmatched) = matcher.filter(&[ip("192.168.1.1"), ip("1.1.1.1")]);
        assert_eq!(matched, vec![ip("192.168.1.1")]);
        assert_eq!(unmatched, vec![ip("1.1.1.1")]);
    }

    #[test]
    fn ip_matcher_star_is_not_a_rule() {
        let (matcher, all) = IpMatcher::parse(&["*".to_string()]).unwrap();
        assert!(all);
        assert!(matcher.is_none());
    }

    // ------------------------------------------------------- selection engine

    #[test]
    fn sort_clients_prefers_domain_match_then_fallback() {
        let client = new_client(vec!["1.1.1.1", "8.8.8.8"]);
        let a = make_ns("1.1.1.1", &["domain:example.com"], false, false);
        let b = make_ns("8.8.8.8", &[], false, false);
        let candidates = vec![&a, &b];
        let ordered = client.sort_clients("www.example.com", &candidates);
        assert_eq!(names(&ordered), vec!["1.1.1.1:53", "8.8.8.8:53"]);
    }

    #[test]
    fn sort_clients_skips_fallback_tagged_servers() {
        let client = new_client(vec!["1.1.1.1", "8.8.8.8"]);
        let a = make_ns("1.1.1.1", &[], true, false);
        let b = make_ns("8.8.8.8", &[], false, false);
        let candidates = vec![&a, &b];
        let ordered = client.sort_clients("example.org", &candidates);
        assert_eq!(names(&ordered), vec!["8.8.8.8:53"]);
    }

    #[test]
    fn sort_clients_truncates_at_final_query() {
        let client = new_client(vec!["1.1.1.1", "8.8.8.8"]);
        let a = make_ns("1.1.1.1", &["domain:example.com"], false, true);
        let b = make_ns("8.8.8.8", &[], false, false);
        let candidates = vec![&a, &b];
        let ordered = client.sort_clients("www.example.com", &candidates);
        assert_eq!(names(&ordered), vec!["1.1.1.1:53"]);
    }

    #[test]
    fn sort_clients_respects_disable_fallback_if_match() {
        let client = new_client_with(vec!["1.1.1.1", "8.8.8.8"], false, true);
        let a = make_ns("1.1.1.1", &["domain:example.com"], false, false);
        let b = make_ns("8.8.8.8", &[], false, false);
        let candidates = vec![&a, &b];
        let ordered = client.sort_clients("www.example.com", &candidates);
        assert_eq!(names(&ordered), vec!["1.1.1.1:53"]);
    }

    #[test]
    fn sort_clients_disable_fallback_returns_first_when_nothing_matches() {
        let client = new_client_with(vec!["1.1.1.1", "8.8.8.8"], true, false);
        let a = make_ns("1.1.1.1", &[], false, false);
        let b = make_ns("8.8.8.8", &[], false, false);
        let candidates = vec![&a, &b];
        let ordered = client.sort_clients("example.org", &candidates);
        assert_eq!(names(&ordered), vec!["1.1.1.1:53"]);
    }

    #[test]
    fn sort_clients_gives_local_server_the_local_tlds() {
        let client = new_client(vec!["1.1.1.1", "localhost"]);
        let remote = make_ns("1.1.1.1", &[], false, false);
        let local = make_ns("localhost", &[], false, false);
        let candidates = vec![&remote, &local];
        let ordered = client.sort_clients("myhost", &candidates);
        assert_eq!(names(&ordered), vec!["system", "1.1.1.1:53"]);
    }

    #[test]
    fn make_groups_merges_only_adjacent_equal_policies() {
        let a = make_ns("1.1.1.1", &[], false, false);
        let b = make_ns("1.1.1.1", &[], false, false);
        let c = make_ns("8.8.8.8", &[], false, false);
        let clients = vec![&a, &b, &c];
        let (groups, group_of) = DnsClient::make_groups(&clients);
        assert_eq!(groups.len(), 2);
        assert_eq!((groups[0].start, groups[0].end), (0, 1));
        assert_eq!((groups[1].start, groups[1].end), (2, 2));
        assert_eq!(group_of, vec![0, 0, 1]);
    }

    #[test]
    fn ns_client_applies_query_strategy_override() {
        let mut ns = make_ns("1.1.1.1", &[], false, false);
        let base = IpOption::new(true, true);
        assert_eq!(ns.ip_option(base), base);
        ns.strategy = Some(QueryStrategy::UseIpv4);
        assert_eq!(ns.ip_option(base), IpOption::new(true, false));
        ns.strategy = Some(QueryStrategy::UseIpv6);
        assert_eq!(ns.ip_option(base), IpOption::new(false, true));
    }
}
