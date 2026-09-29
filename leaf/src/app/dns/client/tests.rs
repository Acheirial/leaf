#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use hickory_proto::rr::{record_type::RecordType, Name};

    use crate::app::fake_dns::{FakeDns, FakeDnsMode};

    use super::{DomainRule, DnsClient, IpMatcher, IpOption, NsClient, QueryStrategy, Resolver};

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

    #[test]
    fn load_servers_keeps_fakedns_entry() {
        // The `fakedns` entry is accepted like any other server; if no engine
        // has been registered the query reports a named error and falls
        // through, so `["fakedns", "<real server>"]` still resolves.
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![dns_server("fakedns"), dns_server("1.1.1.1")];
        let servers = load_servers(&dns);
        assert_eq!(servers.len(), 2);
        assert!(matches!(servers[0].resolver, Resolver::FakeDns));
        match &servers[1].resolver {
            Resolver::Server(addr, false) => assert_eq!(
                *addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
            ),
            _ => panic!("unexpected resolver"),
        }
    }

    #[test]
    fn load_servers_accepts_fakedns_as_the_only_server() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![dns_server("fakedns")];
        let servers = load_servers(&dns);
        assert_eq!(servers.len(), 1);
        assert!(matches!(servers[0].resolver, Resolver::FakeDns));
    }

    #[test]
    fn load_servers_rejects_per_server_cache_options() {
        // The cache is global, so per-server disableCache/serveStale/
        // serveExpiredTTL are rejected rather than silently ignored.
        let mut dns = crate::config::Dns::new();
        let mut cached = dns_server("1.1.1.1");
        cached.disable_cache = Some(true);
        dns.servers = vec![cached, dns_server("8.8.8.8")];
        let servers = load_servers(&dns);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].to_string(), "8.8.8.8:53");
    }

    #[test]
    fn fakedns_entry_is_not_a_direct_server() {
        // A `fakedns` entry must not be miscategorised as a direct transport:
        // it is neither collected for `direct_lookup` nor allowed to shadow a
        // real `direct:` server there.
        let client = new_client(vec!["fakedns", "direct:1.1.1.1"]);
        assert_eq!(
            collect_server_strings(&client, true),
            vec!["direct:1.1.1.1:53".to_string()]
        );
        assert_eq!(
            collect_server_strings(&client, false),
            vec!["fakedns".to_string()]
        );
    }

    #[tokio::test]
    async fn fakedns_entry_reports_a_named_error_without_an_engine() {
        // With no engine registered the entry still loads (the engine is
        // registered after the client is built) and answers every query with
        // the named error the fallback path relies on.
        let client = new_client(vec!["fakedns"]);
        assert!(matches!(client.servers[0].resolver, Resolver::FakeDns));
        let name = Name::from_str("fake.example.").unwrap();
        let err = client
            .query_record_type(
                false,
                &name,
                "fake.example",
                RecordType::A,
                IpOption::new(true, true),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no fake-DNS engine"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn fakedns_entry_is_answered_by_the_registered_engine() {
        let mut client = new_client(vec!["fakedns", "1.1.1.1"]);
        // Accepted, and not miscategorised as a direct server.
        let fake = client
            .servers
            .iter()
            .find(|s| matches!(s.resolver, Resolver::FakeDns))
            .expect("the fakedns entry must be kept");
        assert!(!fake.is_direct());
        assert_eq!(client.servers.len(), 2);

        client.replace_fakedns(Arc::new(FakeDns::new(FakeDnsMode::Exclude, vec![])));

        let name = Name::from_str("fake.example.").unwrap();
        let entry = client
            .query_record_type(
                false,
                &name,
                "fake.example",
                RecordType::A,
                IpOption::new(true, true),
            )
            .await
            .unwrap();
        let ip = match entry.ips.as_slice() {
            [IpAddr::V4(ip)] => *ip,
            other => panic!("expected one fake IPv4, got {:?}", other),
        };
        assert_eq!(&ip.octets()[..2], &[198, 18]);
        // The engine and the returned mapping agree.
        assert_eq!(
            client
                .fakedns
                .as_ref()
                .unwrap()
                .query_domain(&entry.ips[0])
                .await
                .as_deref(),
            Some("fake.example")
        );
    }

    #[tokio::test]
    async fn fakedns_query_falls_through_to_the_next_server() {
        // A stub name server on loopback that answers every request with
        // 10.9.8.7, standing in for the real server next to `fakedns`.
        let stub = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stub_addr = stub.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            while let Ok((n, peer)) = stub.recv_from(&mut buf).await {
                if let Some(resp) = a_record_response(&buf[..n], Ipv4Addr::new(10, 9, 8, 7)) {
                    let _ = stub.send_to(&resp, peer).await;
                }
            }
        });

        let mut client = new_client(vec!["fakedns"]);
        client.replace_fakedns(Arc::new(FakeDns::new(FakeDnsMode::Exclude, vec![])));

        // The engine is registered, but it only answers A records, so an AAAA
        // lookup must fall through to the next server instead of failing.
        let fake = make_ns("fakedns", &[], false, false);
        let next = make_ns(
            &format!("direct:127.0.0.1:{}", stub_addr.port()),
            &[],
            false,
            false,
        );
        let request = DnsClient::new_query(
            Name::from_str("normal.example.").unwrap(),
            RecordType::AAAA,
            None,
        )
        .to_vec()
        .unwrap();
        let entry = client
            .serial_query(&[&fake, &next], "normal.example", RecordType::AAAA, &request)
            .await
            .unwrap();

        assert_eq!(entry.ips, vec![IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))]);
        server.abort();
    }

    /// Builds a minimal DNS response copying the request's question and
    /// answering with a single A record.
    fn a_record_response(request: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
        use hickory_proto::op::{
            header::MessageType, op_code::OpCode, response_code::ResponseCode, Message,
        };
        use hickory_proto::rr::{
            dns_class::DNSClass, rdata, record_data::RData, record_type::RecordType,
            resource::Record,
        };

        let req = Message::from_vec(request).ok()?;
        let query = req.queries().first()?.clone();
        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);
        resp.add_query(query.clone());
        let mut ans = Record::new();
        ans.set_name(query.name().clone())
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_ttl(60)
            .set_data(Some(RData::A(rdata::A(ip))));
        resp.add_answer(ans);
        resp.to_vec().ok()
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

    #[test]
    fn domain_rules_lowercase_their_values() {
        // Xray lowercases `full:`/`domain:`/`keyword:`/bare values while
        // building the matcher, and the query domain is lowercased too; a rule
        // containing an uppercase letter must therefore still match.
        assert!(DomainRule::parse("full:Example.COM")
            .unwrap()
            .matches("example.com"));
        assert!(DomainRule::parse("domain:Example.COM")
            .unwrap()
            .matches("www.example.com"));
        assert!(DomainRule::parse("keyword:AMPLE")
            .unwrap()
            .matches("example.com"));
        assert!(DomainRule::parse("AMPLE").unwrap().matches("example.com"));
        // A regexp is kept verbatim, so a case-insensitive pattern still needs
        // its own `(?i)`.
        #[cfg(feature = "regex")]
        assert!(DomainRule::parse("regexp:(?i)^ADS\\.")
            .unwrap()
            .matches("ads.example.com"));
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
