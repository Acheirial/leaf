#[derive(Clone, Debug)]
struct CacheEntry {
    pub ips: Vec<IpAddr>,
    pub deadline: Instant,
}

#[derive(Clone, Debug)]
pub struct EchCacheEntry {
    pub ech_config_list: String,
    pub deadline: Instant,
}

/// DNS-over-HTTPS transport description.
#[derive(Clone, Debug)]
struct DohResolver {
    domain: String,
    bootstrap_ip: Option<IpAddr>,
    port: u16,
    path: String,
    /// `h2c://` / `h2c+local://`: cleartext HTTP/2 (no TLS).
    is_h2c: bool,
    is_direct: bool,
}

/// DNS-over-QUIC transport description (`quic+local://`).
#[derive(Clone, Debug)]
struct QuicResolver {
    host: String,
    port: u16,
}

/// The parsed transport of a name server.
#[derive(Clone, Debug)]
enum Resolver {
    /// Classic UDP DNS. The bool is `+local` (bypass routing).
    Server(SocketAddr, bool),
    /// DNS over TCP (RFC 7766). The bool is `+local`.
    Tcp(SocketAddr, bool),
    /// DNS over HTTPS / h2c.
    DoH(DohResolver),
    /// DNS over QUIC.
    Quic(QuicResolver),
    /// The OS resolver (`localhost` / `system`).
    System(bool),
    /// The in-process fake-DNS engine (`fakedns`).
    FakeDns,
}

impl Resolver {
    fn is_direct(&self) -> bool {
        match self {
            Self::Server(_, direct) | Self::Tcp(_, direct) | Self::System(direct) => *direct,
            Self::DoH(doh) => doh.is_direct,
            Self::Quic(_) => true,
            // `FakeDns` never becomes an `NsClient` (it is rejected in
            // `build_ns_client`), but it is not a direct transport either: if it
            // were the only "direct" server it would shadow the real servers in
            // `collect_servers(true)` and break `direct_lookup` fallback.
            Self::FakeDns => false,
        }
    }

    /// Overrides the destination port of the transport, if it has one.
    fn with_port(&mut self, port: u16) {
        match self {
            Self::Server(addr, _) | Self::Tcp(addr, _) => {
                addr.set_port(port);
            }
            Self::DoH(doh) => doh.port = port,
            Self::Quic(quic) => quic.port = port,
            Self::System(_) | Self::FakeDns => (),
        }
    }
}

/// A configured name server plus the selection metadata attached to it.
#[derive(Clone)]
struct NsClient {
    resolver: Resolver,
    domains: Vec<DomainRule>,
    expected: Option<IpMatcher>,
    unexpected: Option<IpMatcher>,
    /// `expectedIPs` contained a literal `"*"`.
    act_prior: bool,
    /// `unexpectedIPs` contained a literal `"*"`.
    act_unprior: bool,
    strategy: Option<QueryStrategy>,
    tag: String,
    timeout: Duration,
    final_query: bool,
    skip_fallback: bool,
    /// Equality key used by `make_groups` to decide which servers race together.
    policy_key: String,
}

impl NsClient {
    fn is_direct(&self) -> bool {
        self.resolver.is_direct()
    }

    fn display_name(&self) -> String {
        self.resolver.to_string()
    }

    /// The per-query family filter after applying the server override. A server
    /// without an explicit strategy inherits the global option unchanged.
    fn ip_option(&self, base: IpOption) -> IpOption {
        match self.strategy {
            Some(strategy) => base.override_with(strategy),
            None => base,
        }
    }
}

impl fmt::Display for NsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.resolver)
    }
}

impl fmt::Display for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(addr, direct) => {
                if *direct {
                    write!(f, "direct:{}", addr)
                } else {
                    write!(f, "{}", addr)
                }
            }
            Self::Tcp(addr, direct) => {
                if *direct {
                    write!(f, "direct:tcp://{}", addr)
                } else {
                    write!(f, "tcp://{}", addr)
                }
            }
            Self::DoH(doh) => {
                if doh.is_h2c {
                    if doh.is_direct {
                        write!(f, "h2c+local://{}", doh.domain)?;
                    } else {
                        write!(f, "h2c://{}", doh.domain)?;
                    }
                } else if doh.is_direct {
                    write!(f, "direct:doh:{}", doh.domain)?;
                } else {
                    write!(f, "doh:{}", doh.domain)?;
                }
                if let Some(ip) = doh.bootstrap_ip {
                    write!(f, "@{}", ip)?;
                }
                Ok(())
            }
            Self::Quic(quic) => write!(f, "quic+local://{}:{}", quic.host, quic.port),
            Self::System(direct) => {
                if *direct {
                    write!(f, "direct:system")
                } else {
                    write!(f, "system")
                }
            }
            Self::FakeDns => write!(f, "fakedns"),
        }
    }
}

pub struct DnsClient {
    dispatcher: Option<Weak<Dispatcher>>,
    servers: Vec<NsClient>,
    hosts: HashMap<String, Vec<IpAddr>>,
    fakedns: Option<Arc<crate::app::fake_dns::FakeDns>>,
    client_ip: Option<IpAddr>,
    query_strategy: QueryStrategy,
    disable_cache: bool,
    serve_stale: bool,
    serve_expired_ttl: u32,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
    enable_parallel_query: bool,
    ipv4_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ipv6_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ech_cache: Arc<TokioMutex<LruCache<String, EchCacheEntry>>>,
    ech_query_locks: Arc<TokioMutex<HashMap<String, Arc<TokioMutex<()>>>>>,
}
