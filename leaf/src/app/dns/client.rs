use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::{
    op::{
        header::MessageType, op_code::OpCode, query::Query, response_code::ResponseCode, Edns,
        Message,
    },
    rr::{record_data::RData, record_type::RecordType, Name},
};
use lru::LruCache;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use tracing::{debug, trace, warn, Instrument};

#[cfg(feature = "dns-tls")]
#[cfg(feature = "rustls-tls")]
use {
    std::sync::Arc as SyncArc,
    tokio_rustls::{
        rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
        TlsConnector,
    },
};

#[cfg(all(
    feature = "dns-tls",
    not(feature = "rustls-tls"),
    feature = "openssl-tls"
))]
use {
    futures::TryFutureExt,
    openssl::ssl::{Ssl, SslConnector, SslMethod},
    std::pin::Pin,
    tokio_openssl::SslStream,
};

use crate::{app::dispatcher::Dispatcher, option, proxy::*, session::*};
include!("client/types.rs");
include!("client/rules.rs");
include!("client/selector.rs");

/// EDNS0 UDP payload size advertised in queries (`build_edns_ecs`) and the size
/// of the receive buffer for plain-UDP answers. Both are derived from this one
/// constant so they cannot drift: a compliant server's answer (at most this
/// size) always fits the buffer, and the kernel cannot silently truncate it.
const EDNS_UDP_PAYLOAD_SIZE: usize = 4096;

tokio::task_local! {
    /// Set while a name query is being carried by an outbound.
    ///
    /// Such a query hands its session to the dispatcher, which may pick an
    /// outbound that has to resolve its own dial address. That lookup runs in
    /// this task while this marker is set; if it were itself carried by an
    /// outbound it would resolve that outbound's dial address again --
    /// lookup -> dispatched query -> outbound dial -> lookup -- and recurse
    /// without bound. The helpers below therefore answer a lookup that is
    /// performed under this marker directly, from the local host, instead of
    /// handing it to the dispatcher.
    static ROUTED_QUERY_IN_FLIGHT: ();
}

/// Whether the current task is already carrying a name query through an
/// outbound (see `ROUTED_QUERY_IN_FLIGHT`).
fn routed_query_in_flight() -> bool {
    ROUTED_QUERY_IN_FLIGHT.try_with(|_| ()).is_ok()
}

impl DnsClient {
    // ---------------------------------------------------------------- config

    /// Parses one name server address using Xray's grammar.
    fn parse_server(server: &str) -> Result<Resolver> {
        let (server, is_direct) = if let Some(rest) = server.strip_prefix("direct:") {
            (rest, true)
        } else {
            (server, false)
        };
        let server = server.trim();
        if server.is_empty() {
            return Err(anyhow!("empty dns server address"));
        }
        let lower = server.to_ascii_lowercase();

        if lower == "localhost" || lower == "system" {
            return Ok(Resolver::System(is_direct));
        }
        if lower == "fakedns" {
            return Ok(Resolver::FakeDns);
        }
        if lower.starts_with("doh:") {
            return Self::parse_legacy_doh(server, is_direct);
        }
        if let Some((scheme, rest)) = server.split_once("://") {
            return Self::parse_scheme(scheme, rest, is_direct);
        }

        // Bare `host[:port]` is UDP classic DNS.
        Ok(Resolver::Server(
            Self::parse_ip_host_port(server, 53)?,
            is_direct,
        ))
    }

    fn parse_scheme(scheme: &str, rest: &str, is_direct: bool) -> Result<Resolver> {
        match scheme.to_ascii_lowercase().as_str() {
            "udp" => Ok(Resolver::Server(
                Self::parse_ip_host_port(rest, 53)?,
                is_direct,
            )),
            "tcp" => Ok(Resolver::Tcp(
                Self::parse_ip_host_port(rest, 53)?,
                is_direct,
            )),
            "tcp+local" => Ok(Resolver::Tcp(Self::parse_ip_host_port(rest, 53)?, true)),
            "https" => {
                #[cfg(feature = "dns-tls")]
                {
                    Self::parse_doh(rest, 443, false, is_direct)
                }
                #[cfg(not(feature = "dns-tls"))]
                {
                    let _ = (rest, is_direct);
                    Err(anyhow!(
                        "dns server [https://{}] requires the \"dns-tls\" feature",
                        rest
                    ))
                }
            }
            "https+local" => {
                #[cfg(feature = "dns-tls")]
                {
                    Self::parse_doh(rest, 443, false, true)
                }
                #[cfg(not(feature = "dns-tls"))]
                {
                    let _ = rest;
                    Err(anyhow!(
                        "dns server [https+local://{}] requires the \"dns-tls\" feature",
                        rest
                    ))
                }
            }
            "h2c" => Self::parse_doh(rest, 80, true, is_direct),
            "h2c+local" => Self::parse_doh(rest, 80, true, true),
            "quic+local" => {
                #[cfg(feature = "dns-quic")]
                {
                    let (host, port) = Self::split_authority(rest, 853)?;
                    Ok(Resolver::Quic(QuicResolver { host, port }))
                }
                #[cfg(not(feature = "dns-quic"))]
                {
                    let _ = rest;
                    Err(anyhow!(
                        "dns server [quic+local://{}] requires the \"dns-quic\" feature",
                        rest
                    ))
                }
            }
            other => Err(anyhow!(
                "unsupported dns server scheme [{}://] in [{}://{}]",
                other,
                other,
                rest
            )),
        }
    }

    /// `https://` / `h2c://` / `...+local://` DoH server description.
    fn parse_doh(rest: &str, default_port: u16, is_h2c: bool, is_direct: bool) -> Result<Resolver> {
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/dns-query"),
        };
        if authority.is_empty() {
            return Err(anyhow!("invalid dns server [{}]: empty host", rest));
        }
        let (host, port) = Self::split_authority(authority, default_port)?;
        if host.parse::<IpAddr>().is_err() {
            let mut fqdn = host.clone();
            fqdn.push('.');
            Name::from_str(&fqdn)
                .map_err(|e| anyhow!("invalid dns server host [{}]: {}", host, e))?;
        }
        let path = if path.is_empty() {
            "/dns-query".to_owned()
        } else {
            path.to_owned()
        };
        Ok(Resolver::DoH(DohResolver {
            domain: host,
            bootstrap_ip: None,
            port,
            path,
            is_h2c,
            is_direct,
        }))
    }

    /// The legacy in-tree `doh:domain[@bootstrap-ip]` spelling.
    fn parse_legacy_doh(server: &str, is_direct: bool) -> Result<Resolver> {
        #[cfg(feature = "dns-tls")]
        {
            let rest = &server[4..];
            let (domain, ip) = if let Some((domain, ip)) = rest.split_once('@') {
                (domain, Some(ip))
            } else {
                (rest, None)
            };
            if domain.is_empty() {
                return Err(anyhow!(
                    "invalid dns server [doh:{}]: empty doh domain",
                    rest
                ));
            }
            let mut fqdn = domain.to_owned();
            fqdn.push('.');
            Name::from_str(&fqdn)
                .map_err(|e| anyhow!("invalid dns server [doh:{}]: {}", rest, e))?;
            let bootstrap_ip = if let Some(ip) = ip {
                if ip.is_empty() {
                    return Err(anyhow!(
                        "invalid dns server [doh:{}]: empty bootstrap ip",
                        rest
                    ));
                }
                Some(
                    ip.parse::<IpAddr>()
                        .map_err(|e| anyhow!("invalid dns server [doh:{}]: {}", rest, e))?,
                )
            } else {
                None
            };
            Ok(Resolver::DoH(DohResolver {
                domain: domain.to_string(),
                bootstrap_ip,
                port: 443,
                path: "/dns-query".to_owned(),
                is_h2c: false,
                is_direct,
            }))
        }
        #[cfg(not(feature = "dns-tls"))]
        {
            let _ = is_direct;
            Err(anyhow!(
                "dns server [{}] requires the \"dns-tls\" feature",
                server
            ))
        }
    }

    /// Splits `host:port` where `host` is an IP literal, applying `default_port`
    /// when no port is present.
    fn parse_ip_host_port(s: &str, default_port: u16) -> Result<SocketAddr> {
        let (host, port) = Self::split_authority(s, default_port)?;
        let ip = host
            .parse::<IpAddr>()
            .map_err(|e| anyhow!("invalid dns server [{}]: {}", s, e))?;
        Ok(SocketAddr::new(ip, port))
    }

    /// Splits an `[v6]:port`, `host:port` or `host` authority.
    fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
        let authority = authority.trim();
        if authority.is_empty() {
            return Err(anyhow!("empty host"));
        }
        if let Some(rest) = authority.strip_prefix('[') {
            let end = rest
                .find(']')
                .ok_or_else(|| anyhow!("invalid host [{}]", authority))?;
            let host = rest[..end].to_owned();
            let after = &rest[end + 1..];
            let port = if let Some(port) = after.strip_prefix(':') {
                port.parse::<u16>()
                    .map_err(|e| anyhow!("invalid port [{}]: {}", port, e))?
            } else {
                default_port
            };
            return Ok((host, port));
        }
        if authority.matches(':').count() == 1 {
            if let Some((host, port)) = authority.rsplit_once(':') {
                let port = port
                    .parse::<u16>()
                    .map_err(|e| anyhow!("invalid port [{}]: {}", port, e))?;
                return Ok((host.to_owned(), port));
            }
        }
        Ok((authority.to_owned(), default_port))
    }

    /// The equality key Xray computes in `buildPolicyID`, used by `make_groups`.
    fn build_policy_key(server: &crate::config::DnsServer) -> String {
        fn normalized(list: &[String]) -> String {
            let mut items: Vec<String> = list
                .iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            items.sort();
            items.join(",")
        }
        format!(
            "client=none|skip={}|qs={}|tag={}|domains={}|expected={}|unexpected={}",
            server.skip_fallback.unwrap_or(false) as u8,
            server
                .query_strategy
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_lowercase(),
            server.tag.as_deref().unwrap_or("").trim().to_lowercase(),
            normalized(&server.domains),
            normalized(&server.expected_ips),
            normalized(&server.unexpected_ips),
        )
    }

    fn build_ns_client(server: &crate::config::DnsServer, default_tag: &str) -> Result<NsClient> {
        let mut resolver = Self::parse_server(&server.address)?;
        if let Some(port) = server.port {
            if port == 0 || port > u16::MAX as u32 {
                return Err(anyhow!("invalid dns server port [{}]", port));
            }
            resolver.with_port(port as u16);
        }
        // A `fakedns` entry is accepted unconditionally: the device-wide
        // `FakeDns` engine is registered with `replace_fakedns` right after
        // this client is constructed, so acceptance cannot be decided here.
        // When no engine has been registered, `query_fakedns` reports a named
        // error and the query falls through to the remaining servers, which
        // keeps `["fakedns", "<real server>"]` resolvable.
        let domains = parse_domain_rules(&server.domains)?;
        let (expected, act_prior) = IpMatcher::parse(&server.expected_ips)?;
        let (unexpected, act_unprior) = IpMatcher::parse(&server.unexpected_ips)?;
        let strategy = server
            .query_strategy
            .as_ref()
            .map(|s| QueryStrategy::parse(s));
        let tag = server
            .tag
            .as_ref()
            .filter(|t| !t.is_empty())
            .cloned()
            .unwrap_or_else(|| default_tag.to_owned());
        let timeout = server
            .timeout_ms
            .filter(|v| *v > 0)
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(*option::DNS_TIMEOUT));
        // The cache is a single global LRU per family, keyed by host
        // (`ipv4_cache`/`ipv6_cache`), and stale-serving is decided in
        // `_lookup_inner` before any server is selected. Per-server cache
        // semantics are therefore impossible to honour: reject the options here
        // rather than accepting them and silently applying the global values.
        if server.disable_cache.is_some() {
            return Err(anyhow!(
                "per-server disableCache is not supported: the dns cache is global"
            ));
        }
        if server.serve_stale.is_some() {
            return Err(anyhow!(
                "per-server serveStale is not supported: the dns cache is global"
            ));
        }
        if server.serve_expired_ttl.is_some() {
            return Err(anyhow!(
                "per-server serveExpiredTTL is not supported: the dns cache is global"
            ));
        }
        let policy_key = Self::build_policy_key(server);
        Ok(NsClient {
            resolver,
            domains,
            expected,
            unexpected,
            act_prior,
            act_unprior,
            strategy,
            tag,
            timeout,
            final_query: server.final_query.unwrap_or(false),
            skip_fallback: server.skip_fallback.unwrap_or(false),
            policy_key,
        })
    }

    fn load_servers(dns: &crate::config::Dns, default_tag: &str) -> Result<Vec<NsClient>> {
        let mut servers = Vec::new();
        for server in dns.servers.iter() {
            match Self::build_ns_client(server, default_tag) {
                Ok(client) => servers.push(client),
                Err(err) => warn!("skip invalid dns server [{}]: {}", server.address, err),
            }
        }
        for server in &servers {
            debug!("loaded dns server: {}", server);
        }
        if servers.is_empty() {
            return Err(anyhow!("no dns servers"));
        }
        Ok(servers)
    }

    fn load_hosts(dns: &crate::config::Dns) -> HashMap<String, Vec<IpAddr>> {
        let mut parsed_hosts = HashMap::new();
        for (name, ips) in dns.hosts.iter() {
            let mut parsed = Vec::new();
            for ip in &ips.values {
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    parsed.push(ip);
                }
            }
            parsed_hosts.insert(name.to_owned(), parsed);
        }
        parsed_hosts
    }

    /// Reads the OS hosts file, mirroring Xray's `readSystemHosts`.
    fn load_system_hosts() -> HashMap<String, Vec<IpAddr>> {
        let path = Self::system_hosts_path();
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) => {
                warn!("read system hosts [{}] failed: {}", path.display(), e);
                return HashMap::new();
            }
        };
        let mut hosts: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut fields = line.split_whitespace();
            let Some(addr) = fields.next() else {
                continue;
            };
            let Ok(ip) = addr.parse::<IpAddr>() else {
                continue;
            };
            for host in fields {
                let host = host.trim_end_matches('.').to_lowercase();
                if host.is_empty() {
                    continue;
                }
                hosts.entry(host).or_default().push(ip);
            }
        }
        hosts
    }

    #[cfg(target_os = "windows")]
    fn system_hosts_path() -> std::path::PathBuf {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
        std::path::Path::new(&root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }

    #[cfg(not(target_os = "windows"))]
    fn system_hosts_path() -> std::path::PathBuf {
        std::path::PathBuf::from("/etc/hosts")
    }

    pub fn new(dns: &protobuf::MessageField<crate::config::Dns>) -> Result<Self> {
        let dns = if let Some(dns) = dns.as_ref() {
            dns
        } else {
            return Err(anyhow!("empty dns config"));
        };
        let default_tag = dns
            .tag
            .as_ref()
            .filter(|t| !t.is_empty())
            .cloned()
            .unwrap_or_else(|| "dnsclient".to_owned());
        let servers = Self::load_servers(dns, &default_tag)?;
        let mut hosts = Self::load_hosts(dns);
        if dns.use_system_hosts.unwrap_or(false) {
            for (name, ips) in Self::load_system_hosts() {
                hosts.entry(name).or_insert(ips);
            }
        }
        let client_ip = match dns.client_ip.as_deref() {
            Some(value) if !value.is_empty() => Some(
                value
                    .parse::<IpAddr>()
                    .map_err(|e| anyhow!("invalid dns client_ip [{}]: {}", value, e))?,
            ),
            _ => None,
        };
        let query_strategy = dns
            .query_strategy
            .as_ref()
            .map(|s| QueryStrategy::parse(s))
            .unwrap_or(QueryStrategy::UseIp);
        let ipv4_cache = Arc::new(TokioMutex::new(LruCache::<String, CacheEntry>::new(
            NonZeroUsize::new(*option::DNS_CACHE_SIZE).unwrap(),
        )));
        let ipv6_cache = Arc::new(TokioMutex::new(LruCache::<String, CacheEntry>::new(
            NonZeroUsize::new(*option::DNS_CACHE_SIZE).unwrap(),
        )));
        let ech_cache = Arc::new(TokioMutex::new(LruCache::<String, EchCacheEntry>::new(
            NonZeroUsize::new(*option::DNS_CACHE_SIZE).unwrap(),
        )));

        Ok(Self {
            dispatcher: None,
            servers,
            hosts,
            fakedns: None,
            client_ip,
            query_strategy,
            disable_cache: dns.disable_cache.unwrap_or(false),
            serve_stale: dns.serve_stale.unwrap_or(false),
            serve_expired_ttl: dns.serve_expired_ttl.unwrap_or(0),
            disable_fallback: dns.disable_fallback.unwrap_or(false),
            disable_fallback_if_match: dns.disable_fallback_if_match.unwrap_or(false),
            enable_parallel_query: dns.enable_parallel_query.unwrap_or(false),
            ipv4_cache,
            ipv6_cache,
            ech_cache,
            ech_query_locks: Arc::new(TokioMutex::new(HashMap::new())),
        })
    }

    pub fn replace_dispatcher(&mut self, dispatcher: Weak<Dispatcher>) {
        self.dispatcher.replace(dispatcher);
    }

    /// Wires the in-process fake-DNS engine used by the `fakedns` server form.
    pub fn replace_fakedns(&mut self, fakedns: Arc<crate::app::fake_dns::FakeDns>) {
        self.fakedns.replace(fakedns);
    }

    pub fn reload(&mut self, dns: &protobuf::MessageField<crate::config::Dns>) -> Result<()> {
        let dns = if let Some(dns) = dns.as_ref() {
            dns
        } else {
            return Err(anyhow!("empty dns config"));
        };
        let default_tag = dns
            .tag
            .as_ref()
            .filter(|t| !t.is_empty())
            .cloned()
            .unwrap_or_else(|| "dnsclient".to_owned());
        let servers = Self::load_servers(dns, &default_tag)?;
        let mut hosts = Self::load_hosts(dns);
        if dns.use_system_hosts.unwrap_or(false) {
            for (name, ips) in Self::load_system_hosts() {
                hosts.entry(name).or_insert(ips);
            }
        }
        self.servers = servers;
        self.hosts = hosts;
        self.disable_cache = dns.disable_cache.unwrap_or(false);
        self.serve_stale = dns.serve_stale.unwrap_or(false);
        self.serve_expired_ttl = dns.serve_expired_ttl.unwrap_or(0);
        self.disable_fallback = dns.disable_fallback.unwrap_or(false);
        self.disable_fallback_if_match = dns.disable_fallback_if_match.unwrap_or(false);
        self.enable_parallel_query = dns.enable_parallel_query.unwrap_or(false);
        self.query_strategy = dns
            .query_strategy
            .as_ref()
            .map(|s| QueryStrategy::parse(s))
            .unwrap_or(QueryStrategy::UseIp);
        self.client_ip = match dns.client_ip.as_deref() {
            Some(value) if !value.is_empty() => Some(
                value
                    .parse::<IpAddr>()
                    .map_err(|e| anyhow!("invalid dns client_ip [{}]: {}", value, e))?,
            ),
            _ => None,
        };
        Ok(())
    }

    // ----------------------------------------------------------------- cache

    async fn optimize_cache_ipv4(&self, address: String, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        // If the connected IP is not in the first place, we should optimize it.
        let mut new_entry = if let Some(entry) = self.ipv4_cache.lock().await.get(&address) {
            if !entry.ips.starts_with(&[connected_ip]) && entry.ips.contains(&connected_ip) {
                entry.clone()
            } else {
                return;
            }
        } else {
            return;
        };

        // Move failed IPs to the end, the optimized vector starts with the connected IP.
        if let Ok(idx) = new_entry.ips.binary_search(&connected_ip) {
            trace!("updates DNS cache item from\n{:#?}", &new_entry);
            new_entry.ips.rotate_left(idx);
            trace!("to\n{:#?}", &new_entry);
            self.ipv4_cache.lock().await.put(address, new_entry);
            trace!("updated cache");
        }
    }

    async fn optimize_cache_ipv6(&self, address: String, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        // If the connected IP is not in the first place, we should optimize it.
        let mut new_entry = if let Some(entry) = self.ipv6_cache.lock().await.get(&address) {
            if !entry.ips.starts_with(&[connected_ip]) && entry.ips.contains(&connected_ip) {
                entry.clone()
            } else {
                return;
            }
        } else {
            return;
        };

        // Move failed IPs to the end, the optimized vector starts with the connected IP.
        if let Ok(idx) = new_entry.ips.binary_search(&connected_ip) {
            trace!("updates DNS cache item from\n{:#?}", &new_entry);
            new_entry.ips.rotate_left(idx);
            trace!("to\n{:#?}", &new_entry);
            self.ipv6_cache.lock().await.put(address, new_entry);
            trace!("updated cache");
        }
    }

    /// Updates the cache according to the IP address successfully connected.
    pub async fn optimize_cache(&self, address: String, connected_ip: IpAddr) {
        match connected_ip {
            IpAddr::V4(..) => self.optimize_cache_ipv4(address, connected_ip).await,
            IpAddr::V6(..) => self.optimize_cache_ipv6(address, connected_ip).await,
        }
    }

    async fn cache_insert(&self, host: &str, entry: CacheEntry) {
        if self.disable_cache || entry.ips.is_empty() {
            return;
        }
        match entry.ips[0] {
            IpAddr::V4(..) => self.ipv4_cache.lock().await.put(host.to_owned(), entry),
            IpAddr::V6(..) => self.ipv6_cache.lock().await.put(host.to_owned(), entry),
        };
    }

    async fn get_cached_ech(&self, host: &str) -> Option<String> {
        let mut cache = self.ech_cache.lock().await;
        if let Some(entry) = cache.get(host) {
            if entry
                .deadline
                .checked_duration_since(Instant::now())
                .is_some()
            {
                return Some(entry.ech_config_list.clone());
            }
        }
        cache.pop(host);
        None
    }

    async fn get_cached(&self, host: &String) -> Result<Vec<IpAddr>> {
        let now = Instant::now();
        let mut cached_ips = Vec::new();

        let fetch_order = match (*crate::option::ENABLE_IPV6, *crate::option::PREFER_IPV6) {
            (true, true) => vec![&self.ipv6_cache, &self.ipv4_cache],
            (true, false) => vec![&self.ipv4_cache, &self.ipv6_cache],
            _ => vec![&self.ipv4_cache],
        };

        for cache in fetch_order {
            if let Some(entry) = cache.lock().await.get(host) {
                if entry.deadline.checked_duration_since(now).is_some() {
                    cached_ips.extend_from_slice(&entry.ips);
                } else if self.serve_stale {
                    let expired = now.saturating_duration_since(entry.deadline);
                    if self.serve_expired_ttl == 0
                        || expired < Duration::from_secs(self.serve_expired_ttl as u64)
                    {
                        cached_ips.extend_from_slice(&entry.ips);
                    }
                }
            }
        }

        if cached_ips.is_empty() {
            Err(anyhow!("empty result"))
        } else {
            Ok(cached_ips)
        }
    }

    // ------------------------------------------------------------ transports

    async fn resolve_doh_bootstrap_addr(
        &self,
        domain: &str,
        bootstrap_ip: Option<IpAddr>,
        port: u16,
    ) -> Result<SocketAddr> {
        if let Some(ip) = bootstrap_ip {
            return Ok(SocketAddr::new(ip, port));
        }
        Self::resolve_host_port(domain, port).await
    }

    async fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let owned = host.to_owned();
        let addr = tokio::task::spawn_blocking(move || {
            (owned.as_str(), port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
        })
        .await
        .map_err(|e| anyhow!("spawn blocking failed: {}", e))?;
        addr.ok_or_else(|| {
            anyhow!(
                "bootstrap failed: no resolved address for {}:{}",
                host,
                port
            )
        })
    }

    async fn connect_doh_tcp_stream(
        &self,
        doh: &DohResolver,
        bootstrap_addr: SocketAddr,
        tag: &str,
    ) -> Result<AnyStream> {
        // See `open_udp_socket`: a query resolved under `ROUTED_QUERY_IN_FLIGHT`
        // must not be carried by an outbound.
        if doh.is_direct || routed_query_in_flight() {
            let stream = TcpStream::connect(bootstrap_addr).await?;
            return Ok(Box::new(stream));
        }
        if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
            if let Some(dispatcher) = dispatcher_weak.upgrade() {
                let source = match bootstrap_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };
                let sess = Session {
                    network: Network::Tcp,
                    source,
                    destination: SocksAddr::from(bootstrap_addr),
                    inbound_tag: tag.to_string(),
                    ..Default::default()
                };
                return ROUTED_QUERY_IN_FLIGHT
                    .scope((), dispatcher.dispatch_stream_outbound(sess))
                    .await
                    .map_err(|e| anyhow!("dispatch stream failed: {}", e));
            }
            return Err(anyhow!("dispatcher is gone"));
        }
        Err(anyhow!("no dispatcher"))
    }

    #[cfg(all(feature = "dns-tls", feature = "rustls-tls"))]
    async fn wrap_doh_tls_stream(stream: AnyStream, server_name: &str) -> Result<AnyStream> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(SyncArc::new(config));
        let domain = ServerName::try_from(server_name.to_owned())
            .map_err(|e| anyhow!("invalid tls server name {}: {}", server_name, e))?;
        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| anyhow!("connect tls failed: {}", e))?;
        Ok(Box::new(tls_stream))
    }

    #[cfg(all(
        feature = "dns-tls",
        not(feature = "rustls-tls"),
        feature = "openssl-tls"
    ))]
    async fn wrap_doh_tls_stream(stream: AnyStream, server_name: &str) -> Result<AnyStream> {
        let ssl_connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| anyhow!("create ssl connector failed: {}", e))?
            .build();
        let mut ssl =
            Ssl::new(ssl_connector.context()).map_err(|e| anyhow!("new ssl failed: {}", e))?;
        ssl.set_hostname(server_name)
            .map_err(|e| anyhow!("set tls name failed: {}", e))?;
        let mut stream =
            SslStream::new(ssl, stream).map_err(|e| anyhow!("new ssl stream failed: {}", e))?;
        Pin::new(&mut stream)
            .connect()
            .map_err(|e| anyhow!("connect ssl stream failed: {}", e))
            .await?;
        Ok(Box::new(stream))
    }

    fn build_doh_http_request(host: &str, path: &str, body_len: usize) -> String {
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path, host, body_len
        )
    }

    fn decode_chunked_body(mut data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line_end = data
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| anyhow!("invalid chunked response"))?;
            let size_line = std::str::from_utf8(&data[..line_end])
                .map_err(|e| anyhow!("invalid chunk size line: {}", e))?;
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16)
                .map_err(|e| anyhow!("invalid chunk size: {}", e))?;
            data = &data[line_end + 2..];
            if size == 0 {
                return Ok(out);
            }
            if data.len() < size + 2 {
                return Err(anyhow!("incomplete chunked body"));
            }
            out.extend_from_slice(&data[..size]);
            if &data[size..size + 2] != b"\r\n" {
                return Err(anyhow!("invalid chunk terminator"));
            }
            data = &data[size + 2..];
        }
    }

    fn parse_doh_http_body(resp: &[u8]) -> Result<Vec<u8>> {
        let header_end = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("invalid http response"))?;
        let header_bytes = &resp[..header_end];
        let body = &resp[header_end + 4..];
        let header_text = std::str::from_utf8(header_bytes)
            .map_err(|e| anyhow!("invalid http headers: {}", e))?;
        let mut lines = header_text.split("\r\n");
        let status_line = lines.next().ok_or_else(|| anyhow!("missing status line"))?;
        let mut status_parts = status_line.split_whitespace();
        let _http = status_parts.next();
        let code = status_parts
            .next()
            .ok_or_else(|| anyhow!("invalid status line"))?
            .parse::<u16>()
            .map_err(|e| anyhow!("invalid status code: {}", e))?;
        if code != 200 {
            return Err(anyhow!("doh server returned http status {}", code));
        }
        let mut content_length = None;
        let mut chunked = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                let value = v.trim().to_ascii_lowercase();
                if key == "content-length" {
                    let len = value
                        .parse::<usize>()
                        .map_err(|e| anyhow!("invalid content-length: {}", e))?;
                    content_length = Some(len);
                } else if key == "transfer-encoding" && value.contains("chunked") {
                    chunked = true;
                }
            }
        }
        if chunked {
            return Self::decode_chunked_body(body);
        }
        if let Some(len) = content_length {
            if body.len() < len {
                return Err(anyhow!("incomplete http body"));
            }
            return Ok(body[..len].to_vec());
        }
        Ok(body.to_vec())
    }

    /// DNS-over-HTTPS over TLS (`https://`, `https+local://`, legacy `doh:`).
    #[cfg(feature = "dns-tls")]
    async fn query_with_doh_tls(
        &self,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        doh: &DohResolver,
        tag: &str,
    ) -> Result<CacheEntry> {
        for i in 0..*option::MAX_DNS_RETRIES {
            let start = tokio::time::Instant::now();
            debug!(
                "looking up host={} server={} ({}/{})",
                host,
                resolver,
                i + 1,
                *option::MAX_DNS_RETRIES
            );
            let bootstrap_addr = match self
                .resolve_doh_bootstrap_addr(&doh.domain, doh.bootstrap_ip, doh.port)
                .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    debug!("resolve doh bootstrap failed: {}", err);
                    continue;
                }
            };
            let stream = match self.connect_doh_tcp_stream(doh, bootstrap_addr, tag).await {
                Ok(stream) => stream,
                Err(err) => {
                    debug!("connect doh stream failed: {}", err);
                    continue;
                }
            };
            let mut stream = match Self::wrap_doh_tls_stream(stream, &doh.domain).await {
                Ok(stream) => stream,
                Err(err) => {
                    debug!("connect doh tls failed: {}", err);
                    continue;
                }
            };
            let request_header =
                Self::build_doh_http_request(&doh.domain, &doh.path, request.len());
            if let Err(err) = stream.write_all(request_header.as_bytes()).await {
                debug!("write doh http header failed: {}", err);
                continue;
            }
            if let Err(err) = stream.write_all(&request).await {
                debug!("write doh message body failed: {}", err);
                continue;
            }
            if let Err(err) = stream.flush().await {
                debug!("flush doh request failed: {}", err);
                continue;
            }
            let mut resp = Vec::new();
            if let Err(err) = stream.read_to_end(&mut resp).await {
                debug!("read doh response failed: {}", err);
                continue;
            }
            let dns_payload = match Self::parse_doh_http_body(&resp) {
                Ok(body) => body,
                Err(err) => {
                    debug!("parse doh http response failed: {}", err);
                    continue;
                }
            };
            let message = match Message::from_vec(&dns_payload) {
                Ok(message) => message,
                Err(err) => {
                    debug!("parse doh dns payload failed: {}", err);
                    continue;
                }
            };
            let elapsed = tokio::time::Instant::now().duration_since(start);
            match Self::message_to_entry(&message, host, &doh.domain) {
                Ok(entry) => {
                    debug!(
                        "received from server={} ttl={} elapsed={}ms ips={:?}",
                        resolver,
                        message
                            .answers()
                            .iter()
                            .next()
                            .map(|a| a.ttl())
                            .unwrap_or(0),
                        elapsed.as_millis(),
                        &entry.ips
                    );
                    return Ok(entry);
                }
                Err(err) => {
                    debug!("bad doh dns response: {}", err);
                    continue;
                }
            }
        }
        Err(anyhow!("all doh lookup attempts failed"))
    }

    /// DNS-over-HTTPS over cleartext HTTP/2 (`h2c://`, `h2c+local://`).
    async fn query_with_doh_h2c(
        &self,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        doh: &DohResolver,
        tag: &str,
    ) -> Result<CacheEntry> {
        for i in 0..*option::MAX_DNS_RETRIES {
            let start = tokio::time::Instant::now();
            debug!(
                "looking up host={} server={} ({}/{})",
                host,
                resolver,
                i + 1,
                *option::MAX_DNS_RETRIES
            );
            let bootstrap_addr = match self
                .resolve_doh_bootstrap_addr(&doh.domain, doh.bootstrap_ip, doh.port)
                .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    debug!("resolve doh bootstrap failed: {}", err);
                    continue;
                }
            };
            let stream = match self.connect_doh_tcp_stream(doh, bootstrap_addr, tag).await {
                Ok(stream) => stream,
                Err(err) => {
                    debug!("connect doh stream failed: {}", err);
                    continue;
                }
            };
            let body = match Self::do_h2c_request(stream, &doh.domain, &doh.path, &request).await {
                Ok(body) => body,
                Err(err) => {
                    debug!("h2c request failed: {}", err);
                    continue;
                }
            };
            let message = match Message::from_vec(&body) {
                Ok(message) => message,
                Err(err) => {
                    debug!("parse h2c dns payload failed: {}", err);
                    continue;
                }
            };
            let elapsed = tokio::time::Instant::now().duration_since(start);
            match Self::message_to_entry(&message, host, &doh.domain) {
                Ok(entry) => {
                    debug!(
                        "received from server={} elapsed={}ms ips={:?}",
                        resolver,
                        elapsed.as_millis(),
                        &entry.ips
                    );
                    return Ok(entry);
                }
                Err(err) => {
                    debug!("bad h2c dns response: {}", err);
                    continue;
                }
            }
        }
        Err(anyhow!("all h2c lookup attempts failed"))
    }

    async fn query_with_doh(
        &self,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        doh: &DohResolver,
        tag: &str,
    ) -> Result<CacheEntry> {
        if doh.is_h2c {
            return self
                .query_with_doh_h2c(request, host, resolver, doh, tag)
                .await;
        }
        #[cfg(feature = "dns-tls")]
        {
            self.query_with_doh_tls(request, host, resolver, doh, tag)
                .await
        }
        #[cfg(not(feature = "dns-tls"))]
        {
            let _ = (request, host, resolver, doh, tag);
            Err(anyhow!("https dns server requires the \"dns-tls\" feature"))
        }
    }

    /// Minimal HTTP/2 (RFC 7540, prior knowledge) client for a single DoH POST.
    async fn do_h2c_request(
        mut stream: AnyStream,
        host: &str,
        path: &str,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const FRAME_DATA: u8 = 0x0;
        const FRAME_HEADERS: u8 = 0x1;
        const FRAME_RST_STREAM: u8 = 0x3;
        const FRAME_SETTINGS: u8 = 0x4;
        const FRAME_PING: u8 = 0x6;
        const FRAME_GOAWAY: u8 = 0x7;
        const FLAG_END_STREAM: u8 = 0x1;
        const FLAG_ACK: u8 = 0x1;
        const FLAG_END_HEADERS: u8 = 0x4;

        fn push_string(buf: &mut Vec<u8>, value: &[u8]) {
            // Only plain (non-Huffman) strings are produced.
            let len = value.len();
            if len < 127 {
                buf.push(len as u8);
            } else {
                buf.push(0x7f);
                let mut len = len - 127;
                while len >= 128 {
                    buf.push(((len & 0x7f) | 0x80) as u8);
                    len >>= 7;
                }
                buf.push(len as u8);
            }
            buf.extend_from_slice(value);
        }

        fn push_indexed_name(buf: &mut Vec<u8>, index: u8, value: &[u8]) {
            if index < 15 {
                buf.push(index);
            } else {
                buf.push(0x0f);
                buf.push(index - 15);
            }
            push_string(buf, value);
        }

        fn push_new_name(buf: &mut Vec<u8>, name: &[u8], value: &[u8]) {
            buf.push(0x00);
            push_string(buf, name);
            push_string(buf, value);
        }

        fn emit_frame(out: &mut Vec<u8>, typ: u8, flags: u8, sid: u32, payload: &[u8]) {
            let len = payload.len();
            out.push(((len >> 16) & 0xff) as u8);
            out.push(((len >> 8) & 0xff) as u8);
            out.push((len & 0xff) as u8);
            out.push(typ);
            out.push(flags);
            out.extend_from_slice(&(sid & 0x7fff_ffff).to_be_bytes());
            out.extend_from_slice(payload);
        }

        // HPACK request header block.
        let mut hpack = Vec::new();
        hpack.push(0x83); // :method = POST (static index 3)
        hpack.push(0x86); // :scheme = http (static index 6)
        push_indexed_name(&mut hpack, 1, host.as_bytes()); // :authority
        push_indexed_name(&mut hpack, 4, path.as_bytes()); // :path
        push_indexed_name(&mut hpack, 31, b"application/dns-message"); // content-type
        push_new_name(&mut hpack, b"accept", b"application/dns-message");
        push_indexed_name(&mut hpack, 28, request.len().to_string().as_bytes()); // content-length

        let mut frame = Vec::with_capacity(PREFACE.len() + 9 + hpack.len() + 9 + request.len());
        frame.extend_from_slice(PREFACE);
        emit_frame(&mut frame, FRAME_SETTINGS, 0, 0, &[]);
        emit_frame(&mut frame, FRAME_HEADERS, FLAG_END_HEADERS, 1, &hpack);
        emit_frame(&mut frame, FRAME_DATA, FLAG_END_STREAM, 1, request);
        stream
            .write_all(&frame)
            .await
            .map_err(|e| anyhow!("write h2c request failed: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| anyhow!("flush h2c request failed: {}", e))?;

        let mut body = Vec::new();
        loop {
            let mut header = [0u8; 9];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|e| anyhow!("read h2c frame header failed: {}", e))?;
            let len =
                ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
            let typ = header[3];
            let flags = header[4];
            let sid = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
            let mut payload = vec![0u8; len];
            if len > 0 {
                stream
                    .read_exact(&mut payload)
                    .await
                    .map_err(|e| anyhow!("read h2c frame payload failed: {}", e))?;
            }
            match typ {
                FRAME_DATA => {
                    if sid == 1 {
                        body.extend_from_slice(&payload);
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                FRAME_HEADERS => {
                    if flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                FRAME_SETTINGS => {
                    if flags & FLAG_ACK == 0 {
                        let mut ack = Vec::with_capacity(9);
                        emit_frame(&mut ack, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                        stream.write_all(&ack).await?;
                    }
                }
                FRAME_PING => {
                    if flags & FLAG_ACK == 0 {
                        let mut ack = Vec::with_capacity(9 + payload.len());
                        emit_frame(&mut ack, FRAME_PING, FLAG_ACK, 0, &payload);
                        stream.write_all(&ack).await?;
                    }
                }
                FRAME_RST_STREAM => return Err(anyhow!("h2c stream reset by server")),
                FRAME_GOAWAY => return Err(anyhow!("h2c connection closed by server")),
                _ => (),
            }
        }

        if body.is_empty() {
            return Err(anyhow!("h2c server returned an empty body"));
        }
        Ok(body)
    }

    /// UDP dispatch helper shared by the plain DNS transports.
    async fn open_udp_socket(
        &self,
        addr: SocketAddr,
        is_direct: bool,
        tag: &str,
    ) -> Result<(Box<dyn OutboundDatagram>, tracing::Span)> {
        // A query being resolved to dial the outbound that is already carrying
        // another query must not be carried itself. See
        // `ROUTED_QUERY_IN_FLIGHT`.
        let is_direct = is_direct || routed_query_in_flight();
        if is_direct {
            let socket = self.new_udp_socket(&addr).await?;
            Ok((
                Box::new(StdOutboundDatagram::new(socket)) as Box<dyn OutboundDatagram>,
                tracing::Span::current(),
            ))
        } else if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
            let source = match addr {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let sess = Session {
                network: Network::Udp,
                source,
                destination: SocksAddr::from(addr),
                inbound_tag: tag.to_string(),
                ..Default::default()
            };
            let span = sess.span();
            if let Some(dispatcher) = dispatcher_weak.upgrade() {
                let datagram = ROUTED_QUERY_IN_FLIGHT
                    .scope(
                        (),
                        dispatcher.dispatch_datagram(sess).instrument(span.clone()),
                    )
                    .await?;
                Ok((datagram, span))
            } else {
                Err(anyhow!("dispatcher is gone"))
            }
        } else {
            Err(anyhow!("no dispatcher"))
        }
    }

    async fn query_udp(
        &self,
        addr: SocketAddr,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        tag: &str,
    ) -> Result<CacheEntry> {
        let (socket, span) = self.open_udp_socket(addr, is_direct, tag).await?;
        self.query_with_socket(socket, request, span, host, addr)
            .await
    }

    async fn query_tcp(
        &self,
        addr: SocketAddr,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        tag: &str,
    ) -> Result<CacheEntry> {
        let mut last_err = anyhow!("tcp query failed");
        for i in 0..*option::MAX_DNS_RETRIES {
            debug!(
                "looking up host={} server=tcp://{} ({}/{})",
                host,
                addr,
                i + 1,
                *option::MAX_DNS_RETRIES
            );
            let stream = match self.open_tcp_stream(addr, is_direct, tag).await {
                Ok(stream) => stream,
                Err(err) => {
                    debug!("connect tcp dns server failed: {}", err);
                    last_err = err;
                    continue;
                }
            };
            match Self::exchange_tcp_message(stream, &request).await {
                Ok(message) => match Self::message_to_entry(&message, host, &addr) {
                    Ok(entry) => return Ok(entry),
                    Err(err) => {
                        debug!("bad tcp dns response: {}", err);
                        last_err = err;
                    }
                },
                Err(err) => {
                    debug!("tcp dns exchange failed: {}", err);
                    last_err = err;
                }
            }
        }
        Err(last_err)
    }

    async fn open_tcp_stream(
        &self,
        addr: SocketAddr,
        is_direct: bool,
        tag: &str,
    ) -> Result<AnyStream> {
        // See `open_udp_socket`: a query resolved under `ROUTED_QUERY_IN_FLIGHT`
        // must not be carried by an outbound.
        let is_direct = is_direct || routed_query_in_flight();
        if is_direct {
            return Ok(Box::new(TcpStream::connect(addr).await?));
        }
        if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
            if let Some(dispatcher) = dispatcher_weak.upgrade() {
                let source = match addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };
                let sess = Session {
                    network: Network::Tcp,
                    source,
                    destination: SocksAddr::from(addr),
                    inbound_tag: tag.to_string(),
                    ..Default::default()
                };
                return ROUTED_QUERY_IN_FLIGHT
                    .scope((), dispatcher.dispatch_stream_outbound(sess))
                    .await
                    .map_err(|e| anyhow!("dispatch stream failed: {}", e));
            }
            return Err(anyhow!("dispatcher is gone"));
        }
        Err(anyhow!("no dispatcher"))
    }

    async fn exchange_tcp_message(mut stream: AnyStream, request: &[u8]) -> Result<Message> {
        let mut framed = Vec::with_capacity(request.len() + 2);
        framed.extend_from_slice(&(request.len() as u16).to_be_bytes());
        framed.extend_from_slice(request);
        stream
            .write_all(&framed)
            .await
            .map_err(|e| anyhow!("write tcp query failed: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| anyhow!("flush tcp query failed: {}", e))?;
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| anyhow!("read tcp response length failed: {}", e))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; len];
        stream
            .read_exact(&mut resp)
            .await
            .map_err(|e| anyhow!("read tcp response failed: {}", e))?;
        Message::from_vec(&resp).map_err(|e| anyhow!("parse tcp dns response failed: {}", e))
    }

    #[cfg(feature = "dns-quic")]
    async fn query_quic(
        &self,
        quic: &QuicResolver,
        request: &[u8],
        host: &str,
    ) -> Result<CacheEntry> {
        let addr = Self::resolve_host_port(&quic.host, quic.port).await?;

        let mut roots = rustls::RootCertStore::empty();
        #[cfg(feature = "webpki-roots")]
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        #[cfg(feature = "rustls-tls-aws-lc")]
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(not(feature = "rustls-tls-aws-lc"))]
        let provider = rustls::crypto::ring::default_provider();

        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!("create quic tls config failed: {}", e))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols.push(b"doq".to_vec());

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| anyhow!("create quic client config failed: {}", e))?,
        ));

        let bind = match addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = self.new_udp_socket(&bind).await?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| anyhow!("create quic endpoint failed: {}", e))?;
        endpoint.set_default_client_config(client_config);

        let connecting = endpoint
            .connect(addr, &quic.host)
            .map_err(|e| anyhow!("connect quic server failed: {}", e))?;
        let conn = connecting
            .await
            .map_err(|e| anyhow!("quic handshake failed: {}", e))?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("open quic stream failed: {}", e))?;

        let mut framed = Vec::with_capacity(request.len() + 2);
        framed.extend_from_slice(&(request.len() as u16).to_be_bytes());
        framed.extend_from_slice(request);
        send.write_all(&framed)
            .await
            .map_err(|e| anyhow!("write quic query failed: {}", e))?;
        let _ = send.finish();

        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| anyhow!("read quic response length failed: {}", e))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; len];
        recv.read_exact(&mut resp)
            .await
            .map_err(|e| anyhow!("read quic response failed: {}", e))?;

        let message = Message::from_vec(&resp)
            .map_err(|e| anyhow!("parse quic dns response failed: {}", e))?;
        let display = format!("quic+local://{}:{}", quic.host, quic.port);
        Self::message_to_entry(&message, host, &display)
    }

    #[cfg(not(feature = "dns-quic"))]
    async fn query_quic(
        &self,
        quic: &QuicResolver,
        _request: &[u8],
        _host: &str,
    ) -> Result<CacheEntry> {
        Err(anyhow!(
            "dns server [quic+local://{}:{}] requires the \"dns-quic\" feature",
            quic.host,
            quic.port
        ))
    }

    async fn query_system(&self, host: &str, ty: RecordType) -> Result<CacheEntry> {
        debug!("resolving {} using system resolver", host);
        let addr = format!("{}:0", host);
        let start = std::time::Instant::now();
        let ips = tokio::task::spawn_blocking(move || {
            addr.to_socket_addrs()
                .map(|iter| iter.map(|x| x.ip()).collect::<Vec<_>>())
        })
        .await
        .map_err(|e| anyhow!("spawn blocking failed: {}", e))?
        .map_err(|e| anyhow!("system resolver failed: {}", e))?;
        let ips: Vec<IpAddr> = ips
            .into_iter()
            .filter(|ip| match ty {
                RecordType::A => ip.is_ipv4(),
                RecordType::AAAA => ip.is_ipv6(),
                _ => true,
            })
            .collect();
        debug!(
            "resolved ips={:?} for domain={} from system resolver in {} ms",
            &ips,
            host,
            start.elapsed().as_millis(),
        );
        if ips.is_empty() {
            return Err(anyhow!("no records from system resolver"));
        }
        Ok(CacheEntry {
            ips,
            deadline: Instant::now() + Duration::from_secs(60),
        })
    }

    async fn query_fakedns(&self, host: &str, ty: RecordType) -> Result<CacheEntry> {
        match ty {
            RecordType::A => (),
            _ => return Err(anyhow!("fakedns only answers A queries")),
        }
        let fakedns = self.fakedns.as_ref().ok_or_else(|| {
            anyhow!("fakedns server is configured but no fake-DNS engine is available")
        })?;
        let ip = fakedns
            .lookup_or_allocate(host)
            .await
            .map_err(|e| anyhow!("fakedns lookup failed for {}: {}", host, e))?;
        Ok(CacheEntry {
            ips: vec![ip],
            deadline: Instant::now() + Duration::from_secs(1),
        })
    }

    async fn resolve_with_server(
        &self,
        client: &NsClient,
        request: Vec<u8>,
        host: &str,
        ty: RecordType,
    ) -> Result<CacheEntry> {
        match &client.resolver {
            Resolver::Server(addr, is_direct) => {
                self.query_udp(*addr, *is_direct, request, host, &client.tag)
                    .await
            }
            Resolver::Tcp(addr, is_direct) => {
                self.query_tcp(*addr, *is_direct, request, host, &client.tag)
                    .await
            }
            Resolver::DoH(doh) => {
                self.query_with_doh(request, host, &client.resolver, doh, &client.tag)
                    .await
            }
            Resolver::Quic(quic) => self.query_quic(quic, &request, host).await,
            Resolver::System(_) => self.query_system(host, ty).await,
            Resolver::FakeDns => self.query_fakedns(host, ty).await,
        }
    }

    async fn query_with_socket(
        &self,
        socket: Box<dyn OutboundDatagram>,
        request: Vec<u8>,
        span: tracing::Span,
        host: &str,
        addr: SocketAddr,
    ) -> Result<CacheEntry> {
        let resolver_addr = SocksAddr::from(addr);
        async move {
            let (mut r, mut s) = socket.split();
            for i in 0..*option::MAX_DNS_RETRIES {
                debug!(
                    "looking up host={} server={} ({}/{})",
                    host,
                    addr,
                    i + 1,
                    *option::MAX_DNS_RETRIES
                );
                let start = tokio::time::Instant::now();

                if let Err(err) = s.send_to(&request, &resolver_addr).await {
                    debug!("send DNS query failed: {}", err);
                    continue;
                }

                let mut buf = vec![0u8; EDNS_UDP_PAYLOAD_SIZE];
                let n = match timeout(
                    Duration::from_secs(*option::DNS_TIMEOUT),
                    r.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _))) => n,
                    Ok(Err(e)) => {
                        debug!("recv DNS response from {} failed: {}", addr, e);
                        continue;
                    }
                    Err(e) => {
                        debug!("recv DNS response from {} failed: {}", addr, e);
                        continue;
                    }
                };

                let resp = match Message::from_vec(&buf[..n]) {
                    Ok(resp) => resp,
                    Err(err) => {
                        debug!("parse DNS message from {} failed: {}", addr, err);
                        break;
                    }
                };

                match Self::message_to_entry(&resp, host, &addr) {
                    Ok(entry) => {
                        let elapsed = tokio::time::Instant::now().duration_since(start);
                        debug!(
                            "received from server={} elapsed={}ms ips={:?}",
                            addr,
                            elapsed.as_millis(),
                            &entry.ips
                        );
                        return Ok(entry);
                    }
                    Err(err) => {
                        debug!("bad DNS response from {}: {}", addr, err);
                        break;
                    }
                }
            }
            Err(anyhow!("all lookup attempts failed"))
        }
        .instrument(span)
        .await
    }

    /// Extracts IPs/TTL from a DNS response, mirroring Xray's `parseResponse`.
    fn message_to_entry(
        message: &Message,
        host: &str,
        server: &dyn fmt::Display,
    ) -> Result<CacheEntry> {
        if message.response_code() != ResponseCode::NoError {
            return Err(anyhow!(
                "error DNS response from {} for {}: {}",
                server,
                host,
                message.response_code()
            ));
        }
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        for ans in message.answers() {
            if let Some(data) = ans.data() {
                match data {
                    RData::A(ip) => {
                        ips.push(IpAddr::V4(**ip));
                        ttl = ttl.min(ans.ttl());
                    }
                    RData::AAAA(ip) => {
                        ips.push(IpAddr::V6(**ip));
                        ttl = ttl.min(ans.ttl());
                    }
                    _ => (),
                }
            }
        }
        if ips.is_empty() {
            return Err(anyhow!(
                "no records in DNS response from {} for {}",
                server,
                host
            ));
        }
        if ttl == u32::MAX {
            ttl = 1;
        }
        let Some(deadline) = Instant::now().checked_add(Duration::from_secs(ttl.into())) else {
            return Err(anyhow!("invalid ttl"));
        };
        Ok(CacheEntry { ips, deadline })
    }

    fn build_edns_ecs(client_ip: IpAddr) -> Edns {
        let (family, netmask, mask): (u16, u8, Vec<u8>) = match client_ip {
            IpAddr::V4(ip) => (1, 24, ip.octets()[..3].to_vec()),
            IpAddr::V6(ip) => (2, 96, ip.octets()[..12].to_vec()),
        };
        let mut data = Vec::with_capacity(4 + mask.len());
        data.extend_from_slice(&family.to_be_bytes());
        data.push(netmask);
        data.push(0);
        data.extend_from_slice(&mask);
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_UDP_PAYLOAD_SIZE as u16)
            .set_version(0);
        edns.options_mut().insert(EdnsOption::Unknown(8, data));
        edns
    }

    fn new_query(name: Name, ty: RecordType, client_ip: Option<IpAddr>) -> Message {
        let mut msg = Message::new();
        msg.add_query(Query::query(name, ty));
        let mut rng = StdRng::from_entropy();
        let id: u16 = rng.gen();
        msg.set_id(id);
        msg.set_op_code(OpCode::Query);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        if let Some(client_ip) = client_ip {
            msg.set_edns(Self::build_edns_ecs(client_ip));
        }
        msg
    }

    fn extract_ech_config_list(rdata: &str) -> Option<String> {
        fn extract_quoted(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let value_start = start + key.len();
            let rest = &haystack[value_start..];
            let end = rest.find('"')?;
            let value = rest[..end].trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }

        fn extract_plain(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let value_start = start + key.len();
            let rest = &haystack[value_start..];
            let end = rest
                .find(|c: char| c.is_ascii_whitespace() || c == ',')
                .unwrap_or(rest.len());
            let value = rest[..end].trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }

        extract_quoted(rdata, "echconfig=\"")
            .or_else(|| extract_quoted(rdata, "ech=\""))
            .or_else(|| extract_plain(rdata, "echconfig="))
            .or_else(|| extract_plain(rdata, "ech="))
    }

    async fn query_ech_with_doh(
        &self,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        doh: &DohResolver,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        if doh.is_h2c {
            return Err(anyhow!("h2c does not support ECH queries"));
        }
        #[cfg(feature = "dns-tls")]
        {
            for _ in 0..*option::MAX_DNS_RETRIES {
                let bootstrap_addr = match self
                    .resolve_doh_bootstrap_addr(&doh.domain, doh.bootstrap_ip, doh.port)
                    .await
                {
                    Ok(addr) => addr,
                    Err(err) => {
                        debug!("resolve doh bootstrap failed: {}", err);
                        continue;
                    }
                };
                let stream = match self
                    .connect_doh_tcp_stream(doh, bootstrap_addr, "dnsclient")
                    .await
                {
                    Ok(stream) => stream,
                    Err(err) => {
                        debug!("connect doh stream failed: {}", err);
                        continue;
                    }
                };
                let mut stream = match Self::wrap_doh_tls_stream(stream, &doh.domain).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        debug!("connect doh tls failed: {}", err);
                        continue;
                    }
                };
                let request_header =
                    Self::build_doh_http_request(&doh.domain, &doh.path, request.len());
                if stream.write_all(request_header.as_bytes()).await.is_err() {
                    continue;
                }
                if stream.write_all(&request).await.is_err() {
                    continue;
                }
                if stream.flush().await.is_err() {
                    continue;
                }
                let mut resp = Vec::new();
                if stream.read_to_end(&mut resp).await.is_err() {
                    continue;
                }
                let payload = match Self::parse_doh_http_body(&resp) {
                    Ok(body) => body,
                    Err(err) => {
                        debug!("parse doh http response failed: {}", err);
                        continue;
                    }
                };
                let message = match Message::from_vec(&payload) {
                    Ok(message) => message,
                    Err(err) => {
                        debug!("parse doh dns payload failed: {}", err);
                        continue;
                    }
                };
                return Self::ech_entry_from_message(&message, host, resolver, ty);
            }
            Err(anyhow!("all doh ech lookup attempts failed"))
        }
        #[cfg(not(feature = "dns-tls"))]
        {
            let _ = (request, host, resolver, ty);
            Err(anyhow!("https dns server requires the \"dns-tls\" feature"))
        }
    }

    fn ech_entry_from_message(
        message: &Message,
        host: &str,
        server: &dyn fmt::Display,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        if message.response_code() != ResponseCode::NoError {
            return Err(anyhow!(
                "error DNS response from {} for {}: {}",
                server,
                host,
                message.response_code()
            ));
        }
        let mut last_ttl = None;
        for ans in message.answers() {
            if ans.record_type() != ty {
                continue;
            }
            if let Some(data) = ans.data() {
                last_ttl = Some(ans.ttl());
                let value = data.to_string();
                if let Some(ech_config_list) = Self::extract_ech_config_list(&value) {
                    let ttl = ans.ttl();
                    let Some(deadline) =
                        Instant::now().checked_add(Duration::from_secs(ttl.into()))
                    else {
                        return Err(anyhow!("invalid ttl"));
                    };
                    return Ok(EchCacheEntry {
                        ech_config_list,
                        deadline,
                    });
                }
            }
        }
        if last_ttl.is_some() {
            return Err(anyhow!(
                "missing ech parameter in {} record for {} from {}",
                ty,
                host,
                server
            ));
        }
        Err(anyhow!("no {} records for {} from {}", ty, host, server))
    }

    async fn query_ech_with_socket(
        &self,
        socket: Box<dyn OutboundDatagram>,
        request: Vec<u8>,
        span: tracing::Span,
        host: &str,
        addr: SocketAddr,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let resolver_addr = SocksAddr::from(addr);
        async move {
            let (mut r, mut s) = socket.split();
            for i in 0..*option::MAX_DNS_RETRIES {
                debug!(
                    "fetching ech host={} type={} server={} ({}/{})",
                    host,
                    ty,
                    addr,
                    i + 1,
                    *option::MAX_DNS_RETRIES
                );
                if let Err(err) = s.send_to(&request, &resolver_addr).await {
                    debug!("send DNS ech query failed: {}", err);
                    continue;
                }
                let mut buf = vec![0u8; EDNS_UDP_PAYLOAD_SIZE];
                let n = match timeout(
                    Duration::from_secs(*option::DNS_TIMEOUT),
                    r.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _))) => n,
                    Ok(Err(e)) => {
                        debug!("recv DNS ech response from {} failed: {}", addr, e);
                        continue;
                    }
                    Err(e) => {
                        debug!("recv DNS ech response from {} failed: {}", addr, e);
                        continue;
                    }
                };
                let resp = match Message::from_vec(&buf[..n]) {
                    Ok(resp) => resp,
                    Err(err) => {
                        debug!("parse DNS ech message from {} failed: {}", addr, err);
                        break;
                    }
                };
                match Self::ech_entry_from_message(&resp, host, &addr, ty) {
                    Ok(entry) => return Ok(entry),
                    Err(e) => {
                        debug!("bad DNS ech response from {}: {}", addr, e);
                        break;
                    }
                }
            }
            Err(anyhow!("all ech lookup attempts failed"))
        }
        .instrument(span)
        .await
    }

    async fn resolve_ech_with_server(
        &self,
        client: &NsClient,
        request: Vec<u8>,
        host: &str,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        match &client.resolver {
            Resolver::Server(addr, is_direct) => {
                let (socket, span) = self.open_udp_socket(*addr, *is_direct, &client.tag).await?;
                self.query_ech_with_socket(socket, request, span, host, *addr, ty)
                    .await
            }
            Resolver::DoH(doh) => {
                self.query_ech_with_doh(request, host, &client.resolver, doh, ty)
                    .await
            }
            _ => Err(anyhow!("server {} does not support ECH queries", client)),
        }
    }

    async fn query_ech_record_type(
        &self,
        is_direct: bool,
        name: &Name,
        host: &str,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let msg = Self::new_query(name.clone(), ty, self.client_ip);
        let msg_buf = match msg.to_vec() {
            Ok(buf) => buf,
            Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
        };
        let candidates = self.collect_servers(is_direct);
        if candidates.is_empty() {
            return Err(anyhow!("no dns servers available for query"));
        }
        let ordered = self.sort_clients(host, &candidates);
        let mut errs = Vec::new();
        for client in &ordered {
            match timeout(
                client.timeout,
                self.resolve_ech_with_server(client, msg_buf.clone(), host, ty),
            )
            .await
            {
                Ok(Ok(entry)) => return Ok(entry),
                Ok(Err(e)) => errs.push(e),
                Err(_) => errs.push(anyhow!("query {} {} timeout", host, ty)),
            }
        }
        Err(merge_query_errors(errs))
    }

    async fn query_ech(&self, host: &str, is_direct: bool) -> Result<EchCacheEntry> {
        let mut fqdn = host.to_owned();
        fqdn.push('.');
        let name = match Name::from_str(&fqdn) {
            Ok(n) => n,
            Err(e) => return Err(anyhow!("invalid domain name [{}]: {}", host, e)),
        };
        let https_res = self
            .query_ech_record_type(is_direct, &name, host, RecordType::HTTPS)
            .await;
        match https_res {
            Ok(entry) => Ok(entry),
            Err(https_err) => {
                let svcb_res = self
                    .query_ech_record_type(is_direct, &name, host, RecordType::SVCB)
                    .await;
                match svcb_res {
                    Ok(entry) => Ok(entry),
                    Err(svcb_err) => Err(anyhow!(
                        "ech query failed for {} with HTTPS ({}) and SVCB ({})",
                        host,
                        https_err,
                        svcb_err
                    )),
                }
            }
        }
    }

    pub async fn lookup_ech_config_list(&self, host: &str) -> Result<String> {
        if let Some(cached) = self.get_cached_ech(host).await {
            return Ok(cached);
        }
        let host_lock = {
            let mut locks = self.ech_query_locks.lock().await;
            locks
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };
        let _query_guard = host_lock.lock().await;
        let result = if let Some(cached) = self.get_cached_ech(host).await {
            Ok(cached)
        } else {
            let entry = self.query_ech(host, true).await?;
            let ech_config_list = entry.ech_config_list.clone();
            self.ech_cache.lock().await.put(host.to_owned(), entry);
            Ok(ech_config_list)
        };
        {
            let mut locks = self.ech_query_locks.lock().await;
            if let Some(current) = locks.get(host) {
                if Arc::ptr_eq(current, &host_lock) {
                    locks.remove(host);
                }
            }
        }
        result
    }

    // ------------------------------------------------------------- selection

    fn collect_servers(&self, is_direct: bool) -> Vec<&NsClient> {
        let mut servers = Vec::new();
        for server in &self.servers {
            if server.is_direct() == is_direct {
                servers.push(server);
            }
        }
        if servers.is_empty() {
            for server in &self.servers {
                servers.push(server);
            }
        }
        servers
    }

    fn base_ip_option(&self) -> IpOption {
        let mut option = self.query_strategy.ip_option();
        if !*crate::option::ENABLE_IPV6 {
            option.ipv6 = false;
        }
        option
    }

    fn filter_entry(&self, client: &NsClient, mut entry: CacheEntry) -> CacheEntry {
        if let Some(expected) = &client.expected {
            if !client.act_prior {
                entry.ips = expected.filter(&entry.ips).0;
                if entry.ips.is_empty() {
                    return entry;
                }
            }
        }
        if let Some(unexpected) = &client.unexpected {
            if !client.act_unprior {
                entry.ips = unexpected.filter(&entry.ips).1;
                if entry.ips.is_empty() {
                    return entry;
                }
            }
        }
        if let Some(expected) = &client.expected {
            if client.act_prior {
                let matched = expected.filter(&entry.ips).0;
                if !matched.is_empty() {
                    entry.ips = matched;
                }
            }
        }
        if let Some(unexpected) = &client.unexpected {
            if client.act_unprior {
                let unmatched = unexpected.filter(&entry.ips).1;
                if !unmatched.is_empty() {
                    entry.ips = unmatched;
                }
            }
        }
        entry
    }

    async fn query_task(
        &self,
        client: &NsClient,
        request: Vec<u8>,
        host: &str,
        ty: RecordType,
    ) -> Result<CacheEntry> {
        debug!(
            "query {} {} via {} (tag={})",
            host,
            ty,
            client.display_name(),
            client.tag,
        );
        let entry = match timeout(
            client.timeout,
            self.resolve_with_server(client, request, host, ty),
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => return Err(anyhow!("query {} {} timeout", host, ty)),
        };
        let entry = self.filter_entry(client, entry);
        if entry.ips.is_empty() {
            return Err(anyhow!(
                "no addresses for {} from {} after ip filtering",
                host,
                client
            ));
        }
        Ok(entry)
    }

    async fn query_record_type(
        &self,
        is_direct: bool,
        name: &Name,
        host: &str,
        ty: RecordType,
        base: IpOption,
    ) -> Result<CacheEntry> {
        let msg = Self::new_query(name.clone(), ty, self.client_ip);
        let msg_buf = match msg.to_vec() {
            Ok(buf) => buf,
            Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
        };

        let candidates = self.collect_servers(is_direct);
        if candidates.is_empty() {
            return Err(anyhow!("no dns servers available for query"));
        }

        let mut usable = Vec::new();
        for client in candidates {
            if matches!(ty, RecordType::AAAA) && matches!(client.resolver, Resolver::FakeDns) {
                continue;
            }
            let option = client.ip_option(base);
            let enabled = match ty {
                RecordType::A => option.ipv4,
                RecordType::AAAA => option.ipv6,
                _ => true,
            };
            if enabled {
                usable.push(client);
            }
        }
        if usable.is_empty() {
            return Err(anyhow!("no dns servers support the {} query", ty));
        }

        let ordered = self.sort_clients(host, &usable);
        if ordered.is_empty() {
            return Err(anyhow!("no dns servers available for query"));
        }

        if self.enable_parallel_query {
            self.parallel_query(&ordered, host, ty, &msg_buf).await
        } else {
            self.serial_query(&ordered, host, ty, &msg_buf).await
        }
    }

    async fn dualstack_query<P, F>(
        &self,
        preferred: &mut P,
        fallback: &mut F,
        delay: Duration,
    ) -> Result<(CacheEntry, Option<CacheEntry>)>
    where
        P: Future<Output = Result<CacheEntry>> + Unpin,
        F: Future<Output = Result<CacheEntry>> + Unpin,
    {
        let delay_fut = tokio::time::sleep(delay);
        tokio::pin!(delay_fut);

        let first = tokio::select! {
            biased;
            r = &mut *preferred => Some((true, r)),
            _ = &mut delay_fut => None,
        };

        let (first_is_preferred, first_res) = match first {
            Some(v) => v,
            None => tokio::select! {
                r = &mut *preferred => (true, r),
                r = &mut *fallback => (false, r),
            },
        };

        match first_res {
            Ok(entry) => {
                let other = if first_is_preferred {
                    match timeout(Duration::from_millis(0), &mut *fallback).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                } else {
                    match timeout(Duration::from_millis(0), &mut *preferred).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                };
                Ok((entry, other))
            }
            Err(err1) => {
                let second_res = if first_is_preferred {
                    (&mut *fallback).await
                } else {
                    (&mut *preferred).await
                };
                match second_res {
                    Ok(entry) => Ok((entry, None)),
                    Err(err2) => Err(anyhow!("all dns queries failed: {}; {}", err1, err2)),
                }
            }
        }
    }

    // ---------------------------------------------------------------- lookup

    pub async fn lookup(&self, host: &String) -> Result<Vec<IpAddr>> {
        self._lookup(host, false).await
    }

    pub async fn direct_lookup(&self, host: &String) -> Result<Vec<IpAddr>> {
        self._lookup(host, true).await
    }

    #[async_recursion]
    pub async fn _lookup(&self, host: &String, is_direct: bool) -> Result<Vec<IpAddr>> {
        self._lookup_inner(host, is_direct).await
    }

    async fn _lookup_inner(&self, host: &String, is_direct: bool) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if !self.disable_cache {
            if let Ok(ips) = self.get_cached(host).await {
                return Ok(ips);
            }
        }

        // Making cache lookup a priority rather than static hosts lookup
        // and insert the static IPs to the cache because there's a chance
        // for the IPs in the cache to be re-ordered.
        if !self.hosts.is_empty() {
            if let Some(ips) = self.hosts.get(host) {
                if !ips.is_empty() {
                    if ips.len() > 1 && !self.disable_cache {
                        let deadline = Instant::now()
                            .checked_add(Duration::from_secs(6000))
                            .unwrap();
                        self.cache_insert(
                            host,
                            CacheEntry {
                                ips: ips.clone(),
                                deadline,
                            },
                        )
                        .await;
                    }
                    return Ok(ips.to_vec());
                }
            }
        }

        let base = self.base_ip_option();
        if base.is_empty() {
            return Err(anyhow!("no address family enabled for query"));
        }

        let mut fqdn = host.to_owned();
        fqdn.push('.');
        let name = match Name::from_str(&fqdn) {
            Ok(n) => n,
            Err(e) => return Err(anyhow!("invalid domain name [{}]: {}", host, e)),
        };

        if base.ipv6 {
            let delay = Duration::from_millis(*crate::option::DNS_DUALSTACK_DELAY_MS);
            let mut a_fut =
                Box::pin(self.query_record_type(is_direct, &name, host, RecordType::A, base));
            let mut aaaa_fut =
                Box::pin(self.query_record_type(is_direct, &name, host, RecordType::AAAA, base));

            let (first, second) = if *crate::option::PREFER_IPV6 {
                self.dualstack_query(&mut aaaa_fut, &mut a_fut, delay)
                    .await?
            } else {
                self.dualstack_query(&mut a_fut, &mut aaaa_fut, delay)
                    .await?
            };

            let mut ips = first.ips.clone();
            self.cache_insert(host, first).await;
            if let Some(second) = second {
                ips.extend_from_slice(&second.ips);
                self.cache_insert(host, second).await;
            }
            if !ips.is_empty() {
                return Ok(ips);
            }
            return Err(anyhow!("could not resolve to any address"));
        }

        let entry = self
            .query_record_type(is_direct, &name, host, RecordType::A, base)
            .await?;
        let ips = entry.ips.clone();
        self.cache_insert(host, entry).await;
        if !ips.is_empty() {
            return Ok(ips);
        }
        Err(anyhow!("could not resolve to any address"))
    }
}

impl UdpConnector for DnsClient {}
include!("client/tests.rs");
