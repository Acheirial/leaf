// Domain rules, IP rules and query strategies for the DNS client.
//
// Textually included into the `client` module by `include!("client/rules.rs")`,
// so every item here shares the module scope and the `use` statements of
// `client.rs`.

/// A single domain matching rule, mirroring Xray's `geodata.Domain` kinds.
#[derive(Clone, Debug)]
enum DomainRule {
    /// `full:` — the domain must be exactly this value.
    Full(String),
    /// `domain:` — the domain must be this value or a subdomain of it.
    Domain(String),
    /// `keyword:` — the domain must contain this value.
    Keyword(String),
    /// Bare rules default to Xray's `Domain_Substr`, a substring match.
    Substr(String),
    /// Matches a domain that contains no dot at all (`^[^.]+$`).
    Dotless,
    /// `regexp:` — the domain must match this regular expression.
    #[cfg(feature = "regex")]
    Regexp(String, regex::Regex),
}

impl DomainRule {
    fn parse(rule: &str) -> Result<Self> {
        if let Some(v) = rule.strip_prefix("full:") {
            return Ok(Self::Full(v.to_owned()));
        }
        if let Some(v) = rule.strip_prefix("domain:") {
            return Ok(Self::Domain(v.to_owned()));
        }
        if let Some(v) = rule.strip_prefix("keyword:") {
            return Ok(Self::Keyword(v.to_owned()));
        }
        if let Some(v) = rule.strip_prefix("regexp:") {
            #[cfg(feature = "regex")]
            {
                let regex = regex::Regex::new(v)
                    .map_err(|e| anyhow!("invalid domain regexp [{}]: {}", v, e))?;
                return Ok(Self::Regexp(v.to_owned(), regex));
            }
            #[cfg(not(feature = "regex"))]
            {
                return Err(anyhow!(
                    "regexp domain rule [{}] requires the \"regex\" feature",
                    v
                ));
            }
        }
        Ok(Self::Substr(rule.to_owned()))
    }

    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(v) => domain == v,
            Self::Domain(v) => is_sub_domain(domain, v),
            Self::Keyword(v) | Self::Substr(v) => domain.contains(v.as_str()),
            Self::Dotless => !domain.contains('.'),
            #[cfg(feature = "regex")]
            Self::Regexp(_, regex) => regex.is_match(domain),
        }
    }
}

/// The rules Xray attaches to every local (system) name server so that plain
/// host names and local-only TLDs are resolved by the system resolver first.
fn local_domain_rules() -> Vec<DomainRule> {
    vec![
        DomainRule::Dotless,
        DomainRule::Domain("local".to_owned()),
        DomainRule::Domain("localdomain".to_owned()),
        DomainRule::Domain("localhost".to_owned()),
        DomainRule::Domain("lan".to_owned()),
        DomainRule::Domain("home.arpa".to_owned()),
        DomainRule::Domain("example".to_owned()),
        DomainRule::Domain("invalid".to_owned()),
        DomainRule::Domain("test".to_owned()),
    ]
}

fn parse_domain_rules(rules: &[String]) -> Result<Vec<DomainRule>> {
    let mut parsed = Vec::with_capacity(rules.len());
    for rule in rules {
        parsed.push(DomainRule::parse(rule)?);
    }
    Ok(parsed)
}

// test if domain1 is a subdomain of domain2
// examples:
//   video.google.com vs google.com -> true
//   video.google.com vs gle.com -> false
//   google.com vs video.google.com -> false
fn is_sub_domain(d1: &str, d2: &str) -> bool {
    let d1_parts: Vec<&str> = d1.split('.').rev().collect();
    let d2_parts: Vec<&str> = d2.split('.').rev().collect();
    if d1_parts.len() < d2_parts.len() {
        return false;
    }
    for (i, v) in d2_parts.iter().enumerate() {
        if &d1_parts[i] != v {
            return false;
        }
    }
    true
}

/// Xray's global/per-server `queryStrategy` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryStrategy {
    UseIp,
    UseIpv4,
    UseIpv6,
    UseSystem,
}

impl QueryStrategy {
    /// The accepted spellings, mirroring Xray's `resolveQueryStrategy`. An
    /// unknown value falls back to `UseIp` just like Xray does.
    fn parse(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "useip" | "use_ip" | "use-ip" => Self::UseIp,
            "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4"
            | "use-ipv4" | "use-ip-v4" => Self::UseIpv4,
            "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6"
            | "use-ipv6" | "use-ip-v6" => Self::UseIpv6,
            "usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys" | "use-system" => {
                Self::UseSystem
            }
            _ => Self::UseIp,
        }
    }

    /// The base family option a global strategy enables.
    fn ip_option(&self) -> IpOption {
        match self {
            Self::UseIp | Self::UseSystem => IpOption::new(true, true),
            Self::UseIpv4 => IpOption::new(true, false),
            Self::UseIpv6 => IpOption::new(false, true),
        }
    }
}

/// Which address families a query is allowed to return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IpOption {
    ipv4: bool,
    ipv6: bool,
}

impl IpOption {
    fn new(ipv4: bool, ipv6: bool) -> Self {
        IpOption { ipv4, ipv6 }
    }

    fn is_empty(&self) -> bool {
        !self.ipv4 && !self.ipv6
    }

    /// Xray's `ResolveIpOptionOverride`: narrow the base options with a
    /// per-server strategy. `UseIp`/`UseSystem` keep the base untouched.
    fn override_with(&self, strategy: QueryStrategy) -> Self {
        match strategy {
            QueryStrategy::UseIp | QueryStrategy::UseSystem => *self,
            QueryStrategy::UseIpv4 => IpOption {
                ipv4: self.ipv4,
                ipv6: false,
            },
            QueryStrategy::UseIpv6 => IpOption {
                ipv4: false,
                ipv6: self.ipv6,
            },
        }
    }
}

/// CIDR/`geoip:` matcher used for `expectedIPs` / `unexpectedIPs`.
#[derive(Clone)]
struct IpMatcher {
    cidrs: Vec<cidr::IpCidr>,
    geo_code: Option<String>,
    geo_reader: Option<Arc<maxminddb::Reader<maxminddb::Mmap>>>,
}

impl IpMatcher {
    /// Parses the rule list, returning the matcher (possibly empty) and
    /// whether a literal `"*"` entry was present. `"*"` is not a rule by
    /// itself: it flips the caller into "prioritise"/"unprioritise" mode.
    fn parse(rules: &[String]) -> Result<(Option<Self>, bool)> {
        let mut cidrs = Vec::new();
        let mut geo_code = None;
        let mut geo_reader = None;
        let mut match_all = false;
        for rule in rules {
            let rule = rule.trim();
            if rule.is_empty() {
                continue;
            }
            if rule == "*" {
                match_all = true;
                continue;
            }
            if let Some(code) = rule
                .strip_prefix("geoip:")
                .or_else(|| rule.strip_prefix("ext:"))
            {
                if code.is_empty() {
                    return Err(anyhow!("invalid geoip rule [{}]", rule));
                }
                let code = code
                    .rsplit(':')
                    .next()
                    .unwrap_or(code)
                    .to_owned();
                if geo_reader.is_none() {
                    geo_reader = Some(Self::load_geo_reader(&code)?);
                }
                geo_code = Some(code);
                continue;
            }
            match rule.parse::<cidr::IpCidr>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(e) => return Err(anyhow!("invalid ip rule [{}]: {}", rule, e)),
            }
        }
        if cidrs.is_empty() && geo_code.is_none() {
            return Ok((None, match_all));
        }
        Ok((
            Some(IpMatcher {
                cidrs,
                geo_code,
                geo_reader,
            }),
            match_all,
        ))
    }

    fn load_geo_reader(_code: &str) -> Result<Arc<maxminddb::Reader<maxminddb::Mmap>>> {
        let path = std::path::Path::new(&*crate::option::ASSET_LOCATION).join("geo.mmdb");
        let reader = maxminddb::Reader::open_mmap(&path)
            .map_err(|e| anyhow!("open geo mmdb [{}] failed: {}", path.display(), e))?;
        Ok(Arc::new(reader))
    }

    fn matches(&self, ip: &IpAddr) -> bool {
        for cidr in &self.cidrs {
            if cidr.contains(ip) {
                return true;
            }
        }
        if let (Some(code), Some(reader)) = (&self.geo_code, &self.geo_reader) {
            if let Ok(country) = reader.lookup::<maxminddb::geoip2::Country>(*ip) {
                if let Some(country) = country.country {
                    if let Some(iso_code) = country.iso_code {
                        if iso_code.eq_ignore_ascii_case(code) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Splits `ips` into (matched, unmatched), like Xray's `FilterIPs`.
    fn filter(&self, ips: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
        let mut matched = Vec::new();
        let mut unmatched = Vec::new();
        for ip in ips {
            if self.matches(ip) {
                matched.push(*ip);
            } else {
                unmatched.push(*ip);
            }
        }
        (matched, unmatched)
    }
}
