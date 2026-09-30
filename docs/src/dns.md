# DNS

leaf ships an Xray-aligned DNS client. Nameserver addresses use Xray's address
grammar, and the top-level `dns` block maps onto the internal `Dns`/`DnsServer`
types. YAML and JSON share the same document; the clash-style `.conf` format
exposes only a small subset.

## Server address grammar

A server entry is either a bare string or an object with options. The string is
parsed by `DnsClient::parse_server` (`leaf/src/app/dns/client.rs`):

| Address form | Transport | Default port |
|---|---|---|
| `host[:port]` (bare IP) | classic UDP DNS | 53 |
| `udp://host[:port]` | UDP | 53 |
| `tcp://host[:port]` | TCP | 53 |
| `tcp+local://host[:port]` | TCP, direct (bypasses routing) | 53 |
| `https://host[:port][/path]` | DoH over TLS | 443 |
| `https://host[:port][/path]` + `https+local://…` | DoH over TLS, direct | 443 |
| `h2c://host[:port][/path]` + `h2c+local://…` | cleartext HTTP/2 DoH | 80 |
| `quic+local://host[:port]` | DNS-over-QUIC | 853 |
| `doh:domain[@bootstrap-ip]` | legacy DoH spelling, path `/dns-query` | 443 |
| `localhost`, `system` | the OS resolver | — |
| `fakedns` | the in-process fake-DNS engine registered by a TUN inbound (see below) | — |

A `direct:` prefix (for example `direct:1.1.1.1`) marks any of the above as
direct, bypassing the router. Transports are feature-gated: `https://` and
`doh:` require `dns-tls`; `quic+local://` requires `dns-quic`.

**`fakedns` resolves through the in-process engine.** A `fakedns` entry is
accepted unconditionally and kept in the server list (it is not skipped). The
`FakeDns` engine is created and owned by a TUN inbound, and `leaf::start` hands
it to the DNS client, so `fakedns` answers A queries from that engine. When no
engine is registered, the query fails with the named error
`fakedns server is configured but no fake-DNS engine is available` and falls
through to the remaining servers, which keeps the ordering
`servers: ["fakedns", "<real server>"]` resolvable either way.

**Not supported:** `tls://`, `h3://`, `dhcp://`, `udp+local://`, and `quic://`
without `+local`. These produce `unsupported dns server scheme` at load time.
When no servers are configured a single `1.1.1.1` UDP server is injected.

## Global options

```yaml
dns:
  servers:
    - 1.1.1.1
    - 8.8.8.8
  hosts:
    example.com:
      - 127.0.0.1
  clientIp: 1.2.3.4
  queryStrategy: UseIP
  tag: dnsclient
  disableCache: false
  serveStale: true
  serveExpiredTTL: 3600
  disableFallback: false
  disableFallbackIfMatch: true
  enableParallelQuery: true
  useSystemHosts: true
```

| Key | Alias | Meaning |
|---|---|---|
| `servers` | — | Name server entries (string or object form). |
| `hosts` | — | Static name → IP list, checked after the cache and before a live query. Config entries win over system hosts. |
| `clientIp` | `client_ip` | Adds EDNS Client Subnet to queries (IPv4 `/24`, IPv6 `/96`). Empty disables it. |
| `tag` | — | Default server tag, `dnsclient` by default. |
| `queryStrategy` | `query_strategy` | Family selection, `UseIP` by default (see below). |
| `disableCache` | `disable_cache` | Disable both cache reads and writes (default false). |
| `serveStale` | `serve_stale` | Serve expired cache entries (default false). |
| `serveExpiredTTL` | `serve_expired_ttl` | Maximum staleness in seconds; `0` means unlimited. |
| `disableFallback` | `disable_fallback` | Do not append unmatched servers as a fallback list. |
| `disableFallbackIfMatch` | `disable_fallback_if_match` | Suppress fallback only when a domain rule matched. |
| `enableParallelQuery` | `enable_parallel_query` | Race equivalent servers group-by-group instead of querying them in order. |
| `useSystemHosts` | `use_system_hosts` | Merge the OS hosts file (config `hosts` take precedence). |

All global keys above are honoured. Unknown keys are silently ignored.

### Query strategy

`queryStrategy` accepts, case-insensitively, `UseIP`, `UseIPv4`, `UseIPv6` and
`UseSystem` (underscore and hyphen spellings such as `use-ip4` also work).
`UseIPv4`/`UseIPv6` narrow the query to a single address family; `UseIP` and
`UseSystem` query both. Any unrecognised value falls back to `UseIP`. There is no
`PreferIPv4`/`PreferIPv6`.

### Cache, timeouts and retries

These are not config keys; they are environment-driven:

| Env var | Default | Meaning |
|---|---|---|
| `DNS_CACHE_SIZE` | 512 (64 on iOS) | Cache entry count. |
| `DNS_TIMEOUT` | 4 s | Query timeout. |
| `MAX_DNS_RETRIES` | 4 | Retry count. |
| `DNS_DUALSTACK_DELAY_MS` | 250 ms | Delay before the second family. |
| `PREFER_IPV6` | false | Prefer AAAA answers when ordering dual-stack results. |

IPv6 is only used when the build enables it (`ENABLE_IPV6`).

## Per-server options

A server entry may be an object instead of a plain string:

```yaml
dns:
  servers:
    - address: https://dns.google/dns-query
      domains:
        - domain:google.com
      expectedIPs:
        - 8.8.8.8
        - 8.8.4.4
      unexpectedIPs:
        - 10.0.0.0/8
      queryStrategy: UseIPv4
      timeoutMs: 3000
      skipFallback: false
      finalQuery: false
      tag: dnsclient
```

| Key | Alias | Meaning |
|---|---|---|
| `address` | — | The address string parsed by the grammar above. |
| `port` | — | Overrides the transport default port. |
| `domains` | — | Domain rules that select this server; see below. |
| `expectedIPs` | `expectIPs`, `expected_ips` | Keep/prioritise answers matching these CIDRs or `geoip:`/`ext:` rules. A literal `*` switches to "prioritise matched" mode. |
| `unexpectedIPs` | `unexpected_ips` | Drop/unprioritise answers matching these rules. A literal `*` switches to "unprioritise matched" mode. |
| `queryStrategy` | `query_strategy` | Per-server family override. |
| `timeoutMs` | `timeout_ms` | Per-query timeout (only when `> 0`). |
| `skipFallback` | `skip_fallback` | Exclude this server from the implicit fallback list. |
| `finalQuery` | `final_query` | Truncate the ordered server list after this server — no fallback. |
| `disableCache` | `disable_cache` | **Rejected** per server (global only) — see the note below. |
| `serveStale` | `serve_stale` | **Rejected** per server (global only). |
| `serveExpiredTTL` | `serve_expired_ttl` | **Rejected** per server (global only). |
| `tag` | — | Overrides the global tag for this server. |

`domains` entries accept a `full:` / `domain:` / `keyword:` / `regexp:` prefix
(or a bare rule, which is a plain case-insensitive substring match). `regexp:`
rules require the `regex` cargo feature.

> Per-server `disableCache`, `serveStale` and `serveExpiredTTL` are **rejected**
> at load: the cache is a single global LRU keyed by host, and stale-serving is
> decided before a server is selected, so per-server semantics cannot be
> honoured. A server entry carrying any of them is skipped with a warning rather
> than silently treated as the global option.

## Server selection

For each query the candidate servers are ordered: system servers first gain the
implicit local TLD rules (`local`, `localdomain`, `localhost`, `lan`,
`home.arpa`, `example`, `invalid`, `test`, …); explicit domain rules match in
server order; a `finalQuery` server
truncates the list; the remaining non-`skipFallback` servers are appended as the
fallback list unless `disableFallback` or `disableFallbackIfMatch` suppressed it.
With `enableParallelQuery` set, adjacent servers that share a selection policy
are raced as a group and the first successful group wins; otherwise servers are
queried one by one.

Expired cache entries are served only when the **global** `serveStale` is set and
within the **global** `serveExpiredTTL`.

## JSON

The JSON form uses the same keys:

```json
{
  "dns": {
    "servers": [
      "1.1.1.1",
      { "address": "https://dns.google/dns-query", "domains": ["domain:google.com"], "expectedIPs": ["8.8.8.8"] }
    ],
    "hosts": { "example.com": ["127.0.0.1"] },
    "clientIp": "1.2.3.4",
    "serveStale": true,
    "serveExpiredTTL": 3600,
    "useSystemHosts": true
  }
}
```

## clash-style `.conf`

The `.conf` format has no `dns:` block. Servers come from the `[General]`
`dns-server` list (bare addresses only) and static names from `[Host]`. None of
the other options are available:

```conf
[General]
dns-server = 1.1.1.1, 8.8.8.8

[Host]
example.com = 127.0.0.1
```
