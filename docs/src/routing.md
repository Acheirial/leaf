# Routing

The router maps a session to an outbound. Rules are evaluated **in config order
and the first match wins**; if no rule matches, the outbound manager's default
handler is used (the first outbound that loaded, unless a `FINAL` rule hoisted
another one — see below).

## Rule fields (YAML / JSON)

Rules live under `router.rules`. Each rule is an object whose fields are ANDed
together:

| Key | Alias | Matches |
|---|---|---|
| `type` | — | Only the literal `FINAL` has meaning; see [default outbound](#default-outbound). |
| `ip` | — | Destination IP in one of the given CIDRs (e.g. `8.8.8.8/32`). |
| `domain` | — | Exact destination domain. |
| `domainKeyword` | `domain_keyword` | Substring of the destination domain. |
| `domainSuffix` | `domain_suffix` | The domain itself or any subdomain of it. |
| `geoip` | — | Country code looked up in the bundled `geo.mmdb`. |
| `external` | — | `mmdb:<code>` / `mmdb:<file>:<code>` or `site:<code>` / `site:<file>:<code>`. |
| `portRange` | `port_range` | Destination port, `start-end` (e.g. `1000-2000`). |
| `network` | — | `TCP` or `UDP` (other values are silently dropped). |
| `inboundTag` | `inbound_tag` | The tag of the inbound that accepted the session. |
| `processName` | `process_name` | Source process name. **Requires the non-default `rule-process-name` feature**; otherwise the field is dropped with a warning. |
| `target` | — | The outbound tag to route to. **Required.** |

`ip`, `geoip` and `external` rules only match a non-domain destination; for a
hostname they apply only after `domainResolve` has resolved it.

### Domain match types

`domain` is an exact match, `domainSuffix` matches the domain and its
subdomains, and `domainKeyword` is a substring match. (`site:` geosite entries
carry their own match type.)

### `domainResolve`

With `router.domainResolve: true` (alias `domain_resolve`), an unmatched
hostname destination is resolved through the configured DNS client and the whole
rule list runs a second time with the resolved IP — this is what lets `ip` and
`geoip` rules apply to hostnames. Only the first resolved address is used, and
lookup errors abort the routing decision.

### Default outbound

A rule with `type: FINAL` is not a matcher: it moves the outbound named by
`target` to be the default handler and is otherwise skipped. In the clash-style
format `FINAL` also stops parsing the rule list, so it must be last; in YAML/JSON
it does not stop later rules.

## Example (YAML)

```yaml
router:
  domainResolve: true
  rules:
    - domainSuffix:
        - google.com
      target: auto
    - domain:
        - www.example.com
      target: direct
    - ip:
        - 8.8.8.8/32
      target: direct
    - portRange:
        - 1000-2000
      network: TCP
      target: direct
    - type: FINAL
      target: auto
```

## Rules in clash-style `.conf`

The `[Rule]` section uses `TYPE, filter, target` lines:

| TYPE | Maps to |
|---|---|
| `IP-CIDR` | `ip` |
| `DOMAIN` | `domain` (exact) |
| `DOMAIN-KEYWORD` | `domainKeyword` |
| `DOMAIN-SUFFIX` | `domainSuffix` |
| `GEOIP` | `geoip` |
| `EXTERNAL` | `external` |
| `PORT-RANGE` | `portRange` |
| `NETWORK` | `network` |
| `INBOUND-TAG` | `inboundTag` |
| `PROCESS-NAME` | `processName` (feature-gated) |
| `FINAL` | default outbound (must be last) |

```conf
[General]
routing-domain-resolve = true

[Rule]
DOMAIN-SUFFIX, google.com, auto
DOMAIN, www.example.com, direct
IP-CIDR, 8.8.8.8/32, direct
FINAL, auto
```

## Outbound groups

Groups reference other outbounds by tag through `actors`. A group whose actors
cannot all be resolved to a non-empty set is skipped entirely. They exist as
outbounds only (the `chain` protocol additionally has an inbound form).

### `chain`

`settings.actors` — forwards the session through the actors in order, using the
earlier ones as transports for the last.

```yaml
outbounds:
  - protocol: chain
    tag: chained
    settings:
      actors: [tls_out, ws_out, trojan_out]
```

### `failover`

Health-checked failover with an LRU fallback cache. Settings (defaults in
parentheses): `actors`, `failTimeout` (4 s), `healthCheck` (true),
`healthCheckTimeout` (6 s), `healthCheckDelay` (200 ms), `healthCheckActive`
(900 s), `healthCheckPrefers`, `checkInterval` (300 s), `healthCheckOnStart`
(false), `healthCheckWait` (false), `healthCheckAttempts` (1),
`healthCheckSuccessPercentage` (50), `failover` (true), `fallbackCache`
(false), `cacheSize` (256), `cacheTimeout` (60), `lastResort`.

Actors are health-checked periodically and scheduled by RTT; `healthCheckPrefers`
gives named actors higher priority. When all actors fail, `lastResort` (if it
resolves to a known tag) is used. With `failover: false` only the single best
actor is scheduled; the clash-style `url-test` group maps to that.

### `static`

`settings.actors` plus `settings.method`, one of `random`, `random-once` or
`rr` (round-robin). Any other value is an error.

### `tryall`

`settings.actors` plus `settings.delayBase`. Every actor is raced concurrently,
actor *i* delayed by `delayBase * i` milliseconds; the first success wins.

### `select`

`settings.actors`. Forwards to `actors[selected]`, where the active index starts
at 0 and can be changed at runtime through the [API](api.md)
(`/api/v1/app/outbound/select`); the choice is persisted to a selector cache and
restored on startup and reload. Requires the `outbound-select` feature.

### `mptp`

Multi-path Transport Protocol; see [MPTP](protocols/mptp.md) and the
[MPTP usage](mptp_usage.md) chapter. `settings.actors` are the sub-connections,
with `settings.address` / `settings.port` naming the server.

## Groups in clash-style `.conf`

```conf
[Proxy Group]
Tag = type, actor1, actor2, ... [, key=value ...]
```

`type` is matched case-sensitively against `chain`, `tryall`, `static`,
`failover`, `select` and `mptp`. Unknown keys are ignored; recognised options
include `address`, `port`, `health-check`, `check-interval`, `fail-timeout`,
`failover`, `fallback-cache`, `cache-size`, `cache-timeout`, `last-resort`,
`health-check-timeout`, `health-check-delay`, `health-check-active`,
`health-check-prefers` (colon-separated), `health-check-on-start`,
`health-check-wait`, `health-check-attempts`,
`health-check-success-percentage`, `delay-base` and `method`. The aliases
`url-test` (→ `failover` with `failover=false`) and `fallback` (→ `failover`)
are also accepted.

```conf
[Proxy Group]
auto = failover, proxy_a, proxy_b, fail-timeout=4, health-check=true, last-resort=direct
```
