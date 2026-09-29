# Configuration

leaf accepts three configuration formats. They express the same model
(`inbounds`, `outbounds`, `dns`, `router`, `log`) and are interchangeable — the
same sections are accepted by all three.

| Extension | Format | Feature |
|---|---|---|
| `.yml`, `.yaml` | YAML (**preferred**) | `config-yaml` |
| `.json` | JSON | `config-json` |
| `.conf` | clash-style `.conf` | `config-conf` |

## Format dispatch

When a **file path** is passed to `leaf::start` / `leaf::test_config`, the
format is chosen by extension (`leaf/src/config/mod.rs::from_file`):

- `.yml` / `.yaml` → YAML
- `.json` → JSON
- `.conf` → clash-style
- anything else → an error naming the accepted extensions

When a **string** is passed (`Config::Str`), the content is sniffed
(`leaf/src/config/mod.rs::from_string`):

1. Input starting with `{` is parsed as JSON (an error if the build has no
   `config-json` feature).
2. Input starting with `[` is tried as JSON, then falls through — a clash-style
   `[Section]` header is not a JSON array.
3. YAML is attempted; the document is only accepted if it is a mapping carrying
   at least one recognised top-level key (`inbounds`, `outbounds`, `dns`, `log`,
   `router`, `api`). This keeps clash-style `.conf` text, which also parses as
   YAML, from being silently swallowed.
4. Otherwise the clash-style parser is used.

Because the parsers are feature-gated (`config-yaml`, `config-json`,
`config-conf`), a build only understands the formats it was compiled with. The
default feature bundle enables all three (see [Development](development.md)).

An optional top-level `env` mapping sets environment variables before the
configuration is converted; it is accepted by all three formats but is not one of
the keys that mark a document as YAML.

## Full example (YAML)

A complete configuration: a SOCKS5 inbound, a `direct` outbound, two public DNS
resolvers plus a hosts override, and router rules.

```yaml
log:
  level: info
  output: console

dns:
  servers:
    - 8.8.8.8
    - 1.1.1.1
  hosts:
    example.com:
      - 127.0.0.1

inbounds:
  - tag: socks_in
    address: 127.0.0.1
    port: 1086
    protocol: socks

outbounds:
  - tag: direct_out
    protocol: direct

router:
  domainResolve: true
  rules:
    - domainSuffix:
        - google.com
      target: direct_out
    - target: direct_out
```

Every chapter in this book shows the fields relevant to it:
[Protocols](protocols/socks.md), [Routing](routing.md), [DNS](dns.md),
[TLS options](tls.md) and [API](api.md).

## JSON

The same document in JSON, selected by the `.json` extension or by input
beginning with `{`:

```json
{
  "log": { "level": "info", "output": "console" },
  "dns": {
    "servers": ["8.8.8.8", "1.1.1.1"],
    "hosts": { "example.com": ["127.0.0.1"] }
  },
  "inbounds": [
    { "tag": "socks_in", "address": "127.0.0.1", "port": 1086, "protocol": "socks" }
  ],
  "outbounds": [{ "tag": "direct_out", "protocol": "direct" }],
  "router": {
    "domainResolve": true,
    "rules": [
      { "domainSuffix": ["google.com"], "target": "direct_out" },
      { "target": "direct_out" }
    ]
  }
}
```

## clash-style `.conf`

The `.conf` format uses INI-like sections. The sections consumed by the parser
are `[General]`, `[Proxy]`, `[Proxy Group]`, `[Rule]`, `[Host]`, `[Env]`, plus
`[Certificate.<name>]` and `[Ech.<name>]` blocks referenced by name.

```conf
[General]
loglevel = info
dns-server = 8.8.8.8, 1.1.1.1

[Proxy]
Direct = direct
Socks1 = socks, 1.2.3.4, 1080, username, password

[Proxy Group]
Failover1 = failover, Direct, Socks1

[Rule]
DOMAIN-SUFFIX, google.com, Direct
FINAL, Direct
```

In `[Proxy]`, a line is `Tag = protocol[, address[, port[, password]]][, option=value ...]`.
In `[Proxy Group]`, a line is `Tag = group_type, actor1, actor2, ...` with optional
`key=value` settings. See [Routing](routing.md) for the group types and the rule
grammar.

> The `api-port` / `api-interface` `[General]` options are parsed but ignored —
> the API is enabled by the `api` feature together with the `API_LISTEN`
> environment variable, not by the config file. See [API](api.md).

## Validation

Validate a config file before starting without launching the runtime:

```rust
leaf::test_config("config.yml")?;
```
