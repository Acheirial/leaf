# Introduction

**leaf** is a proxy **core library** — a Rust crate, not a standalone program.
It contains the proxy protocols, transports, routing engine, DNS client and
runtime, but ships **no command-line interface and no default binary**. You embed
it in your own application and drive it through the `leaf` crate API.

```rust
use leaf::{start, Config, RuntimeOption, StartOptions};

fn main() -> Result<(), leaf::Error> {
    start(
        0,
        StartOptions {
            config: Config::File("config.yml".to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: RuntimeOption::SingleThread,
        },
    )?;

    // `leaf::reload(0)` re-reads the config, `leaf::shutdown(0)` stops the runtime.
    std::thread::park();
    Ok(())
}
```

## What it provides

- **Inbounds** — listeners that accept traffic from local applications or from
  remote peers: `socks`, `http`, `hc`, `tls`, `ws`, `quic`, `amux`, `mptp`,
  `tun` and `tproxy` (Linux-only), plus the `chain`/`cat` helpers. The `vless`
  and `reality` directions are outbound-only in the current tree.
- **Outbounds** — the upstream the traffic is sent through: `direct`, `drop`,
  `redirect`, `socks`, `shadowsocks`, `trojan`, `vmess`, `vless`, `obfs`, `tls`,
  `ws`, `quic`, `reality`, `amux`, `mptp`, plus the routing groups `chain`,
  `failover`, `static`, `tryall` and `select`.
- **Routing** — rule-based dispatch on domain, IP, port, network, inbound tag and
  (when enabled) process name; see [Routing](routing.md).
- **DNS** — an Xray-aligned DNS client with UDP, TCP, DoH (h2/h2c) and DNS-over-QUIC
  transports, hosts overrides, caching and fallback; see [DNS](dns.md).
- **TLS** — inbound and outbound TLS options; see [TLS options](tls.md). Reality
  is an outbound-only TLS variant; see [Reality](protocols/reality.md).
- **API** — an optional HTTP/JSON API for runtime control; see [API](api.md).

Every supported direction is listed per protocol in the
[Protocols](protocols/socks.md) section, and the [Configuration](configuration.md)
chapter explains how to write the config file.

## Relationship to other projects

The configuration schema and DNS server grammar follow
[Xray-core](https://github.com/XTLS/Xray-core) conventions, and the project
reuses a few Xray-related crates (see [Development](development.md)). It is its
own implementation, not a binding of Xray.

## Repository layout

This repository contains the `leaf` crate only. The three files under
`docs/src/` that predate the book — [MPTP architecture](mptp_architecture.md),
[MPTP usage](mptp_usage.md) and the [YAML configuration guide](yaml_config.md) —
remain part of the book.
