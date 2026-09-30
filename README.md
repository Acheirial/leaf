<p align="center">
<img src=".github/assets/leaf-logo-horizontal-white-bg.png" alt="Leaf Logo" width="360">
</p>

<p align="center">
<img src="https://github.com/eycorsican/leaf/workflows/releases/badge.svg">
<img src="https://github.com/eycorsican/leaf/workflows/ci/badge.svg">
</p>

<h1 align="center">Leaf</h1>

<p align="center">
A versatile and efficient proxy framework.
</p>

## Documentation

The documentation site is an [mdBook](https://rust-lang.github.io/mdBook/)
living in [`docs/`](docs/) and is published to GitHub Pages at
<https://acheirial.github.io/leaf/>. It covers configuration, the supported
protocols and transports, routing, DNS, TLS and the API.

- [Introduction](docs/src/introduction.md)
- [Configuration](docs/src/configuration.md)
- [YAML configuration guide](docs/src/yaml_config.md)
- [MPTP architecture](docs/src/mptp_architecture.md) and [usage](docs/src/mptp_usage.md)

## Supported Protocols

### Proxy Protocols

| Protocol | Inbound | Outbound |
|---|---|---|
| HTTP | ✅ | ❌ |
| HC | ✅ | ❌ |
| SOCKS5 | ✅ | ✅ |
| Shadowsocks | ❌ | ✅ |
| Trojan | ❌ | ✅ |
| VMess | ❌ | ✅ |
| VLESS | ✅ | ✅ |
| Hysteria2 | ✅ | ✅ |

### Transports & Security

| Transport | Inbound | Outbound | Notes |
|---|---|---|---|
| WebSocket | ✅ | ✅ | |
| TLS | ✅ | ✅ | Full option list in [TLS options](docs/src/tls.md) |
| QUIC | ✅ | ✅ | |
| XHTTP | ✅ | ✅ | HTTP/1.1 only; no h2c/HTTP-3 |
| AMux | ✅ | ✅ | Leaf specific multiplexing |
| FinalMask | ✅ | ✅ | Byte masks (fragment, header-custom, sudoku, salamander, noise) |
| Obfs | ❌ | ✅ | Simple obfuscation |
| Reality | ✅ | ✅ | Xray Reality; inbound authenticates and falls back to a real site |
| MPTP | ✅ | ✅ | Multi-path Transport Protocol (Aggregation) ([Architecture](docs/src/mptp_architecture.md), [Usage](docs/src/mptp_usage.md)) |

### Traffic Control

| Feature | Inbound | Outbound | Notes |
|---|---|---|---|
| Chain | ✅ | ✅ | Proxy chaining |
| Failover | ❌ | ✅ | Failover with health check |
| Select | ❌ | ✅ | Delegates to one configured actor; the active selection can be driven through the API |

### Transparent Proxying

| Mechanism | Inbound | Outbound | Notes |
|---|---|---|---|
| TUN | ✅ | ❌ | Linux, macOS, Windows, iOS, Android; lwip, smoltcp |
| TPROXY | ⚠️ Linux only | ❌ | Original-destination recovery via iptables/nftables |

### Name resolution

| Feature | Notes |
|---|---|
| DNS | Xray-aligned client: UDP, TCP, DoH (h2/h2c) and DNS-over-QUIC, hosts overrides, caching and fallback; see [DNS](docs/src/dns.md) |

## Configuration

Leaf selects the configuration format by file extension:

| Extension | Format |
|---|---|
| `.yml`, `.yaml` | YAML (preferred) |
| `.json` | JSON |
| `.conf` | clash-style `.conf` |

YAML is the preferred format. See the [YAML configuration guide](docs/src/yaml_config.md)
for a complete, runnable example covering `inbounds`, `outbounds`, `dns`, `router`
and `log`. JSON and clash-style `.conf` configurations remain fully supported.

## Building

This repository contains the core library only (the `leaf` crate).

```sh
cargo build -p leaf --release
```

## Testing

```sh
cargo test -p leaf
# or
make test
```

## License

This project is licensed under the [Apache License 2.0](https://github.com/eycorsican/leaf/blob/master/LICENSE).
