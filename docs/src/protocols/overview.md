# Protocol overview

This page is the support matrix for the whole book. A direction is implemented
only if the corresponding Cargo feature (and therefore a handler) exists; each
protocol's own chapter has the settings.

## Proxy protocols

| Protocol | Inbound | Outbound | Notes |
|---|---|---|---|
| [SOCKS](socks.md) | ✅ | ✅ | SOCKS5, with user/password auth on the inbound. |
| [HTTP](http.md) | ✅ | ❌ | CONNECT proxy. |
| [HC](hc.md) | ✅ | ❌ | HTTP health-check responder. |
| [Shadowsocks](shadowsocks.md) | ❌ | ✅ | AEAD client only. |
| [Trojan](trojan.md) | ❌ | ✅ | Client only. |
| [VMess](vmess.md) | ❌ | ✅ | AEAD client only. |
| [VLESS](vless.md) | ✅ | ✅ | Inbound: UUID auth, `xtls-rprx-vision`, UDP `cmd=2`, fallbacks with PROXY protocol. |
| [Hysteria2](hysteria2.md) | ✅ | ✅ | QUIC; TCP as streams, UDP as datagrams. |

## Transports

| Transport | Inbound | Outbound | Notes |
|---|---|---|---|
| [TLS](tls.md) | ✅ | ✅ | See [TLS options](../tls.md). |
| [WebSocket](ws.md) | ✅ | ✅ | |
| [QUIC](quic.md) | ✅ | ✅ | Streams, BBR. |
| [AMux](amux.md) | ✅ | ✅ | Leaf-specific multiplexing. |
| [MPTP](mptp.md) | ✅ | ✅ | Multi-path aggregation ([architecture](../mptp_architecture.md), [usage](../mptp_usage.md)). |
| [XHTTP](xhttp.md) | ✅ | ✅ | HTTP/1.1 only; no h2c/HTTP-3; `xmux` limits not enforced. |
| [FinalMask](finalmask.md) | ✅ | ✅ | Byte masks; only the masks listed in the chapter exist. |
| [Obfs](obfs.md) | ❌ | ✅ | Simple HTTP/TLS obfuscation. |
| [Reality](reality.md) | ✅ | ✅ | Inbound: ClientHello auth and a steal path. Outbound: Xray Reality client. |
| [TPROXY](tproxy.md) | ⚠️ Linux only | ❌ | No settings; the inbound's own `address`/`port` are the listener. |
| [TUN](tun.md) | ✅ | ❌ | Linux, macOS, Windows, iOS, Android; lwip, smoltcp. |

## Control outbounds

| Protocol | Inbound | Outbound | Notes |
|---|---|---|---|
| [Direct](direct.md) | ❌ | ✅ | Dial the destination unchanged. |
| [Drop](drop.md) | ❌ | ✅ | Discard. |
| [Redirect](redirect.md) | ❌ | ✅ | Rewrite the destination. |
| [Chain](../routing.md#chain) | ✅ | ✅ | Compose actors; also available as an inbound. |
| Cat | ✅ | ❌ | stdin/stdout inbound helper. |
| [Failover](../routing.md#failover) | ❌ | ✅ | Health-checked failover with an LRU cache. |
| [Select](../routing.md#select) | ❌ | ✅ | Delegates to one actor; switchable through the API. |
| [Static](../routing.md#static) | ❌ | ✅ | Random / round-robin. |
| [TryAll](../routing.md#tryall) | ❌ | ✅ | Race every actor. |
| Plugin | ❌ | ✅ | Loads an outbound from a shared library; requires the non-default `plugin` feature. |

## DNS and TLS

- [DNS](../dns.md) — Xray-aligned client with UDP, TCP, DoH (h2/h2c) and
  DNS-over-QUIC, hosts overrides, caching and fallback.
- [TLS options](../tls.md) — the full inbound/outbound option list used by the
  [TLS](tls.md), [Reality](reality.md) and [QUIC](quic.md) transports.

## Configuration formats

The examples in this section are YAML, the preferred format. The same documents
are accepted in JSON, and a subset is expressible in the clash-style `.conf`
format; see [Configuration](../configuration.md) and the
[YAML configuration guide](../yaml_config.md).
