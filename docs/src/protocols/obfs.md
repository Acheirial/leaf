# Obfs

| Direction | Supported |
|---|---|
| Inbound | ❌ |
| Outbound | ✅ (`outbound-obfs`) |

Simple-obfs: an obfuscation wrapper that makes a connection look like HTTP or
TLS. It has no destination of its own (`connect_addr` is `Next`), so it is used
as the leading actor of a [chain](../routing.md#chain) in front of the real
protocol.

## Outbound settings

| Key | Meaning |
|---|---|
| `method` | `http` (wrap as an HTTP `GET` request) or `tls` (a fake TLS ClientHello). Any other value is an error. |
| `host` | The `Host` header (HTTP) or the SNI (TLS). |
| `path` | The request path for the `http` method. |

```yaml
outbounds:
  - tag: obfs_out
    protocol: obfs
    settings:
      method: http
      host: example.com
      path: /
```

Typical use is `obfs` chained in front of `shadowsocks`.

In clash-style `.conf` the keys are `obfs`, `obfs-host` and `obfs-path`; setting
`obfs` on a shadowsocks proxy makes the converter build the chain automatically.

## Inbound

Not implemented.
