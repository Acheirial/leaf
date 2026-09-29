# Trojan

| Direction | Supported |
|---|---|
| Inbound | ❌ |
| Outbound | ✅ (`outbound-trojan`) |

A Trojan client.

## Outbound settings

| Key | Meaning |
|---|---|
| `address`, `port` | Server endpoint. |
| `password` | Trojan password. |

```yaml
outbounds:
  - tag: trojan_out
    protocol: trojan
    settings:
      address: 192.0.2.1
      port: 443
      password: secret
```

Both TCP and UDP are supported. Trojan is normally chained behind
[TLS](tls.md).

In clash-style `.conf`, `Trojan = trojan, <address>, <port>, <password>` with
`sni=` (and the `tls-ech*` keys) builds the TLS chain automatically.

## Inbound

Not implemented.
