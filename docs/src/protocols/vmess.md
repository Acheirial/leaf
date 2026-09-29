# VMess

| Direction | Supported |
|---|---|
| Inbound | ❌ |
| Outbound | ✅ (`outbound-vmess`) |

A VMess (AEAD) client.

## Outbound settings

| Key | Meaning |
|---|---|
| `address`, `port` | Server endpoint. |
| `uuid` | User UUID. |
| `security` | Cipher, one of `chacha20-poly1305`, `chacha20-ietf-poly1305` or `aes-128-gcm` (case-insensitive). Defaults to `chacha20-ietf-poly1305`; any other value is an error. |

```yaml
outbounds:
  - tag: vmess_out
    protocol: vmess
    settings:
      address: 192.0.2.1
      port: 443
      uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
      security: aes-128-gcm
```

Both TCP and UDP are supported. VMess is usually chained behind
[TLS](tls.md) so the server name and certificate options take effect.

## Inbound

Not implemented.
