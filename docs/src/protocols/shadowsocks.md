# Shadowsocks

| Direction | Supported |
|---|---|
| Inbound | ❌ |
| Outbound | ✅ (`outbound-shadowsocks`) |

An AEAD Shadowsocks client.

## Outbound settings

| Key | Meaning |
|---|---|
| `address`, `port` | Server endpoint. |
| `method` | Cipher. Defaults to `chacha20-ietf-poly1305`. |
| `password` | Password. |
| `prefix` | Optional percent-encoded prefix, limited to the cipher key length. |

Supported AEAD ciphers: `chacha20-poly1305`, `chacha20-ietf-poly1305`,
`aes-256-gcm`, `aes-128-gcm`.

```yaml
outbounds:
  - tag: ss_out
    protocol: shadowsocks
    settings:
      address: 192.0.2.1
      port: 8388
      method: aes-256-gcm
      password: secret
```

Both TCP and UDP are supported.

In clash-style `.conf` the positional form is
`Tag = shadowsocks, <address>, <port>, <method>, <password>`, with optional
`prefix=` and `obfs=` keys (the latter synthesises an [obfs](obfs.md) chain);
`ss` is accepted as an alias.

## Inbound

Not implemented.
