# Reality

| Direction | Supported |
|---|---|
| Inbound | ❌ (not implemented in the current tree) |
| Outbound | ✅ (`outbound-reality`) |

Xray Reality: an outbound that masquerades as a TLS connection to a real site.
It reuses the TLS transport config (ALPN is fixed to `h2` + `http/1.1`).

## Outbound settings

| Key | Meaning |
|---|---|
| `serverName` | TLS SNI (the masqueraded site). |
| `publicKey` | The server's X25519 public key: 32 bytes, hex or URL-safe base64 without padding. |
| `shortId` | Hex short id, left-padded to 16 hex characters (8 bytes); may be empty. |

```yaml
outbounds:
  - tag: reality_out
    protocol: reality
    settings:
      serverName: www.example.com
      publicKey: <32-byte hex or base64url>
      shortId: <hex>
```

## Inbound

The inbound manager contains a `reality` arm behind the `inbound-reality`
feature, and `RealityInboundSettings` (dest, serverNames, privateKey, shortIds,
… ) exists in the schema — but `leaf/src/proxy/reality/` contains **no inbound
handler module**, so the inbound direction is not implemented in the current
tree. Do not configure a `reality` inbound.
