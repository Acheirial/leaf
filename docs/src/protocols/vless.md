# VLESS

| Direction | Supported |
|---|---|
| Inbound | ❌ (not implemented in the current tree) |
| Outbound | ✅ (`outbound-vless`) |

## Outbound

A VLESS client using the `xtls-rprx-vision` flow.

| Key | Meaning |
|---|---|
| `address`, `port` | Server endpoint. |
| `uuid` | User UUID. |
| `encryption` | Accepted in the schema but **ignored** by the handler. |

```yaml
outbounds:
  - tag: vless_out
    protocol: vless
    settings:
      address: 192.0.2.1
      port: 443
      uuid: b831381d-6324-4d53-ad4f-8cda48b30811
```

Both TCP and UDP are supported.

## Inbound

The inbound manager contains a `vless` arm behind the `inbound-vless` feature,
and `VlessInboundSettings` (users, flows, fallbacks) exists in the schema — but
`leaf/src/proxy/vless/` contains **no inbound handler module**, so the inbound
direction is not implemented in the current tree. Do not configure a `vless`
inbound; use the [SOCKS](socks.md), [HTTP](http.md), [TLS](tls.md) or
[chain](../routing.md#chain) inbounds instead.
