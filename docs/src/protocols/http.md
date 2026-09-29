# HTTP

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-http`) |
| Outbound | ❌ |

An HTTP proxy inbound. It parses origin-form, absolute-form and `CONNECT`
requests.

## Inbound

This inbound has **no settings**.

```yaml
inbounds:
  - tag: http_in
    address: 127.0.0.1
    port: 8080
    protocol: http
```

In clash-style `.conf` it is created from `[General]` `http-interface` /
`http-port`.

## Outbound

Not implemented — there is no HTTP outbound.
