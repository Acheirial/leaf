# Redirect

| Direction | Supported |
|---|---|
| Inbound | ❌ |
| Outbound | ✅ (`outbound-redirect`) |

The `redirect` outbound always dials a fixed server and then passes the
established connection through unchanged, regardless of the session destination.

## Outbound settings

| Key | Meaning |
|---|---|
| `address`, `port` | The fixed endpoint every session is sent to. |

```yaml
outbounds:
  - tag: redirect_out
    protocol: redirect
    settings:
      address: 127.0.0.1
      port: 1080
```

For UDP, the receive half rewrites the reported source back to the session
destination and the send half rewrites the target to the configured address, so
only symmetric NAT sessions are supported.

## Inbound

Not implemented. Note that the unrelated transparent-proxy original-destination
recovery lives in the Linux-only [TPROXY](tproxy.md) inbound; this outbound is
platform-independent.
