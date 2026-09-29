# HC

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-hc`) |
| Outbound | ❌ |

A canned HTTP server used as a health-check endpoint. It is the counterpart of
the [failover](../routing.md#failover) outbound's health probe: configure
`path: /` so a `GET /` request receives the configured `response`.

## Inbound

Settings:

| Key | Meaning |
|---|---|
| `path` | Required. The request path that is answered. |
| `request` | Optional request body that must match. When empty, the expected method is `GET`; otherwise `POST` with exactly this body. |
| `response` | Optional response body (returned as `text/plain` with `Connection: close`). |

A successful match answers `HTTP/1.1 200 OK` with the configured body. Any
mismatch sleeps a random 0–10 seconds and then closes the connection.

```yaml
inbounds:
  - tag: hc_in
    address: 0.0.0.0
    port: 8080
    protocol: hc
    settings:
      path: /
      response: ok
```

## Outbound

Not implemented.
