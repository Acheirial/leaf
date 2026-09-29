# WebSocket (ws)

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-ws`) |
| Outbound | ✅ (`outbound-ws`) |

A WebSocket transport (RFC 6455). `websocket` is accepted as an alias for the
protocol name in YAML/JSON.

## Inbound settings

| Key | Meaning |
|---|---|
| `path` | The request path to accept. Empty defaults to `/`; a request whose path differs is answered with `404`. |

A `Forwarded` header on the request sets the session's forwarded source.

```yaml
inbounds:
  - tag: ws_in
    address: 127.0.0.1
    port: 8080
    protocol: ws
    settings:
      path: /ws
```

## Outbound settings

| Key | Meaning |
|---|---|
| `path` | Request path. |
| `headers` | Extra headers; every header except `Host` is inserted, and `User-Agent` is overwritten from the `HTTP_USER_AGENT` option when set. |

```yaml
outbounds:
  - tag: ws_out
    protocol: ws
    settings:
      path: /ws
      headers:
        Host: example.com
```
