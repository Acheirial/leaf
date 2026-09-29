# Drop

| Direction | Supported |
|---|---|
| Inbound | ❌ |
| Outbound | ✅ (`outbound-drop`) |

The `drop` outbound discards traffic: it has no destination and both the stream
and datagram handlers fail with `dropped`. Use it to blackhole matching traffic.

## Outbound settings

None.

```yaml
outbounds:
  - tag: drop_out
    protocol: drop
```

In clash-style `.conf` the `reject` protocol is an alias for `drop`.

## Inbound

Not implemented.
