# Direct

| Direction | Supported |
|---|---|
| Inbound | ❌ |
| Outbound | ✅ (`outbound-direct`) |

The `direct` outbound dials the session destination itself, with no proxy. The
stream and datagram handlers are pure pass-throughs.

## Outbound settings

None.

```yaml
outbounds:
  - tag: direct_out
    protocol: direct
```

Both TCP and UDP are supported. `direct` is the natural `lastResort` for a
[failover](../routing.md#failover) group and a common actor for
[MPTP](mptp.md).

## Inbound

Not implemented.
