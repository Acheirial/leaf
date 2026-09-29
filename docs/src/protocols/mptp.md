# MPTP

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-mptp`) |
| Outbound | ✅ (`outbound-mptp`) |

MPTP (Multi-path Transport Protocol) aggregates several reliable sub-connections
into one logical tunnel for bandwidth aggregation and resilience. Each sub-
connection is opened through a configured actor outbound and points at an MPTP
server, which joins the session by connection ID.

See [MPTP architecture](../mptp_architecture.md) and [MPTP usage](../mptp_usage.md)
for the full picture.

## Inbound

The inbound has **no settings**.

```yaml
inbounds:
  - tag: mptp_in
    address: 0.0.0.0
    port: 3001
    protocol: mptp
```

## Outbound

| Key | Meaning |
|---|---|
| `actors` | Outbound tags used as sub-connections. Requires at least one resolvable tag, otherwise the outbound is skipped. |
| `address`, `port` | The MPTP server. |

```yaml
outbounds:
  - tag: mptp_out
    protocol: mptp
    settings:
      actors: [direct1, direct2]
      address: 192.0.2.1
      port: 3001
  - tag: direct1
    protocol: direct
  - tag: direct2
    protocol: direct
```

In clash-style `.conf` only the outbound form exists:

```conf
[Proxy Group]
MptpOutTag = mptp, actor1, actor2, actor3, address=1.2.3.4, port=10000
```

## Wire format

The handshake carries `version | connection-id (16 bytes) | command |
destination address | destination port`, with `CONNECT` for TCP and a UDP
command for datagrams; data is carried in length-prefixed data/ping/pong/fin/rst
frames.
