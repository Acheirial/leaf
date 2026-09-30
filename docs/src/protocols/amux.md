# AMux

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-amux`) |
| Outbound | ✅ (`outbound-amux`) |

A stream multiplexing layer that carries many proxy streams over a single
connection. It is normally chained behind another transport (TLS, WebSocket,
QUIC, …), which is selected through `actors`.

## Inbound settings

| Key | Meaning |
|---|---|
| `actors` | Tags of other inbound handlers the accepted connection is first passed through (e.g. a TLS inbound). |

```yaml
inbounds:
  - tag: tls_in
    address: 127.0.0.1
    port: 443
    protocol: tls
    settings:
      certificate: /c.pem
      certificateKey: /k.pem
  - tag: amux_in
    address: 127.0.0.1
    port: 443
    protocol: amux
    settings:
      actors: [tls_in]
```

## Outbound settings

| Key | Default | Meaning |
|---|---|---|
| `address`, `port` | — | Server endpoint (used when `actors` is empty). |
| `actors` | — | Outbound handlers the new connection is passed through before muxing; use this to chain behind a transport. |
| `maxAccepts` / `max_accepts` | 8 | Maximum streams per mux connection. |
| `concurrency` | 2 | Maximum concurrent open streams per connection. |
| `max_recv_bytes` | 0 | Rotate the connection once received bytes reach this value (`0` disables). |
| `max_lifetime` | 0 | Rotate the connection after this many seconds (`0` disables). |

```yaml
outbounds:
  - tag: tls_out
    protocol: tls
    settings:
      serverName: example.com
  - tag: amux_out
    protocol: amux
    settings:
      address: example.com
      port: 443
      actors: [tls_out]
      maxAccepts: 8
      concurrency: 2
```

AMux outbounds are resolved after other outbounds, so `actors` may reference
tags defined later in the file.

## UDP in a chain

A chain carries a datagram only when the payload at its end frames it inside
what the transports under it carry, and AMux carries streams. A VLESS payload
does that with `cmd=2`; a socks payload cannot, because its UDP needs a socks5
server address of its own, which a chain has nowhere to put. An AMux inbound
also has no datagram half, so a chain inbound whose first actor is AMux gets no
UDP listener at all and could not receive one.
