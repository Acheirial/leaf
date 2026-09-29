# SOCKS

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-socks`) |
| Outbound | ✅ (`outbound-socks`) |

SOCKS5 (and SOCKS4/4a on the inbound side).

## Inbound

Settings: `username`, `password`. Both optional — when `username` is empty no
authentication is required; otherwise SOCKS5 username/password authentication is
enforced. The inbound accepts SOCKS4/4a and SOCKS5, supporting the `CONNECT` and
`UDP ASSOCIATE` commands.

```yaml
inbounds:
  - tag: socks_in
    address: 127.0.0.1
    port: 1086
    protocol: socks
    settings:
      username: user
      password: pass
```

In clash-style `.conf`, a SOCKS inbound can also be created from `[General]`
`socks-interface` / `socks-port`.

## Outbound

Settings: `address`, `port` (server), `username`, `password` (optional; empty
username means no authentication). Supports both TCP and UDP.

```yaml
outbounds:
  - tag: socks_out
    protocol: socks
    settings:
      address: 192.0.2.1
      port: 1080
      username: user
      password: pass
```

In clash-style `.conf`: `Tag = socks, <address>, <port>, <username>, <password>`.
