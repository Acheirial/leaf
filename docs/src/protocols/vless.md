# VLESS

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-vless`) |
| Outbound | ✅ (`outbound-vless`) |

VLESS is Xray's lightweight proxy protocol. This implementation follows
`Xray-core/proxy/vless` for the wire format (`encoding.rs`) and for the inbound
fallback lookup rules.

A VLESS request header is
`[version:1][user id:16][addons len:1][addons][command:1][port:2][addr type:1][addr]`,
and the server always answers with a `[version:1][addons len:1][addons]`
response header. The only addon field used is `Flow`.

## Inbound

### Authentication and users

`users` is a list whose entries are either a bare UUID string or an object. A
request is authenticated when its 16-byte user id matches a configured UUID
using Xray's `vless.ProcessUUID` comparison (the two route bytes at offsets 6
and 7 of the id are ignored). An empty `users` list is a startup error
(`no VLESS users configured`); an unknown user id is rejected with an error
rather than being sent to a fallback.

Object entries support these fields:

| Field | Meaning |
|---|---|
| `id` | User UUID. Required. |
| `flow` | Only `""` or `xtls-rprx-vision`. Any other value is a startup error. |
| `encryption` | Must be empty or `none` on the inbound; anything else is a startup error. |
| `level` | Parsed but not used. |

### Inbound settings

| Key | Meaning |
|---|---|
| `users` | The user list described above. |
| `decryption` | VLESS encryption. Only empty or `none` is accepted; any `mlkem768x25519plus.…` scheme is rejected at startup while the handshake is not implemented in this build. |
| `fallbacks` | List of fallback entries (see below). |

### Commands

| `command` | Behaviour |
|---|---|
| `1` (TCP) | Streams a single connection to the requested destination. |
| `2` (UDP) | Carries a UDP session to one destination as `[length:2][payload]` datagrams over the stream. Enforced up to 65535 bytes per datagram. |
| `3`, `4` (MUX/RVS) | Parsed by the header decoder but then rejected (`unsupported VLESS request command`). Multiplexing and reverse proxies are not implemented. |

`xtls-rprx-vision` (`flow`) is supported for TCP: the server wraps the stream in
the Vision record layer. Vision combined with UDP is rejected
(`xtls-rprx-vision does not support UDP without mux`).

VLESS itself has no datagram transport: UDP travels inside a `cmd=2` stream. The
inbound builds a datagram handler, but it only logs and yields nothing rather
than pretending to carry raw datagrams.

### Fallbacks

When the request header cannot be parsed, and at least one fallback is
configured, the connection is spliced to another responder instead of being
dropped. Each entry matches on `(name, alpn, path)`:

| Key | Meaning |
|---|---|
| `name` | TLS server name. Matched by longest configured substring of the session's TLS SNI, else the empty wildcard entry. |
| `alpn` | Negotiated ALPN. leaf does not expose the negotiated ALPN of an outer TLS session, so this is always empty at runtime: only the wildcard (`""`) ALPN entry can match. |
| `path` | Request path, parsed from the first bytes of an HTTP request. Empty means the wildcard. Must be empty or start with `/`. |
| `type` | `tcp` or `unix`; any other value is a startup error, and it may not be empty while `dest` is set. |
| `dest` | `host:port` (or a Unix socket path). |
| `xver` | PROXY protocol version prepended to the fallback connection: `0` none (default), `1` v1 ASCII, `2` v2 binary. Values above `2` are a startup error. |

The lookup follows Xray's inheritance rules: a wildcard `name` entry supplies
the default ALPN entries, and a wildcard `alpn` entry supplies the default
paths. The bytes already read from the client are replayed verbatim to the
fallback destination before the two directions are spliced together.

### Example (YAML)

```yaml
inbounds:
  - tag: vless_in
    address: 0.0.0.0
    port: 443
    protocol: vless
    settings:
      users:
        - b831381d-6324-4d53-ad4f-8cda48b30811
        - id: 9d4e2c1a-0000-4000-8000-000000000000
          flow: xtls-rprx-vision
      fallbacks:
        - name: ""
          alpn: ""
          path: /ws
          type: tcp
          dest: 127.0.0.1:8080
        - name: www.example.com
          alpn: ""
          path: ""
          type: tcp
          dest: 127.0.0.1:80
          xver: 1
```

## Outbound

| Key | Meaning |
|---|---|
| `address`, `port` | Server endpoint. |
| `uuid` | User UUID. |
| `encryption` | Only empty or `none` is accepted; any `mlkem768x25519plus.…` scheme is rejected at startup while the handshake is not implemented in this build. |

The outbound settings carry no flow field, so the client sends no flow (an empty
addons blob): `xtls-rprx-vision` is a server-side capability here, not something
the outbound requests. Both TCP and UDP are supported; UDP uses the same
`cmd=2` framing as the inbound.

```yaml
outbounds:
  - tag: vless_out
    protocol: vless
    settings:
      address: 192.0.2.1
      port: 443
      uuid: b831381d-6324-4d53-ad4f-8cda48b30811
```
