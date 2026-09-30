# Hysteria2

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-hysteria2`) |
| Outbound | ✅ (`outbound-hysteria2`) |

Hysteria2 over QUIC (quinn), with an HTTP/3 authentication exchange. One QUIC
endpoint serves everything: HTTP/3 for the auth request, QUIC bidirectional
streams for proxied TCP, and QUIC datagrams for proxied UDP. The negotiated ALPN
is `h3`.

The inbound registers only a datagram handler with the framework, but that
handler itself carries both TCP (as streams) and UDP (as datagrams); there is no
separate inbound stream handler.

The examples below are YAML.

## Authentication

The client sends an HTTP/3 `POST` to `https://hysteria/auth` with the header
`Hysteria-Auth: <password>` plus `Hysteria-CC-RX` (its declared receive rate)
and a random `Hysteria-Padding`. The server compares the password by plain
string equality and answers `233` on success with headers `Hysteria-CC-RX:
<rate|"auto">` and `Hysteria-Padding`, plus `Hysteria-UDP: true` **only when the
connection can actually carry UDP replies** (see [UDP relay](#udp-relay)); when
it cannot, `Hysteria-UDP: false` is sent and the reason is logged once at
`info`. A request that is not a valid auth POST, or carries the wrong password,
is answered by the masquerade (anti-probe) rather than an error. Proxy streams
that arrive before authentication are reset.

## Inbound settings

| Key | Default | Meaning |
|---|---|---|
| `password` | — | **Required** and non-empty; the shared secret. |
| `certificate` | — | **Required** TLS certificate (inline PEM or file path; `.der` files are read as DER). |
| `certificateKey` / `certificate_key` | — | **Required** key (PKCS#8, then PKCS#1, then SEC1). |
| `obfs` | — | Obfuscation. Only `salamander` is supported; any other value is a startup error. |
| `obfsPassword` / `obfs_password` | — | Required when `obfs: salamander`. At least 4 bytes. |
| `masquerade` | — | Unified masquerade value: an `http://`/`https://` URL, an existing file path, or a literal string (see below). |
| `masqueradeFile` / `masquerade_file` | — | Serve this file for probes. Takes precedence over `masquerade`. |
| `masqueradeString` / `masquerade_string` | — | Answer probes with this literal string. Takes precedence over both. |
| `upMbps` / `up_mbps` | `0` | Server send rate in Mbit/s. Only seeds the congestion-controller initial window. |
| `downMbps` / `down_mbps` | `0` | Server receive rate in Mbit/s, reported to the client as `Hysteria-CC-RX`. |
| `ignoreClientBandwidth` / `ignore_client_bandwidth` | `false` | When true, advertise `Hysteria-CC-RX: auto` so the client detects its own rate. |
| `udpIdleTimeout` / `udp_idle_timeout` | `60` | Seconds before an idle UDP session is reaped. |
| `mtu` | — | Initial QUIC MTU; applied only when in `1200..=1452`, otherwise ignored with a warning. |

`salamander` prefixes every QUIC packet on the wire with an 8-byte random salt
and XORs it with `BLAKE2b-256(psk ‖ salt)`.

### Masquerade

When a request is not a valid auth POST:

- nothing configured → `404` with `404 page not found\n`;
- `masqueradeString` (or a `masquerade` string that is not a URL or path) →
  `200 text/plain` with that string;
- `masqueradeFile` (or a `masquerade` value that is an existing path) → the file
  is served, with `index.html` for a directory and a content type from the
  extension; `..`/`.` path components are rejected;
- `masquerade` set to an `http://`/`https://` URL → **`502 Bad Gateway`**. The
  reference reverse-proxies to the URL; this crate has no HTTP client in its
  feature set, so it refuses instead of leaking the proxy.

Every masquerade response advertises `alt-svc: h3=":<port>"; ma=2592000`.

## Outbound settings

| Key | Default | Meaning |
|---|---|---|
| `server` | — | **Required** server address, `host:port` (port defaults to `443` when absent). |
| `password` | `""` | Shared secret. |
| `obfs` / `obfsPassword` (`obfs_password`) | — | As on the inbound: only `salamander`, and the password is required for it. |
| `sni` | server host | TLS server name. |
| `insecure` | `false` | Skip certificate verification. |
| `alpn` | `["h3"]` | A **comma-separated** string; each entry is trimmed and empties dropped. |
| `upMbps` / `up_mbps` | `0` | As above. |
| `downMbps` / `down_mbps` | `0` | Advertised to the server as the client's receive rate. |
| `udpIdleTimeout` / `udp_idle_timeout` | — | **Accepted but ignored**; the QUIC connection idle timeout governs. |
| `mtu` | — | As above. |

The outbound refuses UDP when the server did not answer `Hysteria-UDP: true`,
and drops a UDP message larger than 4096 bytes.

## UDP relay

Proxied UDP rides on QUIC datagrams. In the inbound (leaf as the Hysteria2
**server**), the `Hysteria-UDP` auth response is `true` only when the client's
QUIC transport parameters let the server *send* datagrams, i.e. when the client
advertised `max_datagram_frame_size` (quinn's `Connection::max_datagram_size()`
returns `Some`). When they do not, the server answers `Hysteria-UDP: false`,
logs the reason once at `info`, and does not accept a UDP uplink; this prevents a
one-way relay whose every reply would be silently dropped. A leaf-to-leaf pair
works because both sides advertise datagram support.

### Limitation: no UDP relay against the reference client

- **Direction affected:** server → client (the reply direction of an inbound UDP
  relay).
- **Clients affected:** the official Hysteria2 client (and anything else built on
  it). `core/client/client.go` sets `OmitMaxDatagramFrameSize: true`, so it never
  sends the `max_datagram_frame_size` transport parameter, even though it is
  willing to receive datagrams.
- **Why:** the reference server sidesteps this with the non-standard
  `AssumePeerMaxDatagramFrameSize: 1200` option
  (`core/server/server.go`), which tells quic-go to assume the peer's parameter.
  quinn exposes no equivalent: `Datagrams::max_size()` returns `None` when the
  peer omitted the parameter, and there is no "assume" knob. Without it there is
  no size at which datagrams may be sent, so the reply path does not exist.
- **Behaviour today:** the reference client is told `Hysteria-UDP: false` and
  therefore never attempts UDP — the relay is disabled rather than
  silently one-way. TCP is unaffected.
- **What fixing it would require:** a patched `quinn-proto` that exposes an
  `assume_peer_max_datagram_frame_size` setting (used in place of the absent
  peer parameter inside `Datagrams::max_size`). This project consumes the
  published quinn crate, so that change would mean maintaining a fork.

## Congestion control — `brutal` is not implemented

Hysteria's own sender ("brutal") paces traffic at the rate negotiated during
authentication and ignores loss. quinn exposes no public hook with those
semantics — its `Controller` trait is implementable, but the RTT estimator its
callbacks hand out is not publicly nameable, so a rate-paced sender cannot be
expressed from outside quinn. This port therefore uses quinn's **BBR**, the
reference's own fallback when no bandwidth is known.

The configured `upMbps`/`downMbps` do **not** pace traffic. They only seed BBR's
initial window (one tenth of a second of data at the configured rate, clamped)
and appear as informational auth headers; the outbound's negotiated send rate is
computed and logged but never applied. There is no bandwidth detection.

## Other limitations

- Masquerade reverse-proxying (`http(s)://` target) returns `502` (see above).
- The outbound's `udpIdleTimeout` is parsed but unused.
- A bidi stream that dies before declaring its frame type finishes the whole
  HTTP/3 connection (h3 cannot skip a stream).
- UDP sessions cannot be converted to a std socket.
- The inbound answers the TCP request with `Connected` **before** the target dial
  completes. The reference server dials first and returns the dial error to the
  client (`core/server/server.go`, `handleTCPRequest`: `Outbound.TCP` before
  `WriteTCPResponse(stream, true, "Connected")`, and `WriteTCPResponse(stream,
  false, err)` on failure). In leaf the dial happens later, in the framework's
  dispatcher, after the stream has been handed over, and there is no channel
  back to the inbound; so a failed dial currently surfaces as a stream reset
  after a spurious `Connected` rather than as a dial error. Matching the
  reference needs a dial-result signal from the dispatcher to the inbound
  (outside this protocol's own sources).

## Example (YAML)

Inbound:

```yaml
inbounds:
  - tag: hysteria2_in
    address: 0.0.0.0
    port: 443
    protocol: hysteria2
    settings:
      password: hunter2
      certificate: /etc/leaf/cert.pem
      certificateKey: /etc/leaf/key.pem
      obfs: salamander
      obfsPassword: shared-secret
      masqueradeString: "Welcome"
      upMbps: 100
      downMbps: 200
      udpIdleTimeout: 60
```

Outbound:

```yaml
outbounds:
  - tag: hysteria2_out
    protocol: hysteria2
    settings:
      server: example.com:443
      password: hunter2
      sni: example.com
      obfs: salamander
      obfsPassword: shared-secret
      alpn: h3
      insecure: false
```
