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
(`no VLESS users configured`). An unknown but well-formed user id is treated
like any other authentication failure: when fallbacks are configured the bytes
read so far are replayed to the fallback, otherwise the request is rejected
with `invalid VLESS request user id`.

Object entries support these fields:

| Field | Meaning |
|---|---|
| `id` | User UUID. Required. |
| `flow` | Only `""` or `xtls-rprx-vision`. Any other value is a startup error. |
| `encryption` | Must be empty or `none` on the inbound; anything else is a startup error (Xray rejects it too, `infra/conf/vless.go:84`). |
| `level` | Parsed but not used. |

### Inbound settings

| Key | Meaning |
|---|---|
| `users` | The user list described above. |
| `decryption` | VLESS encryption. Empty or `none` disables it; a `mlkem768x25519plus.…` scheme enables it (see [VLESS encryption](#vless-encryption-mlkem768x25519plus)). Mutually exclusive with `fallbacks`. |
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

The flow is enforced per account, as in Xray:

- a request carrying `xtls-rprx-vision` for an account whose `flow` is not
  `xtls-rprx-vision` is rejected (`… is not able to use the flow …`);
- a request with an empty flow (`cmd=1`) for an account configured with
  `xtls-rprx-vision` is rejected (`… is rejected since the client flow is
  empty …`);
- any other flow value is rejected (`unknown VLESS request flow …`).

VLESS itself has no datagram transport: UDP travels inside a `cmd=2` stream. The
inbound builds a datagram handler, but it only logs and yields nothing rather
than pretending to carry raw datagrams.

### Fallbacks

When the request header cannot be parsed, and at least one fallback is
configured, the connection is spliced to another responder instead of being
dropped. Each entry matches on `(name, alpn, path)`:

| Key | Meaning |
|---|---|
| `name` | Server name of the outer TLS/REALITY session (the client's SNI, lower-cased). Matched by longest configured substring, else the empty wildcard entry. |
| `alpn` | ALPN negotiated on the outer TLS/REALITY session (lower-cased). The TLS inbound does not configure ALPN, so that entry is normally empty; REALITY negotiates `h2`/`http/1.1`. |
| `path` | Request path, parsed from the first bytes of an HTTP request. Empty means the wildcard. Must be empty or start with `/`. |
| `type` | `tcp` or `unix`. It may not be empty while `dest` is set (startup error); a non-empty unknown value is rejected only when the fallback is dialed (`unsupported fallback type`), not at startup. |
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
| `flow` | Optional. Set to `xtls-rprx-vision` to request the client-side Vision flow; an empty value sends no flow (empty addons blob). |
| `encryption` | Optional VLESS encryption. Empty or `none` disables it; a `mlkem768x25519plus.…` scheme enables it (see [VLESS encryption](#vless-encryption-mlkem768x25519plus)). |

When `flow` is `xtls-rprx-vision` the outbound sends the flow in the request
addons and wraps the body in the Vision record layer. The leading write is
long-padded; if no payload is available within 500 ms an empty long-padded
block is sent first, mirroring Xray's client. Both TCP and UDP are supported;
UDP uses the same `cmd=2` framing as the inbound (and never carries a flow).

Vision requires a TLS/REALITY outer transport, so chain the outbound behind a
`tls` (TLS 1.3) or `reality` outbound. A vision-configured server rejects a
plain (non-TLS) request for a vision account.

```yaml
outbounds:
  - tag: vless_out
    protocol: vless
    settings:
      address: 192.0.2.1
      port: 443
      uuid: b831381d-6324-4d53-ad4f-8cda48b30811
      flow: xtls-rprx-vision
```

## VLESS encryption (`mlkem768x25519plus`)

The inbound `decryption` and outbound `encryption` settings accept Xray's
`mlkem768x25519plus` scheme. The hybrid ML-KEM-768 + X25519 handshake runs
before the VLESS request header, and the header and body are then carried as
AEAD records (the VLESS protocol itself is unchanged). A session that fails the
handshake aborts; it is never downgraded to plaintext.

The accepted grammar (`encryption/scheme.rs`) is:

```text
server (decryption): mlkem768x25519plus.{native|xorpub|random}.{N[s]|N-M[s]}.[padding.]{key}[.{key}]
client (encryption): mlkem768x25519plus.{native|xorpub|random}.{0rtt|1rtt}.[padding.]{key}[.{key}]
```

* **Disguise** — `native`, `xorpub` or `random`. `xorpub` XORs the ephemeral
  public keys of the relay chain with an AES-256-CTR stream keyed from the
  configured key and the IV; `random` additionally XORs the 5-byte header of
  every record.
* **Client mode** — `1rtt` or `0rtt`.
* **Server lifetime** — `N`, `Ns`, `N-M` or `N-Ms`; a single trailing `s`
  belongs to the whole field and is stripped before the field is split on its
  first `-`, so `Ns-M` and `Ns-Ms` are invalid. A single value `N` is not a
  fixed lifetime: the server picks a random value in `[N/2, N)`; the `N-M` form
  picks a random value in `[N, M)`.
* **Padding and keys** — the dot-separated fields that precede the first field
  of 20 or more characters; fields shorter than 20 characters are padding. The
  remaining fields are the keys (base64url, no padding). A key is X25519 (32
  bytes) or ML-KEM-768: the client supplies the 1184-byte encapsulation key,
  the server the 64-byte private seed. At least one key is required; any other
  key length is a startup error.

### Supported

* `native`, `xorpub` and `random` disguise;
* the `1rtt` client handshake and the full server lifetime grammar;
* the AEAD record layer: 8192-byte plaintext chunks framed with a TLS-shaped
  `17 03 03 <len:2>` header (accepted ciphertext length `17..=16640`),
  AES-256-GCM by default and ChaCha20-Poly1305 when the AES hardware path is
  unavailable — the server guesses AES and switches to ChaCha on the first
  record;
* a fresh hybrid key exchange per session: the client sends a 16-byte IV, one
  relay entry per configured key, and an ML-KEM-768 encapsulation key plus an
  X25519 public key; the server answers with an ML-KEM-768 ciphertext plus an
  X25519 public key. The ML-KEM and X25519 shared secrets are concatenated and
  mixed with the relay-derived key, and every handshake key is a BLAKE3
  derive-key output;
* the server still issues the 16-byte ticket whose first two bytes carry the
  advertised lifetime.

### Not supported

Both gaps fail closed as named errors, never as a silent downgrade:

* **Client `0rtt`** — rejected while parsing the outbound `encryption` setting
  (`EncryptionError::Unsupported`, the message names `0rtt`). There is no
  ticket cache; configure `1rtt` instead.
* **Server 0-RTT hello** — a client hello whose decrypted length is 32 (Xray's
  0-RTT ticket handshake) is rejected at connection time
  (`VLESS encryption: 0-RTT tickets are not implemented in this build`). There
  is no session store and no replay protection.

As a result a VLESS client configured for 0-RTT (e.g. Xray) does not
interoperate with this server; the account must use 1-RTT.

### Configuration rules

* On the inbound, `decryption` may be empty, `none`, or a
  `mlkem768x25519plus.…` scheme. A real scheme is mutually exclusive with
  `fallbacks`: combining them is a startup error
  (`"fallbacks" cannot be used together with "decryption"`), because the
  handshake consumes bytes before the VLESS request header is seen and a
  fallback could not be handed the connection verbatim (Xray
  `infra/conf/vless.go:157`).
* A per-user `encryption` in `users` is still rejected
  (`VLESS users: "encryption" should not be in inbound settings`), matching
  Xray (`infra/conf/vless.go:84`): encryption is configured once per inbound,
  not per user.
* `level` is parsed but not used.
