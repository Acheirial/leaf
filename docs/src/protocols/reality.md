# Reality

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-reality`) |
| Outbound | ✅ (`outbound-reality`) |

Xray Reality: the outbound masquerades as a TLS connection to a real site, and
the inbound authenticates those clients and impersonates that site for everyone
else. This chapter documents both directions. The inbound is TCP-only.

## Inbound

The inbound runs a hand-rolled TLS ClientHello parser in front of rustls. A
connection whose ClientHello proves knowledge of the server's X25519 private key
is served a rustls session; every other connection is relayed verbatim to the
real site (`dest`).

### Inbound settings

| Key | Default | Meaning |
|---|---|---|
| `privateKey` / `private_key` | — | Server X25519 private key. **Required.** 32 bytes, base64url without padding or hex. |
| `serverNames` / `server_names` | — | Allow-list of TLS SNI values. **Required** and non-empty. Auth is gated on a case-insensitive exact match; the list does not select a certificate or destination. |
| `shortIds` / `short_ids` | — | Allow-list of hex short ids. **Required** and non-empty. Each is decoded to 8 bytes; more than 16 hex characters is an error, and an odd length is rejected (unlike Xray, which pads). An empty string is the all-zero id. |
| `dest` | `target[0]` | Address dialed on the steal path (`host:port`). Required, directly or via `target`. |
| `target` | — | Fallback list; **only the first entry is used**, and only when `dest` is absent. |
| `show` | `false` | Log authenticated and rejected connections. No behavioural effect. |
| `xver` | `0` | PROXY protocol version prepended to the **steal path** connection: `0` none, `1` v1 ASCII, `2` v2 binary. Values above `2` are a startup error. |
| `maxTimeDiffMs` / `max_time_diff_ms` | unset or `0` (no check) | Maximum accepted clock difference, in milliseconds, between the client's embedded timestamp and the server clock. Resolution is one second. |

ALPN is fixed to `h2` and `http/1.1` and is not configurable.

### Authentication

A client proves itself by sending a TLS 1.3 ClientHello with:

- a 32-byte `session_id`, which is the AES-256-GCM encryption of
  `version[3] || 0 || unix_time_be[4] || short_id[8]`;
- a key share of group X25519MLKEM768 (4588), contributing its X25519 half,
  and/or a plain X25519 (29) key share; no other group authenticates. A
  duplicate share of either group, or a plain X25519 share that precedes the
  hybrid, takes the steal path;
- an SNI matching `serverNames`.

The server derives the AES key as
`HKDF-SHA256(ikm = x25519(privateKey, client_pub), salt = ClientHello.random[0..20], info = "REALITY")`,
uses `random[20..32]` as the nonce, and opens `session_id` with the ClientHello
as additional data (with the `session_id` field zeroed). It then checks the
decrypted short id against `shortIds` and the timestamp against
`maxTimeDiffMs`. There is no server-side replay cache; freshness rests on the
timestamp window and short id, plus TLS 1.3's requirement of the client's
ephemeral key.

On success the client is served a rustls session whose certificate is the
embedded dummy Ed25519 certificate with its last 64 bytes overwritten by
`HMAC-SHA512(key = AuthKey, msg = <server public key>)` — the REALITY marker the
client verifies.

### Steal path

Any connection that does not authenticate — no or wrong SNI, not TLS 1.3, no
acceptable key share, wrong `session_id` length, bad decryption, unknown short
id, a timestamp outside the window, or a first record that is not a parseable
TLS ClientHello (plain HTTP, a TLS 1.0/1.1 handshake, any probe) — is handled by
dialing `dest` over plain TCP, optionally writing a PROXY protocol header
(`xver`), replaying every byte already read from the client verbatim, and then
splicing both directions. leaf does **not** terminate TLS or emit a TLS alert on
this path; the client simply continues its handshake with the real site and sees
its certificate. If `dest` is unreachable the client gets a connection error.

The dial and the replay of the consumed bytes happen before the inbound handler
returns, so a dial failure still surfaces; the splice then runs in the
background for the connection's lifetime, so a relayed connection is not subject
to the listener's accept timeout.

### Limits

- TLS 1.3 only for authentication; TLS 1.2 ClientHellos take the steal path.
- Key exchange limited to X25519 and X25519MLKEM768.
- X25519MLKEM768 is not required to *authenticate*: leaf's inbound accepts a
  ClientHello carrying only a plain X25519 share, so leaf-to-leaf still works
  even from a `default-ring` build. Xray's server rejects such a ClientHello —
  it requires the hybrid share before any plain X25519 one — and leaf's outbound
  mirrors that ordering (see Outbound below).
- One static embedded certificate serves every `serverNames` entry.
- No `target` round-robin: only `target[0]` is ever consulted.
- `xver` applies to the steal path only; authenticated clients never get a PROXY
  header.

### Example (YAML)

```yaml
inbounds:
  - tag: reality_in
    address: 0.0.0.0
    port: 443
    protocol: reality
    settings:
      dest: www.example.com:443
      serverNames:
        - www.example.com
      privateKey: <32-byte base64url or hex X25519 private key>
      shortIds:
        - ""
        - 0123456789abcdef
      maxTimeDiffMs: 60000
```

## Outbound

| Key | Meaning |
|---|---|
| `serverName` / `server_name` | TLS SNI (the masqueraded site). |
| `publicKey` / `public_key` | The server's X25519 public key: 32 bytes, hex or URL-safe base64 without padding. |
| `shortId` / `short_id` | Hex short id, zero-padded on the right to 16 hex characters (8 bytes); may be empty. A value that is not valid hex is an error. |

The outbound reuses the TLS transport and pins ALPN to `h2` and `http/1.1`. It
is a stream-only handler.

A server certificate that does not carry a matching REALITY HMAC aborts the
handshake before any application data is sent: unlike a plain TLS client, the
outbound never falls back to public-root validation, so a non-REALITY peer
(e.g. a MITM or a redirected connection) cannot be mistaken for the server.

### ClientHello key exchange

leaf's outbound offers `X25519MLKEM768` as its first key share, immediately
followed by a plain `X25519` share that reuses the hybrid's X25519 key — the
ordering Xray/uTLS uses, and the ordering an Xray/REALITY server requires
(`reality-ref/tls.go:216-236` rejects a ClientHello whose plain `X25519` share is
not preceded by the hybrid). Both the REALITY `AuthKey` ECDH and, when the server
selects it, the TLS key exchange itself use that same X25519 key pair.

This needs the `default-aws-lc` feature (leaf's default), whose aws-lc-rs
provider supplies ML-KEM-768. Under `default-ring` no ML-KEM is available, so the
outbound can offer only a plain `X25519` share: it still connects to another leaf
inbound, but an Xray/REALITY server treats it as a probe and forwards it to the
masquerade site. leaf logs a warning on the first such connection. Build with
`default-aws-lc` (and without `default-ring`) for Xray interoperability.

```yaml
outbounds:
  - tag: reality_out
    protocol: reality
    settings:
      serverName: www.example.com
      publicKey: <32-byte hex or base64url>
      shortId: <hex>
```
