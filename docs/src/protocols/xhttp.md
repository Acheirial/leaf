# XHTTP

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-xhttp`) |
| Outbound | ✅ (`outbound-xhttp`) |

XHTTP (Xray's `transport/internet/splithttp`) carries a proxy stream inside
ordinary HTTP requests. This port implements the HTTP/1.1 form by hand, because
the crate pulls in no HTTP client or server library: plaintext XHTTP speaks
HTTP/1.1, one request per connection (Xray's `DisableKeepAlives` behaviour).

XHTTP is a **stream transport only**. There is no datagram transport of its own:
UDP travels inside the stream as ordinary payload. The inbound registers a
datagram handler, but it only rejects what it is handed
(`xhttp does not support an inbound datagram transport`).

The examples below are YAML.

## Inbound settings

| Key | Default | Meaning |
|---|---|---|
| `host` | `""` | When non-empty, the `Host` header must match (port ignored, case-insensitive) or the request gets `404`. |
| `path` | `/` | Prefix the request path must start with; the remainder carries the session id / sequence when those are placed in the path. |
| `mode` | `auto` | One of `auto`, `packet-up`, `stream-up`, `stream-one`. Any other value is a startup error. |
| `extra` | — | A JSON string of Xray `extra` options (see below). |
| `downloadSettings` / `download_settings` | — | Parsed into the config but **not used**. |
| `maxUploadSize` / `max_upload_size` | — | Parsed into the schema but **not used**; the enforced per-POST limit is `scMaxEachPostBytes` (`413 Payload Too Large`). |

### Modes

| Mode | Wire shape |
|---|---|
| `stream-one` | A single chunked POST carries both directions: the request body is the uplink and the response body is the downlink. |
| `stream-up` | A chunked POST for the uplink plus a second connection issuing the downlink GET. |
| `packet-up` | A downlink GET plus one POST per uplink chunk, each on a fresh connection with a `seq`. |
| `auto` | Dials as `packet-up` (the dial always speaks plain HTTP/1.1). |

The inbound accepts all four and validates the request shape per mode, answering
`400 Bad Request` on a mismatch; a request that is neither an uplink POST nor a
downlink GET gets `405 Method Not Allowed`. Outbound dials `stream-one` →
`stream-one`, `stream-up` → `stream-up`, and everything else (including `auto`)
→ `packet-up`.

### `extra`

`extra` is a JSON **string** holding an object. It replaces every configurable
field except `host`, `path` and `mode`. Recognised keys include:

`headers`, `xPaddingBytes`, `xPaddingObfsMode`, `xPaddingKey`, `xPaddingHeader`,
`xPaddingPlacement`, `xPaddingMethod`, `noGRPCHeader`, `noSSEHeader`,
`scMaxEachPostBytes`, `scMinPostsIntervalMs`, `scMaxBufferedPosts`,
`scStreamUpServerSecs`, `uplinkHTTPMethod`, `sessionIDPlacement`,
`sessionIDKey`, `sessionIDTable`, `sessionIDLength`, `seqPlacement`, `seqKey`,
`uplinkDataPlacement`, `uplinkDataKey`, `uplinkChunkSize`,
`serverMaxHeaderBytes`, `xmux`.

Selected defaults (as Xray): `scMaxEachPostBytes` `{1000000,1000000}`,
`scMinPostsIntervalMs` `{30,30}`, `scMaxBufferedPosts` `30`,
`scStreamUpServerSecs` `{20,80}`, `serverMaxHeaderBytes` `8192`,
`xPaddingBytes` `{100,1000}`, padding method `repeat-x`, padding header
`X-Padding`, padding key `x_padding`, padding placement `queryInHeader`,
`uplinkHTTPMethod` `POST`, session/seq placement `path` (keys `x_session` /
`x_seq` in query or cookie, `X-Session` / `X-Seq` in a header),
`uplinkDataPlacement` `auto`.

Validation errors are startup-fatal: `headers` may not contain `host`,
`xPaddingBytes` cannot be disabled, `uplinkHTTPMethod` may be `GET` only in
`packet-up`, `uplinkDataPlacement` may be `cookie`/`header` only in `packet-up`,
and `maxConnections` and `maxConcurrency` are mutually exclusive.

Padding is generated as `repeat-x`. `tokenish` padding is *validated* exactly
as the reference does, by the HPACK Huffman-encoded length of the value (the
static RFC 7541 table is embedded rather than pulling in an HPACK library), so a
reference `tokenish` client is accepted. Generation still emits `repeat-x`:
`X` has an 8-bit Huffman code, so its encoded length equals its raw length and
also satisfies `tokenish`.

### Limitations

- **No h2c or HTTP/3.** Only HTTP/1.1 is generated and parsed; the crate has no
  HTTP library, so an HTTP/2 or HTTP/3 form is simply not spoken. Put a TLS
  actor in front if a cryptographic wrapper is needed.
- **`xmux` is parsed but not enforced.** Only the
  `maxConnections`/`maxConcurrency` mutual-exclusion check is applied. The
  transport is one request per connection, so there is no connection reuse or
  keep-alive for `maxConcurrency`, `cMaxReuseTimes`, `hMaxRequestTimes`,
  `hMaxReusableSecs` or `hKeepAlivePeriod` to act on.
- `downloadSettings` and `maxUploadSize` are accepted but ignored (above).
- The in-process session table holds at most `MAX_SESSIONS = 4096` sessions
  (oldest evicted). A session whose downlink GET has not connected is reaped
  after 30 s (the reference's TTL, `hub.go` `upsertSession`), so a POST-only
  session cannot pin its upload channel indefinitely. The `packet-up`
  reassembly queue is bounded by `scMaxBufferedPosts`.
- **Remaining divergences from the reference**, none of which affect HTTP/1.1
  framing or ordinary traffic: `OPTIONS` is not special-cased and no
  `Access-Control-*` headers are ever emitted, where the reference answers a
  CORS preflight with `200` (`hub.go` `requestHandler.ServeHTTP` and
  `WriteResponseHeader`, `config.go:99`); a `stream-up` POST gets no periodic
  padding heartbeats (`hub.go` `scStreamUpServerSecs`); response padding is
  emitted only on the downlink response and only for the `header`,
  `queryInHeader` and `cookie` placements, where the reference also pads POST
  responses (`hub.go` `ServeHTTP` calls `ApplyXPaddingToResponse` for every
  method); the client
  percent-encodes query values with its own encoder rather than Go's
  `url.Values.Encode()`, which differs byte-for-byte for characters outside the
  unreserved set (both ends still decode the same value for the common cases);
  session ids are drawn from the `rand` crate's thread RNG rather than
  `crypto/rand`, and a non-empty `sessionIDTable` with no positive
  `sessionIDLength` is a startup error here where the reference silently falls
  back to a v4 UUID (`config.go` `GenerateSessionID`); and `downloadSettings`
  and the `xmux` defaults are parsed but not applied.

### Inbound example

XHTTP is a transport, so the accepted stream still has to be spoken to a proxy
protocol. Compose them with a `chain` inbound:

```yaml
inbounds:
  - tag: xhttp_in
    address: 0.0.0.0
    port: 443
    protocol: xhttp
    settings:
      host: example.com
      path: /x
      mode: packet-up
      extra: '{"scMaxEachPostBytes":{"from":2000000,"to":2000000}}'
  - tag: vless_in
    protocol: vless
    settings:
      users:
        - b831381d-6324-4d53-ad4f-8cda48b30811
  - tag: xhttp_vless_in
    address: 0.0.0.0
    port: 8443
    protocol: chain
    settings:
      actors: [xhttp_in, vless_in]
```

## Outbound settings

| Key | Meaning |
|---|---|
| `host` | `Host` header of the request; overrides the dial destination's host when set. |
| `path` | Request path (normalized to a leading and trailing slash). |
| `mode` | As above; `auto` dials as `packet-up`. |
| `extra` | Same JSON options as the inbound (`downloadSettings` is inbound-only). |
| `maxUploadSize` / `max_upload_size` | Accepted but not used. |

The outbound has no destination of its own (`connect_addr` is `Next`): it wraps
the connection dialled by another actor, so it must be used inside a `chain`. A
typical client is VLESS over XHTTP over TLS:

```yaml
outbounds:
  - tag: tls_out
    protocol: tls
    settings:
      serverName: example.com
      alpn: [h2, http/1.1]
  - tag: xhttp_out
    protocol: xhttp
    settings:
      host: example.com
      path: /x
      mode: packet-up
  - tag: vless_out
    protocol: vless
    settings:
      address: example.com
      port: 443
      uuid: b831381d-6324-4d53-ad4f-8cda48b30811
  - tag: vless_over_xhttp
    protocol: chain
    settings:
      actors: [tls_out, xhttp_out, vless_out]
```
