# TLS options

The `tls` protocol is a transport built on rustls (features `rustls-tls` plus a
crypto-provider selection; a reduced OpenSSL path exists for the outbound). This
chapter lists the options that are actually implemented, as parsed from
YAML/JSON. Keys are shown in their camelCase spelling; the snake_case alias is
accepted where one exists.

## Inbound

| Key | Default | Meaning |
|---|---|---|
| `certificate`, `certificateKey` | `""` | A single certificate/key pair. Inline PEM (containing `-----BEGIN`) or a file path. Used only when `certificates` is empty; both halves are required together. Keys are tried as PKCS#8, then PKCS#1, then SEC1. |
| `certificates` | `[]` | A list of `TlsCertificate` entries; takes precedence over the flat pair. |
| `rejectUnknownSni` | false | When true, an SNI that matches no certificate is rejected; when false the first certificate is used. |
| `minVersion`, `maxVersion` | rustls defaults | `1.0`–`1.3`. Values below 1.2 are clamped up to 1.2; a maximum below 1.2 (or `min > max`) is an error. |
| `cipherSuites` | — | Colon-separated **IANA** cipher-suite names. Applies to TLS ≤ 1.2 only; an unknown name is an error. |

`TlsCertificate` fields:

| Field | Meaning |
|---|---|
| `certificateFile`, `certificate[]` | File path or inline PEM blocks (the file wins). |
| `keyFile`, `key[]` | Key file path or inline PEM blocks. |
| `usage` | Only `""` (unset) or `"encipherment"` is accepted on the inbound; `verify`/`issue` are rejected. |
| `oneTimeLoading` | File-backed entries require `true`. |
| `ocspStapling`, `buildChain` | **Not supported** — a non-zero / `true` value is rejected. |

> Inbound ECH is **not supported**: `echConfig`/`echKey` and `echServerKeys` are
> rejected with an error.

## Outbound

| Key | Default | Meaning |
|---|---|---|
| `serverName` | `""` | TLS SNI. Empty (or `fromMitM`) uses the session destination host. |
| `alpn` | `[]` | ALPN protocols, applied in order. A single `fromMitM` entry expands to `["h2", "http/1.1"]`. |
| `certificate` | `""` | A custom CA list; when set it is **added** alongside the system roots unless `disableSystemRoot`. |
| `certificates` | `[]` | Root CA entries (each `usage` must be `"verify"`). System roots are kept unless `disableSystemRoot`. |
| `insecure` | false | Accept any server certificate. |
| `pinnedPeerCertSha256` | — | Comma-separated hex SHA-256 pins matched against the **leaf** certificate only; falls back to normal name/chain verification. |
| `verifyPeerCertByName` | — | Comma-separated names the certificate must be valid for; `fromMitM` expands to the server name and its parent domains. |
| `minVersion`, `maxVersion` | rustls defaults | Same mapping as the inbound. |
| `cipherSuites` | — | Colon-separated cipher-suite names. Note: the outbound matches rustls **Debug** names, unlike the inbound's IANA names. |
| `curvePreferences` | `[]` | Allowed key-exchange groups (e.g. `X25519`, `CurveP256`). |
| `enableSessionResumption` | false | When true, an in-memory session cache (128 entries) is used. |
| `disableSystemRoot` | false | Drop system roots; affects both the flat `certificate` and the `certificates` path. |
| `masterKeyLog` | — | Writes TLS keys for Wireshark; the configured path is honoured only when it matches `$SSLKEYLOGFILE`. |
| `fingerprint` | `""` | Only the literal `unsafe` (or unset) is accepted; uTLS fingerprints are not supported. |

ECH on the outbound (`ech`, `echConfigList`, `echDisableDnsLookup`) requires the
`rustls-tls-aws-lc` crypto provider and TLS 1.3; with the ring backend it is an
error at connect time. Without `echDisableDnsLookup` the config list is fetched
from DNS HTTPS/SVCB records, falling back to a fixed list.

### Not implemented on the outbound

- `certificateKey` (and its `rawCertificateKey` form) is **rejected** with an
  error — client certificate (mutual TLS) authentication is not implemented, so
  a certificate+key pair is never silently reinterpreted as a CA.
- Of the `TlsCertificate` sub-fields, only `usage`, `certificate`/`certificate_file`
  are used; `key_file`, `key`, `ocsp_stapling`, `one_time_loading` and
  `build_chain` are silently ignored.

## Backend differences

The OpenSSL backend rejects `pinnedPeerCertSha256`, `verifyPeerCertByName`,
`curvePreferences`, `masterKeyLog` and `disableSystemRoot`. The inbound
always uses rustls.

## clash-style `.conf`

The `.conf` format cannot express a TLS inbound. For outbounds it synthesises a
TLS actor for `trojan`/`vmess` and supports only these keys: `tls-cert`,
`tls-insecure`, `tls-ech`, `tls-ech-disable-dns-lookup`, `tls-ech-config-list`
and `sni`. All other TLS options are unavailable there.
