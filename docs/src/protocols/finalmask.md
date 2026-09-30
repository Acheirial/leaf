# FinalMask

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-finalmask`) |
| Outbound | ✅ (`outbound-finalmask`) |

FinalMask is a transport that rewrites the bytes on the wire: a header, a
segmentation, an obfuscation or an appearance transform applied in front of
another protocol. It is a transport pair — each side must be configured with a
matching set of masks — and it is normally chained (see
[chain](../routing.md#chain)) around the protocol it protects.

The inbound unmasks what it reads and masks what it writes; the outbound does
the opposite. Both directions accept the same mask types for the same transport,
but the two transports (TCP and UDP) have **different** mask sets.

The examples below are YAML.

## Settings

| Key | Meaning |
|---|---|
| `tcp` | List of TCP masks, each `{ maskType, settings }`. |
| `udp` | List of UDP masks. |
| `tcpTemplate` / `tcp_template` | A JSON object keyed by mask type holding default settings for TCP masks. |
| `udpTemplate` / `udp_template` | The same for UDP masks. |

Each mask's `settings` is a JSON **string** holding an object. At startup the
mask's own settings are deep-merged over the template defaults of the same
`maskType` (`tcpTemplate` for TCP, `udpTemplate` for UDP). With no masks
configured the transport is a no-op pass-through — no error.

Masks run in configuration order; a UDP mask may emit zero, one or several wire
packets (for example `noise` emits decoys first).

## Mask types

| `maskType` | TCP | UDP | What it does |
|---|---|---|---|
| `fragment` | ✅ | ❌ | Splits a write into several TCP segments; `tlshello` mode fragments the TLS ClientHello. |
| `header-custom` | ✅ | ✅ | Prepends a header built from a small expression language and verifies/strips it on the peer. |
| `sudoku` | ✅ | ✅ | Hides payload bytes as 4×4-Sudoku hint bytes (a password-seeded appearance transform). |
| `salamander` | ❌ | ✅ | Hysteria2's UDP obfuscator: 8-byte random salt + XOR with `BLAKE2b-256(psk ‖ salt)`. |
| `noise` | ❌ | ✅ | Sends decoy packets before the first real packet (and after a reset interval); the payload is untouched. |

Per-mask `settings` (all camelCase; invalid values are startup errors):

- **fragment** — `packets` (a range string, or `tlshello`), `length`/`lengths`,
  `delay`/`delays`, `maxSplit`. The last `lengths` entry must have a non-zero
  lower bound, so `fragment` with no settings is rejected rather than passing
  through.
- **header-custom** — TCP: `clients`, `servers`, `errors`, each an array of
  sequences of items; UDP: `mode` (`""` or `prefix`), `client`, `server`. An
  item is one of `packet` (with `type` `array`/`str`/`hex`), `rand` (+ optional
  `randRange`), `reuse`, `transform` (`op` + `args`), `capture`, `delay`. The
  supported transform ops are `concat`, `slice`, `xor16`, `xor32`, `be16`,
  `be32`, `le16`, `le32`, `le64`, `pad`, `truncate`, `add`, `sub`, `and`, `or`,
  `shl`, `shr`; TCP expressions cannot use address `metadata`.
- **salamander** — `password`, at least 4 bytes.
- **sudoku** — `password`, `ascii` (`""`/`entropy`/`prefer_entropy`/`ascii`/
  `prefer_ascii`), `customTable`/`customTables` (exactly 8 characters of `x`/`p`/`v`),
  `paddingMin`/`paddingMax`.
- **noise** — `reset`, `noise` items with `packet` or `rand` (+ optional
  `randRange`, `type`, `delay`).

## Limitations

- **Only the masks above exist.** Any other `maskType`, or an implemented mask
  used on the wrong transport (for example `fragment` under `udp`, `salamander`
  under `tcp`), fails at startup with
  `finalmask mask type [<name>] is not implemented`. Xray masks such as `realm`
  or `udphop` are not implemented.
- A missing `maskType` (`finalmask mask type is missing`), malformed `settings`
  JSON (`invalid finalmask settings json`), or a value the mask rejects
  (`invalid finalmask [<mask>]: <reason>`) is likewise startup-fatal. Nothing is
  silently passed through.
- At runtime, a UDP datagram whose mask cannot decode it is dropped (a
  `header-custom` size mismatch, a `salamander` packet shorter than 8 bytes, or
  a `sudoku` datagram that does not decode cleanly). TCP mask handshake failures
  surface as I/O errors on the first read or write.
- `noise` delays use a blocking sleep inside the encode path.

## Example (YAML)

TCP masks (fragment the TLS ClientHello, then a custom header):

```yaml
outbounds:
  - tag: finalmask_out
    protocol: finalmask
    settings:
      tcpTemplate: '{"header-custom":{"clients":[[{"packet":[1,2,3,4]}]],"servers":[[{"packet":[5,6,7,8]}]]}}'
      tcp:
        - maskType: fragment
          settings: '{"packets":"tlshello","length":{"from":40,"to":80}}'
        - maskType: header-custom
  - tag: tls_out
    protocol: tls
    settings:
      serverName: example.com
  - tag: vless_out
    protocol: vless
    settings:
      address: example.com
      port: 443
      uuid: b831381d-6324-4d53-ad4f-8cda48b30811
  - tag: masked_vless
    protocol: chain
    settings:
      actors: [finalmask_out, tls_out, vless_out]
```

UDP masks (salamander obfuscation over the datagram transport):

```yaml
outbounds:
  - tag: finalmask_udp
    protocol: finalmask
    settings:
      udp:
        - maskType: salamander
          settings: '{"password":"shared-secret"}'
  - tag: hysteria2_out
    protocol: hysteria2
    settings:
      server: example.com:443
      password: hunter2
      sni: example.com
  - tag: masked_udp
    protocol: chain
    settings:
      actors: [finalmask_udp, hysteria2_out]
```

On the receiving side, configure the mirror masks on a `finalmask` inbound
chained in front of the payload protocol:

```yaml
inbounds:
  - tag: finalmask_in
    address: 0.0.0.0
    port: 443
    protocol: finalmask
    settings:
      tcp:
        - maskType: fragment
          settings: '{"packets":"tlshello","length":{"from":40,"to":80}}'
        - maskType: header-custom
          settings: '{"clients":[[{"packet":[1,2,3,4]}]],"servers":[[{"packet":[5,6,7,8]}]]}'
  - tag: tls_in
    protocol: tls
    settings:
      certificate: /etc/leaf/cert.pem
      certificateKey: /etc/leaf/key.pem
  - tag: masked_in
    address: 0.0.0.0
    port: 8443
    protocol: chain
    settings:
      actors: [finalmask_in, tls_in]
```
