# QUIC

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-quic`) |
| Outbound | ✅ (`outbound-quic`) |

A QUIC transport (over rustls). It demultiplexes QUIC bidirectional streams into
individual proxy streams and uses BBR congestion control.

## Inbound settings

| Key | Meaning |
|---|---|
| `certificate`, `certificateKey` | Server certificate and key. Inline PEM (containing `-----BEGIN`) or a file path; `.der` files are loaded as DER. |
| `alpn` | List of ALPN protocol names. |

```yaml
inbounds:
  - tag: quic_in
    address: 0.0.0.0
    port: 443
    protocol: quic
    settings:
      certificate: /etc/leaf/cert.pem
      certificateKey: /etc/leaf/key.pem
      alpn: [h3]
```

## Outbound settings

| Key | Meaning |
|---|---|
| `address`, `port` | Server endpoint. |
| `serverName` | TLS SNI; defaults to `address` when empty. |
| `certificate` | Root CA to trust (inline PEM or file, `.der` supported). |
| `alpn` | List of ALPN protocol names. |

```yaml
outbounds:
  - tag: quic_out
    protocol: quic
    settings:
      address: example.com
      port: 443
      serverName: example.com
      alpn: [h3]
```

> The outbound's `certificateKey` field is parsed but client certificate
> authentication is not yet implemented.

Transport limits come from the `QUIC_MAX_CONCURRENT_BIDI_STREAMS`,
`QUIC_MAX_IDLE_TIMEOUT_MS` / `QUIC_SERVER_MAX_IDLE_TIMEOUT_MS` and
`QUIC_KEEP_ALIVE_INTERVAL_MS` options/environment variables.
