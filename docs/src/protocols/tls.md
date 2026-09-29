# TLS

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-tls`) |
| Outbound | ✅ (`outbound-tls`) |

TLS as a transport wrapping another protocol, built on rustls. The full option
list is on the [TLS options](../tls.md) page.

## Inbound

Terminates TLS and presents a certificate to the client. Certificates are
selected by SNI: the first configured certificate is the default, and every
certificate is indexed by the DNS names from its SANs and subject CN (with a
one-level wildcard match).

## Outbound

Initiates TLS. The outbound has no destination of its own — its
`connect_addr` is `Next`, so a bare TLS outbound cannot dial. It must be used as
an actor of a [chain](../routing.md#chain) or another group, whose dialing
protocol supplies the endpoint:

```yaml
outbounds:
  - tag: tls_out
    protocol: tls
    settings:
      serverName: example.com
      alpn: [h2, http/1.1]
  - tag: vmess_out
    protocol: vmess
    settings:
      address: 203.0.113.10
      port: 443
      uuid: 00000000-0000-0000-0000-000000000000
  - tag: vmess_over_tls
    protocol: chain
    settings:
      actors: [tls_out, vmess_out]
```

## Inbound example

```yaml
inbounds:
  - tag: tls_in
    address: 0.0.0.0
    port: 8443
    protocol: tls
    settings:
      certificates:
        - certificateFile: server.crt
          keyFile: server.key
          usage: encipherment
          oneTimeLoading: true
      rejectUnknownSni: false
      minVersion: "1.2"
      maxVersion: "1.3"
```

Certificate and key values may be inline PEM (containing `-----BEGIN`) or file
paths.

> The clash-style `.conf` format cannot express a TLS inbound, and only a narrow
> subset of TLS outbound options (see [TLS options](../tls.md)).
