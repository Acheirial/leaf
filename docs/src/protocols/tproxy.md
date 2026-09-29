# TPROXY

| Direction | Supported |
|---|---|
| Inbound | ⚠️ Linux only |
| Outbound | ❌ |

A transparent-proxy inbound that recovers the original destination of
intercepted connections. The implementation is **Linux-only**: it uses
`IP_TRANSPARENT`, `IP_RECVORIGDSTADDR` and `SO_ORIGINAL_DST` / `SO_ORIGINAL_DST`
(IPv6 variant), and the handler constructors return `Unsupported` on other
targets, causing the listener to fail fast.

It is intended to be used with `iptables`/`nftables` TPROXY rules plus policy
routing; UDP replies are spoofed from the original destination.

## Configuration

A `tproxy` inbound is expressed like any other inbound. The listener address and
port come from the inbound entry's own `address`/`port` fields; the protocol
takes **no options**, so the `settings` object is empty (and may be omitted
entirely). Any field inside `settings` is rejected as unknown rather than being
silently ignored.

```yaml
inbounds:
  - tag: tproxy_in
    protocol: tproxy
    address: 0.0.0.0
    port: 12345
```

The equivalent JSON:

```json
{
  "inbounds": [
    {
      "tag": "tproxy_in",
      "protocol": "tproxy",
      "address": "0.0.0.0",
      "port": 12345
    }
  ]
}
```

The clash-style `.conf` format has no inbound section, so it cannot express a
`tproxy` inbound.

### Example `iptables` rules

```sh
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

iptables -t mangle -N TPROXY
iptables -t mangle -A TPROXY -p tcp -j TPROXY --on-port 12345 --tproxy-mark 0x1/0x1
iptables -t mangle -A TPROXY -p udp -j TPROXY --on-port 12345 --tproxy-mark 0x1/0x1
```

The equivalent `nftables` rules:

```nft
table ip tproxy {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto { tcp, udp } tproxy to :12345 meta mark set 0x1
    }
}
```

## Outbound

Not implemented.
