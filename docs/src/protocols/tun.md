# TUN

| Direction | Supported |
|---|---|
| Inbound | ✅ (`inbound-tun`) |
| Outbound | ❌ |

A TUN device inbound that captures IP traffic and feeds it to the proxy stack
through a userspace TCP/IP stack (lwIP or smoltcp).

## Platform support

TUN settings compile for `ios`, `android`, `macos`, `linux` and `windows`; on
any other target the configuration is rejected with
`tun inbound is not supported on this platform`. Host route/interface plumbing
runs on **Linux and macOS**; Windows uses the WinTun backend plus the derived
`OUTBOUND_INTERFACE`, and iOS/Android compile the settings but do not perform
host setup here.

## Inbound settings

| Key | Meaning |
|---|---|
| `fd` | Attach to an existing TUN file descriptor (default `-1` = unused). Mutually exclusive with `auto`. |
| `auto` | Use built-in name/address/gateway defaults. |
| `name` | Device name. |
| `address`, `gateway`, `netmask`, `mtu` | Explicit device configuration (`netmask` is ignored on mips). |
| `tun2socks` | `smoltcp` selects the smoltcp netstack; anything else (or unset) selects lwIP. |
| `fakeDnsExclude`, `fakeDnsInclude` | Fake-DNS domain lists; mutually exclusive. |
| `wintun` | Windows only: path to the WinTun DLL. |
| `dnsServers` | Windows only: adapter DNS servers. |

```yaml
inbounds:
  - tag: tun_in
    protocol: tun
    settings:
      name: tun0
      address: 10.0.0.1
      gateway: 10.0.0.2
      netmask: 255.255.255.0
      mtu: 1500
      tun2socks: smoltcp
```

or simply `settings: { auto: true }`.

In clash-style `.conf`, a single `tun` inbound is produced by `[General]` keys
`tun`, `tun-fd`, `tun2socks-backend`, `wintun` and `tun-dns-server`.

## Outbound

Not implemented.
