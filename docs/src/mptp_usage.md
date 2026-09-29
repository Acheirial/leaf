# MPTP Usage

## Overview

MPTP (Multipath Transport Protocol) combines multiple outbound paths into one logical transport channel.
In Leaf, the common deployment is:

- Client side: local `socks` inbound + `mptp` outbound
- Server side: `mptp` inbound + `direct` outbound

## Configuration

### JSON Config

Client example (`client.json`):

```json
{
  "inbounds": [
    {
      "protocol": "socks",
      "address": "127.0.0.1",
      "port": 1086
    }
  ],
  "outbounds": [
    {
      "protocol": "mptp",
      "settings": {
        "actors": [
          "direct1",
          "direct2"
        ],
        "address": "127.0.0.1",
        "port": 3001
      }
    },
    {
      "protocol": "direct",
      "tag": "direct1"
    },
    {
      "protocol": "direct",
      "tag": "direct2"
    }
  ]
}
```

Server example (`server.json`):

```json
{
  "inbounds": [
    {
      "protocol": "mptp",
      "address": "0.0.0.0",
      "port": 3001
    }
  ],
  "outbounds": [
    {
      "protocol": "direct"
    }
  ]
}
```

Key fields:

- `outbounds[].protocol = "mptp"`: enables MPTP client outbound
- `settings.actors`: list of outbound tags used as sub-connections
- `settings.address`, `settings.port`: MPTP server address and port
- `inbounds[].protocol = "mptp"`: enables MPTP server inbound listener

### conf Config

MPTP outbound can also be configured in `[Proxy Group]`:

```conf
[Proxy Group]
MptpOutTag = mptp, actor1, actor2, actor3, address=1.2.3.4, port=10000
```

## Running

This repository ships the core library only (`leaf`); build it and embed it in your own binary:

```bash
cargo build -p leaf --release
```

```rust
use leaf::{start, Config, RuntimeOption, StartOptions};

fn main() -> Result<(), leaf::Error> {
    // Optional: validate the config before startup.
    leaf::test_config("client.json")?;

    start(
        0,
        StartOptions {
            config: Config::File("client.json".to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: RuntimeOption::SingleThread,
        },
    )?;

    // Call `leaf::reload(0)` to re-read the config, `leaf::shutdown(0)` to stop.
    std::thread::park();
    Ok(())
}
```

Start one process with `server.json` (or a second runtime id in the same process) and another with `client.json`.

## Validation

1. Configure your app to use local SOCKS5 proxy `127.0.0.1:1086`.
2. Start with simple connectivity checks:

```bash
curl --socks5 127.0.0.1:1086 https://example.com
```

3. Verify configuration syntax before production startup with `leaf::test_config(path)` (see above).

## Notes

- `actors` should include at least two outbounds to achieve multipath aggregation.
- Ensure each actor tag exists in `outbounds`.
- Open server listening port (for example `3001`) in firewall/security group.
