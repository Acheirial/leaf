# YAML Configuration

YAML is the **preferred** configuration format for Leaf. It is the format shown
throughout this document. JSON and clash-style `.conf` files remain fully
supported and behave exactly as before.

## Selecting a format

The format is chosen by the extension of the configuration file:

| Extension | Format |
|---|---|
| `.yml`, `.yaml` | YAML (preferred) |
| `.json` | JSON |
| `.conf` | clash-style `.conf` |

When a configuration is passed as a string rather than a file, a document that
is a YAML mapping carrying at least one recognised top-level key (`inbounds`,
`outbounds`, `dns`, `log`, `router`, `api`) is treated as YAML. JSON is still
detected ahead of YAML for input starting with `{` or `[`, and anything else
falls back to the clash-style parser.

## Example

The following is a complete configuration: it starts a SOCKS5 inbound, sends
traffic through the `direct` outbound, queries a pair of public DNS resolvers,
and applies a couple of router rules.

```yaml
log:
  level: info
  output: console

dns:
  servers:
    - 8.8.8.8
    - 1.1.1.1
  hosts:
    example.com:
      - 127.0.0.1

inbounds:
  - tag: socks_in
    address: 127.0.0.1
    port: 1086
    protocol: socks

outbounds:
  - tag: direct_out
    protocol: direct

router:
  domainResolve: true
  rules:
    - domainSuffix:
        - google.com
      target: direct_out
    - target: direct_out
```

Save it as `config.yml` and pass it to Leaf as its configuration file.

## Other supported formats

- **JSON** — same document structure, selected by the `.json` extension or by
  input starting with `{`.
- **clash-style `.conf`** — selected by the `.conf` extension (or as the
  fallback for unrecognised input). See the existing configuration comments in
  the repository for its syntax.

The three formats are interchangeable: the same `inbounds`, `outbounds`, `dns`,
`router`, and `log` sections are accepted by all of them.
