# Development

This repository contains the `leaf` crate (the core library) and nothing else —
there is no binary. Everything below is exercised by
`.github/workflows/ci.yml`, `.github/workflows/release.yml` and the `Makefile`.

## Build and test

```sh
# Build the library in release mode.
cargo build -p leaf --release

# Run the test suite (the CI form).
cargo test -p leaf

# Makefile conveniences:
make build      # cargo build -p leaf --release
make test       # cargo test -p leaf -- --nocapture
make doc        # cargo doc -p leaf --no-deps
make proto-gen  # regenerate protobuf bindings (see below)
```

Formatting is checked in CI with `cargo fmt --all -- --check`.

## Feature flags

`leaf` is feature-gated per protocol and per config format, so a build only
compiles the endpoints it needs. The default feature is `default-aws-lc`:

| Bundle | Enables |
|---|---|
| `default-aws-lc` (default) | all configs + all endpoints, AWS-LC crypto, rustls TLS, AWS-LC QUIC, DNS over TLS and QUIC, `api` |
| `default-ring` | same, but with the `ring` crypto provider |
| `default-openssl` | all configs + all endpoints, OpenSSL TLS/crypto, `ring` QUIC, DNS over TLS and QUIC (**no `api`**) |

Grouping features:

- `all-configs` = `config-conf` + `config-json` + `config-yaml`.
- `all-endpoints` = every `inbound-*` and `outbound-*` feature.

Config-format features: `config-conf` (`regex`), `config-json` (`serde`,
`serde_json`), `config-yaml` (`serde`, `serde_yaml_ng`).

Per-protocol features: `inbound-X` / `outbound-X` for each supported protocol.
They gate compilation of the corresponding module and the match arm in the
inbound/outbound manager; a protocol whose feature is disabled simply does not
exist in that build.

Toggle features (not in any bundle): `plugin` (external plugin outbounds),
`api` (HTTP API server), `auto-reload` (config file watcher), `ctrlc`
(Ctrl-C handling), `rule-process-name` (process-name router rules, pulls
`regex`).

Minimal builds look like:

```sh
# Direct-only, YAML config.
cargo build -p leaf --no-default-features --features outbound-direct,config-yaml

# SOCKS in/out.
cargo build -p leaf --no-default-features \
  --features inbound-socks,outbound-socks,outbound-direct,config-yaml

# Trojan over TLS needs a TLS backend selected explicitly.
cargo build -p leaf --no-default-features \
  --features outbound-trojan,outbound-tls,outbound-direct,rustls-tls,rustls-tls-ring,ring-aead,config-yaml
```

The crypto provider is selected with `rustls-tls-ring` / `rustls-tls-aws-lc`
(or the OpenSSL features). Note that `dns-quic` pulls `quinn-ring`, so even the
`default-aws-lc` bundle enables `ring` for the QUIC DNS transport.

## CI jobs

`ci.yml` runs on every push and pull request:

- `test` — `cargo test -p leaf` on Ubuntu and macOS.
- `build` — `cargo build -p leaf --release`.
- `build-cross` — `cross build --release -p leaf --target <t>` for
  `x86_64-unknown-linux-musl`, `i686-unknown-linux-musl`,
  `aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf` and
  `x86_64-pc-windows-gnu`.
- `feature-matrix` — `cargo build -p leaf --no-default-features --features <f>`
  for `default-ring`, `default-openssl` and `config-json`.
- `docs` — `mdbook build docs` **and** `cargo doc -p leaf --no-deps`.
- `proto-check` — regenerates the protobuf bindings and fails if the checked-in
  `config.rs` differs.
- `fmt` — `cargo fmt --all -- --check`.

The separate `.github/workflows/docs.yml` builds the mdBook plus rustdoc and
deploys it to GitHub Pages (see [Introduction](introduction.md)).

`Cross.toml` overrides only the `x86_64-pc-windows-gnu` target with a custom
cross image and a pre-build symlink of clang's `mm_malloc.h`, because
`netstack-lwip`'s build script parses lwIP headers for that target.

## Reference checkouts and self-maintained forks

Four dependencies are pulled from git (all hosted under the same GitHub org as
this repository) and pinned by exact `rev`:

| Crate | Git URL | Used by |
|---|---|---|
| `reality` | `https://github.com/Acheirial/reality-rs.git` | `inbound-reality`, `outbound-reality` |
| `reality-rustls` (published as `rustls`) | `https://github.com/Acheirial/reality-rustls.git` | `inbound-reality`, `outbound-reality` |
| `netstack-lwip` | `https://github.com/Acheirial/netstack-lwip` | `inbound-tun` |
| `netstack-smoltcp` | `https://github.com/Acheirial/netstack-smoltcp` | `inbound-tun` |

`reality-rustls` is a REALITY-patched fork of `rustls`, renamed via
`package = "rustls"` so it can coexist with the ordinary crates.io `rustls`
dependency; it supplies the REALITY crypto provider and certificate verifier.
It always uses `ring`, independent of leaf's selected backend.

There are no git submodules: `.gitmodules` is empty, even though the workflows
pass `submodules: true` to `actions/checkout` (a no-op). `Cargo.lock` is not
committed (it is git-ignored); git dependencies are pinned by `rev` in
`leaf/Cargo.toml`.

## Regenerating protobuf bindings

The generated bindings are committed. Regenerate them after editing a `.proto`:

```sh
make proto-gen
# or
./scripts/regenerate_proto_files.sh
# which runs:
touch leaf/build.rs && PROTO_GEN=1 cargo build -p leaf
```

`build.rs` regenerates, with a vendored `protoc`:

- `leaf/src/config/internal/config.proto` → `leaf/src/config/internal/config.rs`
- `leaf/src/config/geosite.proto` → `leaf/src/config/geosite.rs`
- `leaf/src/app/outbound/selector_cache.proto` → `leaf/src/app/outbound/selector_cache.rs`

The `touch leaf/build.rs` forces the build script to re-run (the
`rerun-if-changed` lines for the `.proto` files are commented out). The CI
`proto-check` job regenerates them and runs `git diff --exit-code` on
`config.rs` only, failing when the checked-in bindings are stale.

## Mobile bindings and certificates

`build.rs` runs `bindgen` over `src/mobile/wrapper.h` when the target OS is
`ios`, `macos` or `android`, writing `mobile_bindings.rs` into `OUT_DIR` for
`src/mobile/bindings.rs` to include. The iOS `aarch64` path additionally queries
`xcrun --sdk iphoneos --show-sdk-path` for the SDK include path.

`scripts/gen-quic-certs.sh <domain> [out_dir]` generates a CA and a server
certificate chain for QUIC/TLS testing and prints ready-to-paste server and
client config snippets. It is a manual helper and is not invoked by CI; the
QUIC/TLS tests instead synthesise certificates at runtime.
