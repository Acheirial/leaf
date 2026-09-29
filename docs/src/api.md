# API

leaf exposes an administrative **HTTP/JSON** API (built with axum 0.7). It is not
gRPC, and it is **not configured through the config file**.

## Enabling

The API is compiled in by the `api` cargo feature (part of the `default-ring` and
`default-aws-lc` bundles, absent from `default-openssl`) and started only when the
`API_LISTEN` environment variable holds a socket address:

```sh
API_LISTEN=127.0.0.1:8100 ./your_host_binary
```

There is no default port; with `API_LISTEN` empty the API is disabled. Every
config-file spelling of the API is ignored: a top-level `api` key in YAML/JSON is
merely a document marker and is discarded, and the `.conf` options `api-interface`
and `api-port` are parsed but warned about and ignored.

The server has no authentication, TLS or CORS.

## Endpoints

Routes are under `/api/v1`. The `app/outbound/select*` routes are only registered
when the `outbound-select` feature is enabled.

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/runtime/reload` | Re-read the config file and rebuild the router/outbounds. Returns `200` on success, `202` otherwise (e.g. when there is no config file path). |
| POST | `/api/v1/runtime/shutdown` | Stop the runtime. `200` on success, `202` otherwise. |
| GET | `/api/v1/runtime/stat/json` | Active session counters as JSON. |
| GET | `/api/v1/runtime/stat/html` | Active session counters as an HTML table plus totals. |
| GET | `/api/v1/runtime/stat/recent/json` | Recent (completed) session counters as JSON. |
| GET | `/api/v1/runtime/stat/recent/html` | Recent session counters as HTML. |
| GET | `/api/v1/runtime/outbound/{tag}/last_peer_active` | Unix time of the last activity for an outbound tag, or `null`. |
| GET | `/api/v1/runtime/outbound/{tag}/since_last_peer_active` | Seconds since the last activity, or `null`. |
| GET | `/api/v1/runtime/outbound/{tag}/health` | `{"tag":…,"tcp_ms":…,"udp_ms":…}` health probe latencies (`null` on failure). |
| GET | `/api/v1/app/outbound/select?outbound=<tag>` | The currently selected actor of a `select` outbound. |
| GET | `/api/v1/app/outbound/selects?outbound=<tag>` | The selectable actor tags. |
| POST | `/api/v1/app/outbound/select?outbound=<tag>&select=<actor>` | Set the active actor of a `select` outbound. `200` on success, `202` otherwise. |

`reload`, `shutdown` and `select` never return an error status — failures map to
`202 Accepted`.

The `recent` endpoints are empty unless `MAX_RECENT_CONNECTIONS` is set to a
positive value (default `0`). The `health` probe connects to
`healthcheck.leaf:80`, sends `PING` and expects `PONG` over both TCP and UDP, so
it only reports success when something answers that name.

## Example

```yaml
outbounds:
  - tag: direct_out
    protocol: direct
  - tag: proxy_out
    protocol: socks
    settings:
      address: 127.0.0.1
      port: 1087
  - tag: sel_out
    protocol: select
    settings:
      actors: [direct_out, proxy_out]

router:
  rules:
    - target: sel_out
```

```sh
curl -X POST http://127.0.0.1:8100/api/v1/runtime/reload
curl        http://127.0.0.1:8100/api/v1/runtime/stat/json
curl        http://127.0.0.1:8100/api/v1/app/outbound/selects?outbound=sel_out
curl -X POST 'http://127.0.0.1:8100/api/v1/app/outbound/select?outbound=sel_out&select=proxy_out'
```

## What is not available

- No gRPC (Xray's `HandlerService`/`StatsService` are not implemented).
- No per-tag stats query, no stats reset, no online-user listing.
- No runtime add/remove of users, inbounds, outbounds or rules — only a full
  config reload from disk.
- No config get/replace, no authentication.
