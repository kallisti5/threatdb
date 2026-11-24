# traefik-threatdb

A [Traefik](https://traefik.io) middleware plugin that periodically downloads
public "bad IP" lists and blocks requests from addresses that appear on them.
Blocked clients get a friendly explanation instead of a bare 403.

- Downloads lists **at startup and on a schedule**, never on the request path.
- Matches IPv4 and IPv6 addresses, single IPs and CIDR ranges.
- Keeps the last good copy when a provider is down, with retry/backoff.
- Sends conditional requests (`If-None-Match` / `If-Modified-Since`) when the
  provider supports them, and skips re-parsing when a 200 response has the same
  body digest.
- Zero third-party dependencies, so it runs cleanly under Yaegi.
- Parses each list once and shares it across middleware instances with the same
  provider settings.
- Optional status endpoint with JSON details and Prometheus metrics.

> The lists are third-party data. Shared addresses (CGNAT, VPNs, cloud egress,
> mobile carriers) occasionally appear on them, so keep an `allowList` ready and
> do not treat this middleware as your only security control.

## How it works

1. On construction, every configured provider is fetched and parsed in
   parallel. Traefik starts serving only after these attempts finish (bounded by
   `requestTimeout`).
2. Each list is kept in memory as a hash set of addresses plus CIDR networks
   bucketed by prefix length.
3. A background goroutine refreshes each list on its own interval, with a small
   random spread so providers do not all rebuild their lists at once. Failed
   refreshes are retried with exponential backoff (10s up to 5m), while the last
   good copy keeps being used.
4. On every request the client address is checked against the cached sets. Only
   hash lookups are involved (benchmarked in the tens of nanoseconds), and the
   upstream provider is never contacted.
5. A match returns the configured status (default 403) with a message naming the
   list, e.g.:

   ```http
   HTTP/1.1 403 Forbidden
   Content-Type: text/plain; charset=utf-8
   Cache-Control: no-store
   X-Threat-List: Threat.Live

   Your IP is present on the Threat.Live threat list. Please try again later
   ```

## Installation

### From the plugin catalog

Declare the plugin in Traefik's static configuration:

```yaml
# traefik.yml
experimental:
  plugins:
    threatdb:
      moduleName: github.com/kallisti5/threatdb
      version: v0.1.2
```

Then use it from the dynamic configuration:

```yaml
# dynamic.yml
http:
  routers:
    app:
      rule: Host(`example.com`)
      entryPoints:
        - websecure
      middlewares:
        - threatdb
      service: app

  middlewares:
    threatdb:
      plugin:
        threatdb:
          providers:
            threatlive:
              name: Threat.Live
              url: https://list.threat.live
          # Optional: expose status at /_threatdb/status on this router.
          statusPath: /_threatdb/status

  services:
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
```

### Local plugin mode

For development, mount the repository as a local plugin:

```yaml
# traefik.yml
experimental:
  localPlugins:
    threatdb:
      moduleName: github.com/kallisti5/threatdb
```

The source must live in `./plugins-local/src/github.com/kallisti5/threatdb`.
See [`dev/`](dev/) for a ready-to-run Docker Compose setup.

## Configuration

### Core options

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `providers` | map | *(required)* | Threat lists to download. See below. |
| `refreshInterval` | duration | `15m` | How often each list is refreshed. |
| `requestTimeout` | duration | `15s` | Timeout for one list download. Also bounds startup delay per provider. |
| `maxListBytes` | int | `16777216` | Reject responses larger than this (16 MiB). |
| `maxStale` | duration | `24h` | Age after which the status endpoint reports a list as stale. `0` disables the report. Stale lists are still enforced. |
| `statusCode` | int | `403` | Status returned to blocked clients (200–599). |
| `message` | string | see below | Block response body. Supports `{provider}` and `{ip}`. |
| `unavailableMessage` | string | see below | Body used when `failClosed` is on and a list has not loaded. |
| `contentType` | string | `text/plain; charset=utf-8` | `Content-Type` of block responses. |
| `allowList` | list | `[]` | IPs or CIDRs that are never blocked (e.g. `203.0.113.4`, `2001:db8::/32`). |
| `excludePrivateIPs` | bool | `false` | Let loopback, private, link-local, multicast and CGNAT addresses bypass the lists. |
| `trustedProxyDepth` | int | `0` | Trust the last N hops of the forwarded header. `0` uses the TCP peer address. |
| `forwardedForHeader` | string | `X-Forwarded-For` | Header used when `trustedProxyDepth > 0`. |
| `failClosed` | bool | `false` | Return 503 while a list has never loaded instead of failing open. |
| `statusPath` | string | *(disabled)* | Exact path that serves a JSON status document or Prometheus metrics, bypassing blocking. |
| `logBlockedRequests` | bool | `false` | Log each blocked request (can be noisy under attack). |
| `userAgent` | string | `traefik-threatdb/<version>` | User-Agent sent to providers. |

Default messages:

```text
Your IP is present on the {provider} threat list. Please try again later
The {provider} threat list is temporarily unavailable. Please try again later
```

`{provider}` is replaced with the display name(s) of the matching list, joined
with `, ` if several match. `{ip}` is the client address.

### Provider options

The key of each provider entry is a stable identifier used in logs. Provider
entries are processed in sorted key order, which keeps messages deterministic.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | string | *(required)* | Absolute `http` or `https` URL of the list. |
| `name` | string | provider key | Display name used in messages and `X-Threat-List`. |
| `refreshInterval` | duration | global value | Per-provider override. `0` fetches once at startup and never refreshes. |
| `headers` | map | `{}` | Extra request headers, e.g. an API token. Headers are dropped if the provider redirects to a different scheme, host or port. |
| `minEntries` | int | `0` | Reject a download with fewer parsed entries, protecting against truncation or error pages. |
| `maxListBytes` | int | global value | Per-provider size limit. |

### Multiple providers

```yaml
http:
  middlewares:
    threatdb:
      plugin:
        threatdb:
          providers:
            threatlive:
              name: Threat.Live
              url: https://list.threat.live
              refreshInterval: 15m

            spamhaus-drop:
              name: Spamhaus DROP
              url: https://www.spamhaus.org/drop/drop.txt
              refreshInterval: 1h
              minEntries: 100

            firehol1:
              name: FireHOL level 1
              url: https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
              refreshInterval: 1h
              minEntries: 100
```

## Supported list formats

Any text response containing addresses is accepted:

- One entry per line, or several per line separated by spaces, tabs, commas or
  pipes.
- Plain addresses (`203.0.113.5`, `2001:db8::1`), `host:port` pairs, and CIDR
  networks (`198.51.100.0/24`, `2001:db8::/32`).
- Comments after `#` or `;`.
- UTF-8 BOM and CRLF line endings.
- IPv4-mapped IPv6 entries are normalised to IPv4.

An empty result, an HTML error page, an oversized body, or a list smaller than
`minEntries` is rejected and the previous copy is kept.

## Client IP handling

By default the plugin matches the TCP peer address (`RemoteAddr`). This is the
safe choice for a Traefik instance on the public edge.

When Traefik runs behind another proxy or CDN, set `trustedProxyDepth` to the
number of proxies you control in front of it, **including the direct peer**:

```yaml
trustedProxyDepth: 2
forwardedForHeader: X-Forwarded-For
```

With a header of `client, proxy1`, depth `2` selects `client`; depth `1` selects
`proxy1`. If the header has fewer hops than requested, or contains something
that is not an IP, the plugin falls back to the TCP peer address.

Traefik v3 **strips incoming `X-Forwarded-*` headers from untrusted peers**
before middleware runs, so the plugin will see an empty header unless the
entrypoint trusts the peer. Configure the entrypoint as well:

```yaml
# static configuration
entryPoints:
  websecure:
    address: ":443"
    forwardedHeaders:
      trustedIPs:
        - 10.0.0.0/8      # your load balancer / proxy network
        - 192.0.2.10/32   # or individual proxy addresses
```

`forwardedHeaders.insecure: true` also works but trusts every peer, so it is
only appropriate for local experiments (the bundled dev setup uses it to make
simulating client addresses easy).

> **Security warning:** forwarded headers are trivially spoofed by clients.
> Only enable `trustedProxyDepth` when every path to Traefik goes through
> proxies that overwrite or append the header, and make sure Traefik itself is
> not directly reachable. Misconfiguring this lets attackers choose an address
> that is not on the lists.

For Cloudflare, `CF-Connecting-IP` is usually the simplest header:

```yaml
trustedProxyDepth: 1
forwardedForHeader: CF-Connecting-IP
```

Traefik does not strip that header, but you must still make sure your origin
only accepts traffic from Cloudflare.

## Availability behaviour

- If a provider is down at startup, Traefik still starts and the plugin is
  active. With the default `failClosed: false` requests are allowed until a list
  loads; with `failClosed: true` they receive a 503 and
  `unavailableMessage` until every list has been loaded at least once.
- Once a list has loaded it is never discarded on a failed refresh. It keeps
  blocking with the last known data, and the status endpoint reports the error.
- Refreshes are retried with exponential backoff: 10s, 20s, 40s, ... capped at
  5 minutes (or the provider's interval if that is shorter).
- `maxStale` only affects reporting. It does not stop enforcement and does not
  trigger `failClosed`, because stale data still contains real threat entries.

## Status endpoint

Set `statusPath` to a path that your application does not use. A `GET` returns
a JSON snapshot by default:

```json
{
  "middleware": "threatdb@file",
  "version": "0.1.0",
  "failClosed": false,
  "blockStatusCode": 403,
  "maxStaleSeconds": 86400,
  "stats": {
    "requests": 184233,
    "allowed": 184220,
    "rejectedMatches": 13,
    "rejectedUnavailable": 0,
    "noClientIP": 0
  },
  "providers": [
    {
      "key": "threatlive",
      "name": "Threat.Live",
      "url": "https://list.threat.live",
      "entries": 47365,
      "loaded": true,
      "stale": false,
      "fetching": false,
      "matches": 13,
      "refreshSuccesses": 96,
      "refreshFailures": 0,
      "lastRefreshSeconds": 0.21,
      "lastAttempt": "2026-11-23T16:20:03Z",
      "lastSuccess": "2026-11-23T16:20:03Z",
      "ageSeconds": 42,
      "lastError": ""
    }
  ]
}
```

`stats.requests` counts requests evaluated by the middleware; the status path
itself is not included. `rejectedMatches` is the total rejected because the
client appeared on at least one list, and `rejectedUnavailable` counts
`failClosed` rejections. Per-provider `matches` counts requests that matched
that specific list, so one request can increment several providers. Match
counters are per middleware instance; refresh counters and list state describe
the shared provider cache.

The endpoint bypasses the block logic so it can be checked from anywhere the
router is reachable. Restrict it with a dedicated router, a Traefik IP allowlist,
or by not exposing it publicly.

### Prometheus metrics

The same endpoint serves the Prometheus text exposition format when the client
asks for it. Prometheus sends a suitable `Accept` header automatically, so just
point a scrape job at `statusPath`:

```yaml
scrape_configs:
  - job_name: threatdb
    metrics_path: /_threatdb/status
    static_configs:
      - targets: ["traefik.example.com:8080"]
```

Requests with an `Accept: text/plain` or `Accept: application/openmetrics-text`
header, or the explicit `?format=prometheus` query parameter, receive metrics.
Everything else, including browsers and plain `curl`, keeps receiving JSON. If
something in front of Traefik rewrites the `Accept` header, set
`params: {format: [prometheus]}` in the scrape job instead.

To inspect the metrics from a shell:

```bash
curl -s -H 'Accept: text/plain' http://localhost:8000/_threatdb/status
# or
curl -s 'http://localhost:8000/_threatdb/status?format=prometheus'
```

Exported metrics:

| Metric | Type | Description |
| --- | --- | --- |
| `threatdb_requests_total` | counter | Requests evaluated by the middleware. |
| `threatdb_allowed_total` | counter | Requests forwarded to the next handler. |
| `threatdb_rejected_total{reason}` | counter | Rejected requests, `reason="match"` or `"unavailable"`. |
| `threatdb_no_client_ip_total` | counter | Requests forwarded because no client IP could be determined. |
| `threatdb_info{middleware,version}` | gauge | Always `1`; identifies the middleware instance. |
| `threatdb_provider_loaded{provider}` | gauge | `1` when a list has been loaded at least once. |
| `threatdb_provider_stale{provider}` | gauge | `1` when the list is older than `maxStale`. |
| `threatdb_provider_fetching{provider}` | gauge | `1` while a refresh is in progress. |
| `threatdb_provider_entries{provider}` | gauge | Addresses and networks currently loaded. |
| `threatdb_provider_matches_total{provider}` | counter | Requests rejected because they matched this provider. |
| `threatdb_provider_refresh_total{provider,result}` | counter | Refresh attempts, `result="success"` or `"failure"`. |
| `threatdb_provider_last_success_timestamp_seconds{provider}` | gauge | Unix time of the last successful refresh. |
| `threatdb_provider_last_attempt_timestamp_seconds{provider}` | gauge | Unix time of the last refresh attempt. |
| `threatdb_provider_last_refresh_duration_seconds{provider}` | gauge | Duration of the most recent refresh attempt. |

`provider` labels are the configuration keys, not display names, so dashboards
keep working if you rename a list. Timestamps are `0` until the first attempt or
success. Useful alerts are `threatdb_provider_loaded == 0` (with
`failClosed: true`) and `threatdb_provider_stale == 1`.

## Local development

```bash
docker compose -f dev/docker-compose.yml up
```

Then, in another terminal:

```bash
# Allowed request (plain 200 from whoami)
curl -s http://localhost:8000/

# Simulate a listed client (the dev config trusts X-Forwarded-For)
curl -si http://localhost:8000/ -H 'X-Forwarded-For: 45.79.181.251'

# Inspect the loaded lists and request counters
curl -s http://localhost:8000/_threatdb/status | jq .

# Inspect the Prometheus metrics
curl -s -H 'Accept: text/plain' http://localhost:8000/_threatdb/status
```

The Traefik dashboard is available at <http://localhost:8080>.

`dev/dynamic.yml` uses `trustedProxyDepth: 1` on purpose so arbitrary client
addresses can be simulated locally, and `dev/docker-compose.yml` enables
`forwardedHeaders.insecure` so Traefik passes the header through. Do not copy
either setting to production.

## Testing

```bash
make test          # go test ./...
make race          # go test -race ./...
make yaegi-test    # run the tests under Yaegi, Traefik's interpreter
make bench         # set lookup benchmark
```

The test suite covers list parsing, IPv4/IPv6/CIDR matching, client IP
extraction, scheduling and refresh, conditional requests, stale-data retention,
configuration validation, shared provider caches, the status endpoint, and
concurrent traffic during refreshes.

## Publishing to the Traefik plugin catalog

1. Publish this repository at the module path in [`go.mod`](go.mod). If your
   repository lives elsewhere, update `module` in `go.mod`, `import` in
   [`.traefik.yml`](.traefik.yml), and the paths in this README.
2. Add the `traefik-plugin` topic to the GitHub repository.
3. Tag a release, e.g. `git tag v0.1.2 && git push origin main v0.1.2`.
4. The catalog service polls GitHub **once a day**, so a new plugin or version
   can take up to 24 hours to become downloadable. There are no dependencies to
   vendor.

Until the catalog has indexed the version, Traefik returns:

```text
unable to download plugin github.com/kallisti5/threatdb:
error: 404: {"error":"Unknown plugin: github.com/kallisti5/threatdb@v0.1.2"}
```

Check whether a version is available yet (HTTP 200 means yes, 404 means the
catalog has not indexed it):

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://plugins.traefik.io/public/download/github.com/kallisti5/threatdb/v0.1.2
```

Use [local plugin mode](#local-plugin-mode) to run the plugin without waiting
for the catalog. If the catalog rejects a plugin during validation it opens an
issue in the repository; check the Issues tab if the version is still unknown
after a couple of days.

## Operational notes

- **Shared lists:** Traefik constructs a middleware instance for every router
  that references the plugin, but instances with identical provider settings
  share one parsed copy and one refresh loop. Ten routers using the same
  middleware definition download once per interval and store the list once. The
  shared copy is kept for a short grace period after a dynamic-configuration
  reload so the replacement instances attach without re-downloading. Different
  `url`, `headers`, `refreshInterval`, `requestTimeout`, `minEntries`,
  `maxListBytes` or `userAgent` values produce separate caches. Sharing happens
  within one plugin definition (one Yaegi interpreter in the Traefik process),
  which covers the usual setup where every router references the same
  `threatdb` plugin.
- **Memory:** one parsed copy per distinct provider configuration, plus the
  response body during parsing (bounded by `maxListBytes`). Exact IPv4 entries
  are stored in numeric maps; 800k exact addresses retained roughly 9 MiB in
  testing. During a refresh the old and new copies briefly coexist.
- **Use HTTPS for providers:** `http://` URLs are accepted for local or
  private lists, but a cleartext response can be modified in transit and
  inject or remove addresses.
- **Status endpoint is unauthenticated:** anyone who can reach the router can
  read provider names, URLs and entry counts. Restrict it at the router level
  or leave `statusPath` empty.
- **Fail-open by default:** if a list has never loaded, requests are allowed
  unless `failClosed` is set. Watch the status endpoint or the plugin's error
  logs if an outage must not silently disable filtering.
- **Startup:** the first load is synchronous. With an unreachable provider,
  Traefik can be delayed by up to `requestTimeout` per plugin instance; lower
  it if you need faster starts.
- **False positives:** use `allowList` for your own egress, health checkers and
  known shared infrastructure. Consider logging blocked requests temporarily
  while tuning.
- **Provider etiquette:** respect each list's terms of service and rate limits.
  The default 15 minute interval is intentionally conservative; many lists only
  change hourly. Use per-provider intervals and conditional requests where
  supported.
- **Not a WAF:** this only checks source addresses against public lists. It does
  not inspect payloads, and it cannot stop a compromised host on a clean address.

## License

Apache-2.0. See [LICENSE](LICENSE).
