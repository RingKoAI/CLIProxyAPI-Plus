# Prometheus and Grafana monitoring

CLIProxyAPI provides an opt-in `/metrics` endpoint on its existing API listener.
It uses HTTP middleware for client traffic and a usage plugin for provider events;
no provider executor changes or management usage-queue polling are required.

## Enable collection

In `config.yaml`:

```yaml
metrics-enabled: true
```

Set `CLIPROXY_METRICS_TOKEN` to a strong, dedicated random token in the process
environment or the project's `.env` file, and restart the server. Do not reuse
an API key or management password. Both the flag and token are startup settings;
hot reload does not change the endpoint or rotate its token.

PowerShell example (replace the placeholder with a securely generated value):

```powershell
$env:CLIPROXY_METRICS_TOKEN = "replace-with-a-long-random-token"
.\cli-proxy-api.exe --config config.yaml
```

From another PowerShell session with the same environment variable:

```powershell
Invoke-WebRequest http://127.0.0.1:8317/metrics -Headers @{
  Authorization = "Bearer $env:CLIPROXY_METRICS_TOKEN"
}
```

- Disabled by default, with no metrics middleware or usage plugin registration.
- If enabled without a non-empty token, a warning is logged and metrics stay disabled.
- Missing or incorrect bearer credentials receive HTTP 401, even from localhost.
- Uses the API listener's TLS configuration. Use TLS or a trusted private network;
  bearer authentication alone does not encrypt traffic.
- Keep this endpoint off the public Internet. Do not log Authorization headers in
  reverse proxies. Built-in request-body/header logging is excluded for this route.
- `usage-statistics-enabled` controls a separate usage consumer. Prometheus does
  not need it enabled and does not consume `/v0/management/usage-queue` records.

## Prometheus

Copy [the sample configuration](../examples/monitoring/prometheus.yml). Create
`cliproxy-metrics-token` in Prometheus's working directory containing only the token,
restrict its filesystem permissions, and do not commit it. Alternatively, set
`credentials_file` to an absolute path or a mounted secret file.

```bash
prometheus --config.file=examples/monitoring/prometheus.yml
```

Check the `cliproxy` target in Prometheus. The query `up{job="cliproxy"}` should be 1.
If Prometheus runs in Docker Desktop while CLIProxyAPI runs on Windows, change the
target to `host.docker.internal:8317`. The API bind address and firewall must allow
that connection. Inside containers, `127.0.0.1` refers to that container, not the host.
For HTTPS listeners, set `scheme: https` and configure the appropriate trusted CA.

## Grafana

1. Add a Prometheus data source, using an address reachable from the Grafana server.
2. Import [grafana-dashboard.json](../examples/monitoring/grafana-dashboard.json).
3. Select the Prometheus data source during import.

The dashboard uses the sample job name `cliproxy`. It includes availability, active
requests, QPS, HTTP error rate, P95 total latency, P95 TTFT, hourly tokens and Go runtime
panels. Dynamic business series appear only after matching traffic is observed.
Dashboard JSON is a starter configuration; adjust instance selection and thresholds
for your deployment.

## Metrics and semantics

| Metric | Labels | Meaning |
| --- | --- | --- |
| `cliproxy_http_requests_total` | method, route, status | Completed HTTP requests, excluding registered `/metrics` scrapes |
| `cliproxy_http_request_duration_seconds` | method, route | Histogram of entire handler duration, including streaming |
| `cliproxy_http_requests_in_flight` | none | Active handlers, including long-lived streams/WebSockets |
| `cliproxy_upstream_requests_total` | provider, model, outcome | Emitted Usage Record events; outcome is success or failure |
| `cliproxy_tokens_total` | provider, model, type | Positive reported input/output token counts |
| `cliproxy_ttft_seconds` | provider, model | Positive reported TTFT for successful streaming usage records |
| `go_*`, `process_*` | collector-specific | Go runtime and platform-supported process metrics |

HTTP routes use Gin templates, with unknown routes grouped as `unmatched`. Unknown
HTTP methods are grouped as `OTHER`. Usage labels retain at most 256 distinct
provider/model pairs per process; additional pairs aggregate into `other/other`.
Provider or model names longer than 128 bytes also aggregate there. Empty labels
become `unknown`. No API keys, account IDs, session IDs, request bodies or error
bodies are exported. Model/provider names themselves remain visible to authorized
scrapers, so avoid embedding secrets in those names.

HTTP counters cover all registered API/management routes, not only inference. Filter
by `route` for inference-only panels. Recovery is inside the metrics middleware,
so recovered 500 responses are counted. No response writer buffering is added.

Usage events are dispatched asynchronously. An event is not necessarily a physical
upstream attempt: retry and emission behavior depend on the existing provider path.
TTFT is recorded on completion, not at the instant the first token arrives. Missing
TTFT is not interpreted as zero. A failure after streaming headers have been written
may still have HTTP status 200; use usage outcomes alongside HTTP error rates.

Counters and the usage consumer are process-wide and initialized once. Recreating
an API server does not duplicate the consumer or reset counters; multiple embedded
servers share the same usage manager and metrics. Restarting the process resets
counters. Use `rate()` and `increase()` across restarts. These metrics are for
observability, not an exact billing ledger. Cache/reasoning breakdowns and quota or
cost estimates are intentionally not included in this first version.

## Validation

```bash
go test ./internal/telemetry ./internal/config ./sdk/cliproxy/usage
go test ./internal/api -run TestMetricsRoute -count=1
go test -race ./internal/telemetry
go build -o test-output ./cmd/server
```

The race detector requires a working CGO/C compiler setup. Prometheus and Grafana
must be running to validate the deployment configuration and imported dashboard.
