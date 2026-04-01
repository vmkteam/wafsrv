# wafsrv

Self-hosted web application firewall. HTTP reverse proxy with built-in WAF, rate limiting, bot protection, and CAPTCHA challenge support.

Designed to run as a Docker sidecar in front of your backend service (behind Nginx/Angie, no SSL termination).

## Features

**Reverse Proxy**
- Round-robin load balancing with per-backend circuit breakers
- Dynamic backend discovery via DNS SRV (Consul, Nomad)
- JSON-RPC 2.0 method extraction (single + batch), deep inspection with schema discovery
- Real IP extraction from X-Real-IP / X-Forwarded-For with trusted proxy support

**WAF & Security**
- [Coraza](https://coraza.io/) WAF engine with OWASP CRS v4 (detection or blocking mode)
- Per-IP rate limiting (token bucket) with per-method rules and composite keys
- IP whitelist/blacklist (static config + runtime API)
- GeoIP country/ASN lookup — block, challenge, or log by country (free [db-ip.com](https://db-ip.com/db/lite.php) databases)
- IP reputation feeds — FireHOL blacklists, Tor exit nodes, datacenter ASN detection, custom feeds
- Search engine bot verification (Google, Bing, Yandex, Apple, DuckDuckGo) via reverse DNS + IP ranges
- Traffic filter rules (User-Agent, IP, country, platform, ASN, RPC method — AND semantics)
- Request signing (HMAC-SHA256) — anti-replay, anti-tampering
- Decision engine: cumulative score -> pass / CAPTCHA (499) / block (403)
- CAPTCHA challenge pages: [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/), [hCaptcha](https://www.hcaptcha.com/), or built-in Proof-of-Work (SHA-256)
- Per-platform CAPTCHA policy with version gating and fallback actions
- Captcha pass cache: HMAC cookie + IP fallback
- Escalation: N failed challenges -> soft block with TTL
- Webhook alerting (Slack, Telegram, etc.)
- Adaptive auto Under Attack Mode (RPS spike, error rate, latency, blocked rate triggers)

**Observability**
- Prometheus metrics (requests, latency, RPC methods, decisions, rate limits, IP blocks)
- Structured JSON access log
- Management dashboard with real-time stats and config builder
- Management API via [zenrpc](https://github.com/vmkteam/zenrpc) (status, block rules, traffic filter, attack mode)

## Architecture

```
Client -> Nginx/Angie -> wafsrv :8080 (data)  -> Backend
                         wafsrv :8081 (mgmt)   -> /health, /metrics, /rpc/, dashboard
```

Two ports:
- **Data port** (`:8080`) — reverse proxy, all traffic flows through the middleware pipeline
- **Management port** (`127.0.0.1:8081`) — health check, Prometheus metrics, zenrpc API, dashboard UI

### Middleware Pipeline

```
request -> recoverer -> initContext -> realIP -> bodyLimit -> staticBypass
        -> rpcParser -> rpcInspect -> ip -> trafficFilter -> sign
        -> limit -> engine -> decide -> observe -> proxy -> backend
```

Each component is enabled/disabled by configuration. With a minimal config, wafsrv acts as a plain reverse proxy.

## Quick Start

```bash
make init         # copy cfg/local.toml.dist -> cfg/local.toml
```

Edit `cfg/local.toml` — set `Targets` and `ServiceName`:

```toml
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "myapp"
```

Or use DNS SRV discovery (Consul/Nomad):

```toml
[Proxy]
ServiceName = "myapp"

[Proxy.TargetDiscovery]
Enabled = true
Hostname = "myapp.service.consul"
DNSServer = "127.0.0.1:8600"
```

Then run:

```bash
make run          # go run with -verbose
```

GeoIP databases are embedded in the binary by default. Before building, download them:

```bash
make geo-download # download free db-ip.com databases for embedding
```

## Configuration

Format: [TOML](https://toml.io/), PascalCase keys. Path: `cfg/local.toml`.

Minimal config requires only `Proxy.ServiceName` and either `Proxy.Targets` or `Proxy.TargetDiscovery`. Everything else has sensible defaults.

Annotated template: [cfg/local.toml.dist](cfg/local.toml.dist)

### Example: API with WAF + Rate Limiting + CAPTCHA

```toml
[Proxy]
Targets = ["http://backend:3000"]
ServiceName = "apisrv"
Platforms = ["web", "ios", "android"]

[Proxy.Static]
Paths = ["/assets/"]
Extensions = [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff2"]

[[JSONRPC.Endpoints]]
Path = "/rpc/"
Name = "main"
SchemaURL = "/rpc/"
MethodWhitelist = true
MaxBatchSize = 20

[WAF]
Enabled = true
Mode = "detection"

[RateLimit]
Enabled = true
PerIP = "100/min"

[[RateLimit.Rules]]
Name = "login"
Endpoint = "main"
Match = ["auth.login", "auth.loginByPhone"]
Limit = "10/min"

# GeoIP databases are embedded in the binary.
# Override with external files:
# [IP]
# GeoDatabase = "/path/to/dbip-country-lite.mmdb"
# ASNDatabase = "/path/to/dbip-asn-lite.mmdb"

[IP.Countries]
Block = ["KP", "IR"]
Captcha = ["CN", "VN"]

[TrafficFilter]
Enabled = true

[[TrafficFilter.Rules]]
Name = "headless-chrome"
Action = "block"
UAPrefix = ["HeadlessChrome"]

[[TrafficFilter.Rules]]
Name = "python-bots"
Action = "captcha"
UAPrefix = ["Python/", "python-requests/"]

[Decision]
CaptchaThreshold = 5
BlockThreshold = 8
CaptchaFallback = "block"

[Captcha]
Provider = "turnstile"
SiteKey = "your-site-key"
SecretKey = "your-secret-key"

[Alerting]
Enabled = true

[[Alerting.Webhooks]]
URL = "https://hooks.slack.com/services/..."
Events = ["hard_block", "under_attack"]
MinInterval = "5m"
```

### Incremental Rollout

wafsrv is designed for gradual adoption. Start with a plain proxy and enable features one at a time:

1. **Proxy only** — monitor traffic via dashboard
2. **WAF detection** — log threats without blocking
3. **Rate limiting** — protect critical endpoints
4. **Traffic filter** — block known bad actors
5. **IP reputation** — FireHOL blacklists, Tor exit nodes, datacenter detection
6. **CAPTCHA + decision engine** — challenge suspicious traffic
7. **Request signing** — anti-replay for mobile/web clients
8. **JSON-RPC deep inspection** — method whitelist, batch limits
9. **Alerting** — Slack/Telegram notifications
10. **Adaptive mode** — auto Under Attack Mode

## Build

```bash
make build        # CGO_ENABLED=0 static binary
make test         # unit tests with coverage
make test-short   # fast tests
make bench        # benchmarks
make lint         # golangci-lint
make e2e          # e2e tests
```

## Docker

```bash
make build
docker build -f deployments/Dockerfile -t wafsrv .
docker run -p 8080:8080 -p 8081:8081 \
  -v ./cfg:/opt/wafsrv/cfg \
  -v ./data:/opt/wafsrv/data \
  wafsrv
```

### Docker Compose

```yaml
services:
  backend:
    image: your-backend:latest

  wafsrv:
    image: wafsrv:latest
    ports:
      - "8080:8080"
      - "127.0.0.1:8081:8081"
    volumes:
      - ./cfg:/opt/wafsrv/cfg
      - ./data:/opt/wafsrv/data
    depends_on:
      - backend
```

### With Consul Service Discovery

```yaml
services:
  consul:
    image: hashicorp/consul:1.19
    ports:
      - "8500:8500"
      - "8600:8600/udp"
    command: agent -dev -client=0.0.0.0

  wafsrv:
    image: wafsrv:latest
    ports:
      - "8080:8080"
      - "127.0.0.1:8081:8081"
    volumes:
      - ./cfg/local.toml:/app/cfg/local.toml:ro

  backend:
    image: myapp:latest
    deploy:
      replicas: 3
```

## Environment Variables

CLI flags are available as environment variables with `WAFSRV_` prefix:

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `WAFSRV_CONFIG` | `-config` | `config.toml` | Path to TOML config file |
| `WAFSRV_VERBOSE` | `-verbose` | `false` | Enable verbose (debug) logging |
| `WAFSRV_JSON` | `-json` | `false` | JSON log format |
| `WAFSRV_DEV` | `-dev` | `false` | Dev mode (colored text logs) |

## Prometheus Metrics

Metrics are available at `:8081/metrics`.

| Metric | Labels | Description |
|--------|--------|-------------|
| `wafsrv_requests_total` | service, method, status, platform, traffic_type | All proxied requests |
| `wafsrv_request_duration_seconds` | service, method | Latency histogram |
| `wafsrv_rpc_requests_total` | service, rpc_method, platform | JSON-RPC method calls |
| `wafsrv_decision_total` | action, platform | Decisions (pass, captcha, block, soft_block) |
| `wafsrv_ip_blocked_total` | reason | IP blocks (blacklist, country, fake_bot, reputation) |
| `wafsrv_ip_whitelisted_total` | | Whitelisted requests |
| `wafsrv_ratelimit_exceeded_total` | rule, action | Rate limit exceeded |

## Management API

zenrpc endpoint at `:8081/rpc/`.

| Namespace | Method | Description |
|-----------|--------|-------------|
| `status` | `get` | Service info, uptime, WAF/ratelimit state, attack mode |
| `block` | `add(type, value, reason)` | Add block rule (type: "ip") |
| `block` | `remove(type, value)` | Remove block rule |
| `block` | `list(type)` | List blocked items |
| `filter` | `add(rule)` | Add dynamic traffic filter rule |
| `filter` | `remove(name)` | Remove dynamic rule |
| `filter` | `list` | List all rules (static + dynamic) |
| `attack` | `enable(duration)` | Enable Under Attack Mode |
| `attack` | `disable` | Disable Under Attack Mode |
| `attack` | `status` | Get attack mode status |

## Shared Storage

By default, all state (rate limit counters, captcha cache, nonce dedup) is stored in-memory. For multi-instance deployments, use Aerospike as a shared backend:

```toml
[Storage]
Backend = "aerospike"

[Storage.Aerospike]
Hosts = ["127.0.0.1:3000"]
Namespace = "wafsrv"
KeyPrefix = "myapp:"
```

## License

Apache-2.0
