# E2E Tests

End-to-end tests for wafsrv. Starts wafsrv + mock backend in-process, tests all scenarios.

## Running

```bash
# all e2e tests with race detector
make e2e

# with Aerospike storage backend
make e2e-aerospike

# manually
go test -v -count=1 -timeout 60s -race ./e2e/
```

## Test Files

| File | Groups | What it covers |
|------|--------|----------------|
| e2e_test.go | — | Suite setup/teardown, helpers |
| proxy_test.go | 01, 11, 13, 17 | Proxy, static bypass, circuit breaker status, DNS SRV discovery |
| security_test.go | 02, 06, 15 | WAF (SQLi/XSS/LFI/RCE), decision engine, request signing |
| blocking_test.go | 03, 04, 09, 10 | Rate limiting, IP blocking, traffic filter, concurrent safety |
| management_test.go | 05, 08, 12, 14, 16 | Management API, attack mode, metrics, tops, config API |

## How It Works

- `SetupSuite`: starts mock backend (:19990) + wafsrv (:18080 data, :18081 mgmt) in-process
- Each test makes HTTP requests to the data port or management API
- `TearDownSuite`: graceful shutdown
- `-race` flag enables Go race detector
- Config: `e2e/cfg/e2e.toml` (WAF blocking, rate limit, traffic filter rules)
- Discovery tests create isolated proxy instances with mock resolvers
