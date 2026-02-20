# Auth Emulator (Rust HTTP)

HTTP service that emulates authentication:
- issues `id_token` (JWT)
- issues `refresh_token`
- refreshes `id_token` using `refresh_token`
- supports configurable token expiration via environment variables

## Run

```bash
cargo run
```

By default, the service listens on `127.0.0.1:8080`.

## Configuration

- `BIND_ADDR` (default: `127.0.0.1:8080`)
- `TOKEN_SIGNING_SECRET` (default: `local-dev-signing-secret-change-me`)
- `TOKEN_ISSUER` (default: `auth-emulator`)
- `TOKEN_AUDIENCE` (default: `sample-client`)
- `ID_TOKEN_TTL_SECONDS` (default: `300`)
- `REFRESH_TOKEN_TTL_SECONDS` (default: `3600`)
- `REFRESH_CLEANUP_INTERVAL_SECONDS` (default: `60`)
- `REFRESH_STORE_MAX_SIZE` (default: `100000`)
- `VM_PUSH_URL` (optional, e.g. `http://localhost:8428/api/v1/import/prometheus`)
- `VM_PUSH_INTERVAL_SECONDS` (default: `15`)

Example:

```bash
set ID_TOKEN_TTL_SECONDS=30
set REFRESH_TOKEN_TTL_SECONDS=600
cargo run
```

## API

### 1) Issue tokens

`POST /auth/token`

```json
{
  "subject": "user-123"
}
```

Response:

```json
{
  "token_type": "Bearer",
  "id_token": "<jwt>",
  "refresh_token": "<token>",
  "expires_in": 300
}
```

### 2) Refresh tokens

`POST /auth/refresh`

```json
{
  "refresh_token": "<token from /auth/token>"
}
```

Response:

```json
{
  "token_type": "Bearer",
  "id_token": "<new jwt>",
  "refresh_token": "<new refresh token>",
  "expires_in": 300
}
```

### 3) Healthcheck

`GET /health`

### 4) Prometheus metrics

`GET /metrics`

Exposed metrics:
- `http_requests_total{method,path,status}`
- `http_request_duration_seconds{method,path,status}`
- `http_requests_in_flight`

### 5) Validate `id_token`

`POST /auth/validate`

```json
{
  "id_token": "<jwt>"
}
```

Successful response:

```json
{
  "valid": true,
  "claims": {
    "iss": "auth-emulator",
    "aud": "sample-client",
    "sub": "user-123",
    "iat": 1710000000,
    "exp": 1710000300,
    "jti": "..."
  }
}
```

## Performance (local, rough)

Measured on a local machine with the service running in `--release` mode.
These numbers are indicative, not a strict SLA.

- `POST /auth/token`: ~`795` RPS (`4000` requests, concurrency `40`)
- `GET /health`: ~`891` RPS (`8000` requests, concurrency `80`)

Notes:
- Results depend on CPU, OS, background load, and test tool.
- PowerShell jobs were used as a quick load generator, so real throughput may be higher with dedicated tools (`k6`, `oha`, `wrk`).

## Performance test

The repository includes an integration performance test: `tests/performance.rs`.

Run:

```bash
cargo test --test performance -- --ignored --nocapture
```

Optional environment variables:
- `PERF_TOTAL_REQUESTS` (default: `1000`)
- `PERF_CONCURRENCY` (default: `20`)
- `PERF_MIN_RPS` (default: `100`)
- `PERF_TOKEN_SIGNING_SECRET` (default: `perf-test-secret`)

## VictoriaMetrics integration

If `VM_PUSH_URL` is set, the service periodically pushes Prometheus-format metrics with HTTP POST.

Example:

```bash
set VM_PUSH_URL=http://localhost:8428/api/v1/import/prometheus
set VM_PUSH_INTERVAL_SECONDS=15
cargo run
```
