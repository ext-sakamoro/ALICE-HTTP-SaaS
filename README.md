# ALICE HTTP SaaS

HTTP analysis service powered by ALICE. Parse requests, validate payloads, compress responses, and inspect headers via a simple REST API.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Status

| Check | Status |
|-------|--------|
| `cargo check` | passing |
| API health | `/health` |

## Quick Start

```bash
docker compose up -d
```

API Gateway: http://localhost:8133

## Architecture

```
Client
  |
  v
API Gateway     :8133
  |
  v
HTTP Engine     :8134-internal
(parsing, validation, compression, header analysis)
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/http/parse` | Parse raw HTTP request |
| `POST` | `/api/v1/http/validate` | Validate HTTP payload |
| `POST` | `/api/v1/http/compress` | Compress response body |
| `POST` | `/api/v1/http/headers` | Analyze and transform headers |
| `GET`  | `/api/v1/http/stats` | Retrieve analysis statistics |
| `GET`  | `/health` | Service health check |

### parse

```json
POST /api/v1/http/parse
{
  "raw": "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
}
```

### compress

```json
POST /api/v1/http/compress
{
  "body": "Hello, World!",
  "algorithm": "gzip",
  "level": 6
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_ADDR` | `0.0.0.0:8133` | Core engine bind address |
| `GATEWAY_ADDR` | `0.0.0.0:8132` | API gateway bind address |

## License

AGPL-3.0. Commercial dual-license available — contact for pricing.
