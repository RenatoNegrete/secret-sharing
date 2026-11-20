# One-Time Secret Service

```sh
docker compose up -d --build        # API on http://localhost:8080
```

| Endpoint | |
|---|---|
| `POST /secrets` | `{content, ttl_seconds?, max_views?, passphrase?}` → `201 {id, share_url, url, deletion_token, expires_at}` |
| `GET /s/{token}` | `200 {content}` · `401` passphrase missing/wrong (`X-Passphrase` header; JSON body and `?passphrase=` also accepted) · `404` Gone |
| `DELETE /s/{token}` | `Authorization: Bearer <deletion_token>` → `204` · `404` wrong token or Gone |
| `GET /healthz`, `GET /metrics` | liveness, Prometheus |

Read first: `DESIGN.md` (threat model, keys, deletion), `CONTEXT.md` (glossary), `docs/adr/`.

## Tuning at the event (no rebuild)

`RATE_CREATE_PER_SEC` (10) · `RATE_CREATE_BURST` (20) · `RATE_READ_PER_SEC` (100) · `RATE_READ_BURST` (100) · `KDF_ARGON_TIME` (2) · `KDF_ARGON_MEMORY_KIB` (19456) · `PUBLIC_BASE_URL`

```sh
RATE_CREATE_PER_SEC=50 docker compose up -d app
```

## Verify

```sh
go test -race ./...                                      # unit, incl. 50-way race on a fake store
go test -tags integration -count=1 -v ./test/integration # live stack: correctness, race x20, timing, headers, 429 + XFF
./scripts/canary.sh                                      # no canary/passphrase/token in Redis, RDB, app fs, logs, metrics
k6 run loadtest/k6.js                                    # 200 rps x 60 s (raise rate limits to measure raw latency)
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```
