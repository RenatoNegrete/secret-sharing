# Redis with persistence disabled as the only store

Secrets live in a single Redis with RDB and AOF turned off, a `maxmemory` cap and the `noeviction` policy. We chose it over Postgres because native key expiry and an atomic Lua view-count fit one dependency, and because with nothing ever written to disk a deleted Secret is simply gone rather than lingering in dead tuples or WAL. A restart losing every live Secret is accepted: for a one-time secret service it is equivalent to a mass revoke.

## Consequences

- Do not enable persistence or mount a data volume for Redis; that would reintroduce on-disk copies.
- `noeviction` means a full Redis rejects new Secrets (503) instead of silently evicting live ones.
- Memory is bounded only by the content-size cap, the maximum TTL and `maxmemory` together.
- Rate limiting deliberately does **not** use Redis: per-IP token buckets live in process (`golang.org/x/time/rate`), which saves a Redis write per request and keeps limits working when Redis is full. This assumes a single replica; scaling out would need the buckets moved to a shared store.
