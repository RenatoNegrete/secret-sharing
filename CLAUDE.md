# One-Time Secret Service

Build & Break exercise: a "view once" secret-sharing API, shipped as `docker compose up` on port 8080.

Go track: modern

- Glossary: `CONTEXT.md`. Decisions: `docs/adr/`. Design note: `DESIGN.md`.
- Never log, label or echo: content, passphrases, Share Tokens, Lookup IDs, Secret Keys, Deletion Tokens. Wrap them in `internal/sensitive`.
- Client IP is `r.RemoteAddr` only; never trust forwarding headers.
- Redis must stay persistence-free with no volume and no published port (ADR 0002).
