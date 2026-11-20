# Design note — One-Time Secret Service

**Choice: server-side encryption, key carried in the link, never stored.** `POST /secrets` draws a 128-bit Lookup ID and a 256-bit Secret Key, encrypts the content with AES-256-GCM (AAD = Lookup ID), stores only ciphertext, and returns `/s/{token}` where `token = base64url(LookupID ‖ SecretKey)`. Client-side crypto was rejected: an API test that posts raw `content` would have its plaintext stored verbatim. A stored per-secret key was rejected: a storage dump would equal plaintext. (ADR 0001)

## Threat model

| Adversary | Has | Outcome |
|---|---|---|
| Storage / backup / `docker exec` reader | Full Redis dump | Ciphertext, salts and hashed key names only — no Secret Key, no passphrase verifier, no usable Deletion Token, no raw Lookup ID. Nothing decryptable. |
| Log or `/metrics` reader | Container logs, metrics | Events keyed by a one-way per-process **Secret Ref**; labels are fixed route templates/status classes. No tokens, IDs, content or passphrases ever reach either. |
| Holder of a leaked link, no passphrase | Share Token | ≤ 5 guesses, then the Secret is destroyed. Worst case is denial of service, never disclosure. Guesses consume no View. |
| Network client with nothing | Port 8080 | 2¹²⁸ ID space; malformed/unknown/expired/consumed/revoked all return one identical `404` with identical work; passphrase paths always run exactly one KDF, so not-found and wrong-passphrase are timing-equal. |
| Abusive client | Many requests | Per-IP token buckets from the TCP peer address (forwarding headers ignored); 64 KB content cap, 7-day TTL cap and Redis `maxmemory` + `noeviction` bound memory — a full store rejects new Secrets (`503`), it never evicts live ones. |
| Racing readers | 50 concurrent GETs | View consumption is one atomic Lua step per key: exactly `max_views` succeed, no global lock. |

**Out of scope / accepted:** compromise of the running process (plaintext and keys exist transiently in memory during a read); TLS (terminated in front of the container); link-preview bots consuming a View — the spec fixes `GET /s/{id}` as the read, so no interstitial is possible; a tampered token on a passphrase Secret counts as a Failed Unlock (requires the 128-bit Lookup ID, which never appears outside the token).

## Where keys live

| Key | Where | Lifetime |
|---|---|---|
| Secret Key (256-bit) | Only in the Share Token | Held by the recipient; in server memory for one request |
| Passphrase | Recipient's head; mixed into KDF (Argon2id, per-secret salt) | Never stored, not even as a hash |
| Encryption key | `HKDF(SecretKey [‖ Argon2id(passphrase)], salt)` | Derived per request, discarded |
| Deletion Token (256-bit, independent) | Creator; Redis holds only `SHA-256(token)` | Until Revoke/expiry |
| Secret Ref HMAC key | Process memory, random at start | Until restart (which also drops every Secret) |

## How deletion actually deletes

Redis runs with RDB and AOF disabled, no volume, read-only filesystem: no Secret is ever written to disk, so there are no backups, snapshots, WAL or soft-deleted rows to recover. A Secret leaves memory by `DEL` when its last View is consumed, on Revoke, or on the 5th Failed Unlock, and by native `PEXPIRE` when its TTL lapses. Even a copy that somehow survived is undecryptable without the Share Token. A restart is a mass revoke — accepted. (ADR 0002)

## Read path

Peek (`HMGET`) → derive key + AES-GCM open in the app → then one atomic Lua call: on success **consume** (decrement View Allowance, `DEL` at zero; content is returned only if granted); on authentication failure **record a Failed Unlock** (`DEL` at 5). Decrypt-before-consume is what lets wrong guesses cost no View while the race stays exact.
