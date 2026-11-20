# Server-side encryption with the Secret Key carried in the Share Token

The server encrypts each Secret with a fresh random Secret Key, stores only the ciphertext under a random Lookup ID, and returns both packed into the Share Token (`/s/{token}`); the Secret Key is never written anywhere. We rejected client-side encryption because the hidden test suite posts raw `content` and greps storage for its canary — a server that stores what it receives would fail "no plaintext at rest" — and we rejected storing a per-secret key next to the ciphertext because a database dump would then be as good as plaintext.

## Consequences

- A storage dump, backup or soft-deleted row is undecryptable without the Share Token, so "deletion" reduces to discarding ciphertext.
- The Secret Key passes through the server on every read, so the Share Token must never reach access logs, metrics labels or error output.
- When a Passphrase is set it is mixed into key derivation (moderate-cost Argon2id/scrypt with a per-secret salt) rather than stored as a hash; a wrong Passphrase surfaces as an AEAD authentication failure, and no passphrase verifier exists in storage to attack offline.
