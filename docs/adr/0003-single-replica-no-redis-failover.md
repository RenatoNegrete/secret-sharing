# One app replica and one Redis, with no failover

The service runs as exactly one app process against exactly one Redis with no replica. We accept that either one failing is an outage (and, for Redis, a mass revoke — ADR 0002) because the alternative weakens the one promise the service exists to keep. Redis replication is asynchronous: a replica promoted after a failover can still hold a Secret whose last View was already consumed, or whose fifth Failed Unlock already destroyed it, on the old primary. That Secret would be readable a second time. An outage is recoverable; a second View is not.

## Consequences

- Do not add a Redis replica, Sentinel or Cluster for availability. If that is ever required, View consumption must first be made to survive failover — for example by acknowledging a read only after `WAIT` confirms the replica applied it, and treating a timeout as Gone.
- More app replicas against the one Redis would keep Views exact, since every state change is a single atomic Lua call. Two things would still break: rate limits, unlock limits and byte budgets live in process memory, so each replica would grant its own full allowance; and the Secret Ref HMAC key is random per process, so audit events for one Secret would no longer share a ref across replicas. Both must move to shared state before scaling out.
- Deploys restart the single process: in-flight reads are drained by graceful shutdown, and rate-limit buckets reset.
