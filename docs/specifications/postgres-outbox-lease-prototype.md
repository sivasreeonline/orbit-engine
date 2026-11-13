# PostgreSQL Outbox Lease Prototype

- Status: draft implementation stacked on the transactional intake prototype and proposed PR #28 schema.
- Scope: database claim, lease fencing, publication acknowledgement and retry release primitives.
- Includes a transport-neutral publisher orchestration function, but no Cloudflare Queue binding or production worker is configured.

## Implemented behavior

- claimBatch atomically selects eligible PENDING rows in deterministic order using FOR UPDATE SKIP LOCKED.
- Each claimed row receives a new random lease token, worker identity and expiry; delivery-attempt count increments in the same statement.
- Expired leases are eligible for reclaim. A reclaimed row receives a new token.
- markPublished transitions only a pending row whose worker, token and unexpired lease all match. It records published_at and clears lease fields.
- publishOutboxBatch sends the metadata payload first, then acknowledges; a lost acknowledgement is reported explicitly because queue delivery may already have happened.
- releaseForRetry clears a matching active lease and sets a caller-supplied available_at. It does not choose a retry delay.
- Stale workers cannot acknowledge or release a lease after expiry or after another worker has reclaimed it.

## Explicitly not decided or implemented

- Cloudflare Queues is already the accepted transport in ADR-0006. The binding/provisioning, publisher runtime and exact queue message schema remain to be implemented.
- Retry/backoff schedule, maximum delivery attempts, dead-letter threshold and operator replay.
- Lease duration and batch size as deployment policy. The repository accepts caller-supplied values and enforces only defensive bounds.
- Queue binding, scheduled invocation, metrics, tracing and operational alerting.
- The publisher orchestration accepts an injected queue and retry-time function; it is not yet wired to Cloudflare Queues or a Worker lifecycle.
- No source code, hidden tests, expected outputs or credentials are read or placed in queue payloads by these primitives.
- No HTTP route, queue consumer or runner integration is enabled.

## Validation

- Unit tests cover SQL locking/fencing shape, acknowledgement, stale-token rejection, retry release, input validation and publisher send/ack/failure behavior.
- PostgreSQL integration test uses competing publishers to prove they do not claim the same row, then waits for a lease to expire, reclaims it with a new token, rejects the stale acknowledgement and accepts the current lease acknowledgement.
- These tests validate the proposed schema in disposable CI PostgreSQL. They do not prove production throughput or exactly-once queue delivery.

## Next integration gate

Before adding a real publisher, configure/provision the already-selected Cloudflare Queues binding and settle retry/dead-letter policy, lease duration, message schema and operational ownership. Queue delivery must remain at-least-once and consumers must be idempotent.
