# Cloudflare execution queue consumer

**Status:** Proposed implementation slice  
**Queue:** `sky-high-execution-requests`  
**Dead-letter queue:** `sky-high-execution-requests-dlq`

## Delivery contract

The API's intake outbox publisher sends a metadata-only envelope containing exactly:
- `executionId`
- `attemptId`
- `protocolVersion` (`v1`)

The consumer validates the exact shape and identifiers. It never accepts source code, source bytes, hidden tests, expected outputs, credentials or arbitrary routing fields from the queue message.

## Durable acknowledgement

For each message, the consumer calls `PostgresRunnerDispatchHandoffRepository.record`.

- A newly recorded durable runner-dispatch intent is acknowledged.
- An exact duplicate is acknowledged because the same durable intent already exists.
- Invalid envelopes and database/handoff failures are retried.
- The consumer does not claim a runner-dispatch lease, retrieve source or test artifacts, call a runner, execute code or persist an execution result.
- Per-message failures do not prevent unrelated messages in the same batch from being handled.

The handoff repository resolves only after its PostgreSQL transaction commits. This is the acknowledgement boundary.

## Bounded delivery settings

The Wrangler consumer configuration uses a maximum batch size of 10, a 5-second batch timeout, up to 5 retries, then the configured dead-letter queue. These are initial conservative configuration values, not measured throughput or latency guarantees.

Before any deployment, the primary queue and dead-letter queue must be created in the target Cloudflare account. This change does not create queues or provision Cloudflare resources.

## Failure and recovery

- If Hyperdrive/database configuration is unavailable, every message is retried.
- If the database transaction fails, the message is retried and no acknowledgement is issued.
- If the process crashes after commit but before queue acknowledgement, the message may be redelivered; the handoff repository's unique execution identity and duplicate check make that safe.
- Poison messages are retried until the configured queue policy routes them to the dead-letter queue. Operator inspection/replay tooling remains a separate milestone.

## Not proven by this slice

This consumer only records the durable handoff. It does not claim dispatch work, authenticate a runner machine, retrieve private R2 artifacts, execute Java/Python, or provide 500-online capacity. A separately authenticated runner dispatcher and isolated execution runtime are still required.
