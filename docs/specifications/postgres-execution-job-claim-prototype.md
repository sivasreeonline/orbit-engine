# PostgreSQL Execution Job Claim Prototype

- Status: draft implementation stacked on the Cloudflare publisher, outbox lease and proposed intake schema work.
- Scope: idempotent job claim and fenced transition from CLAIMED to RUNNING.
- No runner dispatch or student-code execution is enabled.

## Implemented behavior

- A queue consumer can request a claim for one execution ID.
- Only a QUEUED job whose available_at has arrived can be claimed.
- A CLAIMED job with an expired lease can be reclaimed with a new lease token.
- A live CLAIMED job returns ALREADY_CLAIMED for duplicate queue deliveries.
- Missing, delayed and terminal/non-claimable jobs return distinct internal outcomes.
- markRunning advances only a CLAIMED job with the current worker, token and unexpired lease.
- State version increments on claim, reclaim and RUNNING transition. The lease remains attached while RUNNING for a future runner adapter to use as a fencing token.

## Safety boundary

- This is an internal repository primitive, not a queue consumer or public API.
- It does not trust execution IDs as authorization; future consumer must validate message shape and load authoritative job/attempt records from PostgreSQL.
- It does not retrieve source snapshots, hidden tests or runtime artifacts.
- It does not invoke a runner or execute student code.
- The state machine remains subject to the normative contract approval gate; no terminal result states are written here.

## Validation

- Unit tests cover successful claim, duplicate delivery, missing/delayed/terminal jobs, fenced RUNNING transition, stale lease rejection and fail-closed configuration.
- PostgreSQL integration test races two consumers for one job, verifies only one wins, waits for expiry, reclaims with a new token, rejects the old worker and accepts the new lease.
- CI asserts final state and state_version in disposable PostgreSQL. This is not a production throughput claim.

## Next integration gate

A queue consumer can now be added as a thin message validator and repository caller, but it must not acknowledge a message until its next durable responsibility is secured. Runner dispatch remains blocked on the M0 sandbox evidence gate and the approved runner request/result contracts.
