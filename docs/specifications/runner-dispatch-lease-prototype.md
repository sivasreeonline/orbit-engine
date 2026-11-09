# Runner Dispatch Lease Prototype

- Status: draft implementation; database-only foundation for a future authenticated runner dispatcher.
- Depends on the proposed `runner_dispatch_outbox` migration and transactional handoff repository.

## Implemented behavior

- `claimBatch` claims bounded `PENDING` dispatch intents using PostgreSQL `FOR UPDATE SKIP LOCKED`.
- Claims increment `delivery_attempts`, assign a worker identity, issue a fresh UUID fencing token and set an expiry.
- Expired leases can be reclaimed with a new token.
- `markDelivered` succeeds only for the current worker/token and an unexpired lease. The caller must invoke it only after receiving an authenticated runner receipt.
- `releaseForRetry` releases the current active lease at a caller-selected time; retry timing remains an external policy.
- `markDeadLetter` moves only the current active lease to `DEAD_LETTER`; thresholds and operator replay remain unselected.
- Stale workers cannot acknowledge, retry-release or dead-letter a reclaimed dispatch.

## Safety boundary

- This is a database repository only. It does not select or implement Cloudflare-to-Linux connectivity.
- No queue consumer, runner transport, runner receipt verifier, artifact retrieval or execution endpoint is registered.
- No student source, hidden test data, expected output or credentials are present in dispatch records.
- The repository does not mark a job RUNNING and does not change the execution job state machine.
- `UnconfiguredExecutor` remains fail-closed; gVisor M0 evidence remains outstanding.

## Validation

- Unit tests cover claim SQL, bounded inputs, fencing, retry release, dead-letter and fail-closed configuration.
- PostgreSQL integration test races two dispatchers, waits for lease expiry, reclaims with a new token, rejects stale acknowledgement and accepts the current worker.
- CI applies migration 0004 twice and runs SQL acceptance, handoff concurrency and dispatch lease integration checks against disposable PostgreSQL 17.
- This is correctness evidence for the repository prototype, not production throughput or runner-isolation evidence.
