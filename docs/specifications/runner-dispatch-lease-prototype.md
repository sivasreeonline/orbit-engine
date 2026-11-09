# Runner Dispatch Lease Prototype

- Status: draft implementation; database-only foundation for a future authenticated runner dispatcher.
- Depends on the proposed `runner_dispatch_outbox` migration and transactional handoff repository.

## Implemented behavior

- `claimBatch` claims bounded `PENDING` dispatch intents using PostgreSQL `FOR UPDATE SKIP LOCKED`.
- Claims increment `delivery_attempts`, assign a worker identity, issue a fresh UUID fencing token and set an expiry.
- Expired leases can be reclaimed with a new token.
- `recordReceipt` persists an immutable runner acceptance receipt and changes the dispatch to `DELIVERED` in one PostgreSQL transaction, fenced by the current worker/token and unexpired lease.
- Exact receipt replay returns `DUPLICATE`; a conflicting receipt for the same dispatch or reused runner receipt ID is rejected.
- The dispatch row is locked before checking for an existing receipt, so concurrent duplicate receipts serialize and converge to one persisted receipt.
- Receipt insertion is constrained by a database trigger to the active lease owner and immutable against update/delete.
- `releaseForRetry` releases the current active lease at a caller-selected time; retry timing remains an external policy.
- `markDeadLetter` moves only the current active lease to `DEAD_LETTER`; thresholds and operator replay remain unselected.
- Stale workers cannot acknowledge, retry-release or dead-letter a reclaimed dispatch.

## Safety boundary

- Migration 0005 adds an immutable `runner_dispatch_receipts` record with unique dispatch identity, runner/receipt identity and a SHA-256 digest of receipt metadata. The receipt is acceptance evidence only, not an execution result.
- This is a database repository only. It does not select or implement Cloudflare-to-Linux connectivity.
- No queue consumer, runner transport, runner receipt verifier, artifact retrieval or execution endpoint is registered.
- No student source, hidden test data, expected output or credentials are present in dispatch records.
- The repository does not mark a job RUNNING and does not change the execution job state machine.
- `UnconfiguredExecutor` remains fail-closed; gVisor M0 evidence remains outstanding.

## Validation

- Unit tests cover claim SQL, bounded inputs, fencing, retry release, dead-letter, receipt validation, exact replay, conflicts and fail-closed configuration.
- PostgreSQL integration test races two dispatchers, waits for lease expiry, reclaims with a new token, rejects stale receipt, races eight identical receipts and verifies one durable receipt plus seven idempotent replays.
- CI applies migrations 0004 and 0005 twice and runs SQL acceptance, handoff concurrency and dispatch lease/receipt integration checks against disposable PostgreSQL 17.
- This is correctness evidence for the repository prototype, not production throughput or runner-isolation evidence.
