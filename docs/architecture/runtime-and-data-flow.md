# Runtime and Data Flow

## Run
1. Authenticate and authorize the student.
2. Validate problem version, language, source size and Run policy.
3. Persist immutable attempt and source snapshot metadata.
4. Create an execution job and outbox event in the same database transaction.
5. Publish the outbox event to Cloudflare Queues.
6. Runner claims the execution idempotently, fetches only the required public test bundle and executes in an ephemeral sandbox.
7. Runner posts bounded structured results.
8. Assessment engine stores test results and final verdict.
9. Client polls or subscribes for status; API returns sanitized output.

## Submit
Same lifecycle as Run, but the server selects the full versioned test suite including hidden tests. Client receives aggregate hidden-test outcomes only, never inputs or expected outputs.

## Job states
CREATED -> QUEUED -> CLAIMED -> RUNNING -> EVALUATING -> COMPLETED.
Terminal alternatives: FAILED_INFRASTRUCTURE, CANCELLED, EXPIRED.
A student verdict (Accepted/Wrong Answer/etc.) is distinct from infrastructure status.

## Reliability
- Queue delivery is at-least-once.
- Outbox rows are published until acknowledged.
- Runner uses execution ID as idempotency key.
- Result writes are upserts guarded by job state/version.
- Retries are bounded and classified; student-code failures are not infrastructure retries.
- Dead-letter items are observable and replayable by authorized operators.

## Artifacts
Store metadata, hashes, status and small data in PostgreSQL. Store large source/log artifacts in private R2 objects only when needed. Do not expose hidden test bundles through presigned URLs.
