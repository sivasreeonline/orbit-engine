# Durable Queue-to-Runner Handoff Design

- Status: non-normative design proposal; no consumer, migration, runner transport or execution path is enabled.
- Scope: define the crash-safe boundary between Cloudflare Queue delivery and a separately operated Linux Go runner.
- Depends on: ADR-0006 (Cloudflare Queues + PostgreSQL transactional outbox), ADR-0009 (Go runner), the proposed execution-intake schema and the current job-claim prototype.

## Problem

The current pipeline publishes a metadata-only `EXECUTION_REQUESTED` message from PostgreSQL to Cloudflare Queues. A PostgreSQL repository can independently claim an execution job and move it from `QUEUED` to `CLAIMED`.

Those two operations are not yet one durable handoff. If a consumer claims a job and acknowledges the queue message before a runner dispatch has been durably recorded, a process crash can leave the job claimed with no recoverable dispatch intent. A duplicate delivery that sees `ALREADY_CLAIMED` cannot prove that the first consumer completed the handoff.

The existing `execution_outbox` is the API-to-Cloudflare publication outbox. It has a unique constraint on `execution_id` and therefore must not be repurposed as a second runner-dispatch outbox.

## Proposed architecture

Use two independently recoverable outbox boundaries:

1. **Intake outbox:** API transaction persists immutable attempt, job and `EXECUTION_REQUESTED` event. The scheduled Worker publishes its metadata-only event to Cloudflare Queues.
2. **Runner-dispatch outbox:** a future Queue consumer validates the envelope and, in one PostgreSQL transaction, verifies the authoritative job/attempt and persists a uniquely keyed runner-dispatch intent. It acknowledges the Cloudflare message only after that transaction commits.
3. **Runner dispatcher:** a separate dispatcher leases pending runner-dispatch intents and sends an authenticated, bounded dispatch request over a separately approved private transport to the Linux Go runner.
4. **Runner deduplication:** the runner treats `executionId` as the idempotency key. Repeated dispatch for the same execution must not start a second logical execution.
5. **Result path:** the runner reports a bounded, authenticated result. Result persistence and state transitions remain gated on approval of the normative result contract and state machine.

The dispatch outbox is a durable handoff record, not evidence that the runner received or started the job.

## Queue consumer transaction

The future consumer should:

1. Parse a small, versioned envelope. Require `executionId`, `attemptId`, `protocolVersion` and correlation metadata where present. Reject unknown versions, malformed identifiers and oversized messages.
2. Treat all message values as untrusted routing hints. Load the job and attempt from PostgreSQL and verify that the execution ID, attempt ID, protocol version and allowed state match authoritative records.
3. Begin a database transaction and lock the execution job row.
4. Insert one runner-dispatch intent keyed by `execution_id` with a unique constraint. Persist only opaque identifiers, correlation metadata, protocol version, timestamps and state; never copy student source, hidden tests, expected output, credentials or database connection data into the queue or dispatch envelope.
5. If the intent already exists, verify that it refers to the same attempt and compatible protocol version. Treat an exact duplicate as already handed off; treat conflicting identity as a quarantined integrity error.
6. Commit the transaction.
7. Only after commit, acknowledge the Cloudflare Queue message.

The job claim and dispatch-intent creation must be atomic if the claim is part of this transaction. The current standalone `PostgresExecutionJobRepository.claim()` call is not sufficient for this consumer because it uses its own connection and commits independently. Refactor or add a transaction-scoped repository operation; do not compose separate repository calls and describe them as atomic.

## Crash and retry behavior

| Failure point | Required recovery |
|---|---|
| Before transaction begins | Do not acknowledge; Cloudflare redelivers |
| During transaction / before commit | Roll back; do not acknowledge |
| Commit succeeds, process crashes before queue ack | Redelivery finds the unique dispatch intent and verifies identity, then acknowledges |
| Queue ack succeeds after commit | Dispatch intent remains pending and independently recoverable |
| Dispatcher crashes before sending | Lease expires; another dispatcher reclaims the intent with a new fencing token |
| Runner accepts dispatch, response is lost | Retry may send a duplicate; runner deduplicates by execution ID and returns the existing logical execution receipt |
| Dispatcher receives receipt but DB acknowledgement fails | Lease expiry/retry; runner deduplication prevents a second logical execution |
| Runner unavailable | Keep durable intent pending with bounded retry policy and observable dead-letter/operator workflow |
| Conflicting attempt ID for same execution ID | Do not acknowledge as success; quarantine and alert without disclosing source or hidden data |

Queue acknowledgement must never be used as a substitute for durable runner acceptance. The durable dispatch intent is the recovery anchor between the two systems.

## Proposed dispatch-intent record

The PR #36 branch now contains a prototype migration for the dedicated `runner_dispatch_outbox` table. The table is still an unmerged proposal and must not be applied to production. Its current fields are:

- `id` UUID primary key.
- `execution_id` UUID unique and FK to `execution_jobs`.
- `attempt_id` UUID FK to `execution_attempts`.
- `protocol_version` and `correlation_id`.
- `delivery_state`: `PENDING`, `DELIVERED`, `DEAD_LETTER`.
- `delivery_attempts`, `available_at`, `created_at`, `delivered_at`.
- `lease_owner`, `lease_token`, `lease_expires_at` with all-or-none lease constraint.
- Optional bounded opaque runner receipt/reference; no source bytes, test data or credentials.

The insert must be idempotent by execution ID. A database trigger or transaction-level validation should ensure the attempt ID matches the job's authoritative attempt ID. State transitions and terminal semantics must be aligned with the approved job state machine before migration.

## Linux runner boundary

Cloudflare Queues is accepted for API-to-consumer dispatch. Cloudflare also documents a native HTTP pull-consumer mode for external infrastructure. An evidence-backed comparison of native Queue pull, authenticated control-plane API pull, and Workers VPC/Tunnel dispatch is in [Runner Transport Evaluation](runner-transport-evaluation.md). The evaluation recommends testing native Queue HTTP pull first, subject to verifying and containing the scope of its required account Queues read/write API token. This is a preferred prototype direction only; no transport is selected or approved for production.

Do not introduce RabbitMQ or a public unauthenticated callback as an implementation shortcut. Whichever transport is eventually selected must define:

- Service identity and mutual authentication / credential rotation.
- Network allow-listing and replay protection.
- Request signing or authenticated transport, timestamp/nonce policy and bounded body size.
- Runner acknowledgement semantics and stable execution-ID deduplication.
- Timeouts, cancellation, backpressure, bounded concurrency and retry ownership.
- How the runner retrieves source artifacts and authorized test bundles without exposing hidden tests to the API/queue/browser.
- How result callbacks are authenticated and fenced against stale attempts.

The runner request must be constructed from trusted database policy and artifact metadata, not from student-controlled queue fields. The queue envelope must not contain source code or hidden test material. The proposed machine-to-machine claim/receipt API, service-identity requirements, dispatch-vs-execution lease separation and receipt-schema gap are documented in [Runner Agent Control API Proposal](../specifications/runner-agent-control-api-proposal.md); that proposal is non-normative and adds no routes.

## Observability and operations

Record structured, non-sensitive events for queue receipt, envelope rejection, handoff transaction commit, duplicate handoff, dispatch lease claim, transport attempt, runner receipt, lease expiry and dead-letter transition. Include execution ID and correlation ID where safe. Never log source code, hidden inputs, expected outputs, tokens, credentials or full queue payloads.

Provide operator-visible counts and oldest-age metrics for pending dispatch intents, expired leases, retries and dead-letter records. Replay must be authorized, audited and idempotent.

## Required tests before enabling a consumer

- Malformed, oversized, unknown-version and unknown-field message rejection.
- Message execution/attempt mismatch rejected against database truth.
- Concurrent duplicate deliveries create exactly one dispatch intent.
- Duplicate delivery after committed handoff is acknowledged without creating another intent.
- Transaction rollback leaves no claim or dispatch intent and the queue message is retried.
- Crash-after-commit-before-ack redelivery recovers through the unique intent.
- Dispatcher competing workers cannot lease the same active intent.
- Expired lease can be reclaimed with a new token; stale worker cannot acknowledge.
- Runner duplicate dispatch returns the same logical receipt and never starts a second execution.
- Transport timeout, runner unavailable, cancellation and dead-letter behavior are tested.
- No source, hidden tests, expected output or credentials appear in queue messages, dispatch metadata or logs.
- End-to-end recovery test demonstrates no job is stranded across every crash boundary.

## Decisions still required

1. Select and threat-model the Cloudflare-to-Linux runner transport and network topology, including late Queue acknowledgements and token-scope verification.
2. Select machine identity and approve the runner claim/receipt API and durable receipt schema.
3. Approve the normative request/result contracts and complete job state machine.
4. Define dispatch lease duration, retry classification, backoff, dead-letter threshold and operator replay policy.
5. Define runner receipt semantics, deduplication retention and crash recovery for a runner that has accepted but not completed an execution.
6. Define artifact retrieval authorization, R2 object lifecycle, encryption, retention and deletion.
7. Approve database roles/grants and migration/rollback strategy for the new dispatch table.
8. Define cancellation and stale `RUNNING` job recovery before enabling execution.

## Explicit non-goals and safety gates

- The PR #36 branch contains a dispatch-intent migration and repository/lease prototypes, but no Cloudflare Queue consumer is registered.
- The dispatch table and code remain unmerged prototypes and are not production schema.
- The transport evaluation is a proposal; no Linux runner transport is selected or deployed.
- It does not enable runner HTTP endpoints, artifact retrieval or student-code execution.
- It does not change `UnconfiguredExecutor`; execution remains fail-closed.
- It does not satisfy the gVisor M0 evidence gate. No sandbox approval or production-readiness claim is made.
