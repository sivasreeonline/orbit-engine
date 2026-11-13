# Append-Only Execution Evidence — Draft Implementation

- Status: draft implementation stacked on the proposed execution-intake and fenced-job-claim work.
- Migration: `apps/api/migrations/0004_append_only_execution_results.sql`
- Repository: `apps/api/src/db/execution-evidence-repository.ts`
- Scope: immutable runner lifecycle events, immutable terminal result records, lease-fenced completion and student-owned attempt history queries.
- No cloud service, AWS account, runner host or student identity provider is provisioned by this work.

## What is persisted

The proposed 0003 intake migration already creates the immutable source snapshot, Run/Submit attempt, execution job, scoped idempotency record and metadata-only outbox entry in one transaction.

This 0004 extension adds:

- `execution_evidence_events`: append-only, ordered lifecycle events with stable event IDs, event type, trusted actor kind, phase status, bounded duration and optional safe machine code.
- `execution_result_records`: one immutable terminal result per execution, including infrastructure status, compilation status, deterministic verdict, cleanup status, test aggregates, elapsed time, peak memory, runner version, optional runtime image digest and the result-envelope SHA-256.

Event and result identity is checked against the authoritative execution job and attempt. Tenant and actor scope are copied from the attempt row by SQL; they are not accepted as caller-supplied ownership values for writes.

## Completion and retry rules

A result write first checks whether a result already exists for the execution:

- The same attempt and result digest is an idempotent replay and returns the original outcome.
- A different attempt or result digest is a conflict and cannot replace the original evidence.
- A first-time terminal result requires the current worker ID, lease token, a RUNNING job and an unexpired lease.
- The job's terminal state, immutable result record and final evidence event are committed in one PostgreSQL transaction.
- The job lease is cleared only as part of that successful terminal transaction.

An expired or superseded worker cannot finalize a result. Infrastructure failure is recorded separately from student verdicts; an infrastructure failure must use `NOT_EVALUATED` rather than converting an infrastructure incident into Wrong Answer.

Event writes accept a caller-generated stable event UUID. Repeating the same UUID with the same event identity and payload returns the original sequence. Reusing it for a different execution or different payload is rejected.

## History read boundary

The history query is scoped by both authenticated tenant ID and authenticated actor ID and then filtered by problem slug. It returns source hash and byte length, attempt/action/language/runtime, job state, result dimensions and metrics. It never returns source bytes, hidden test inputs, hidden expected outputs, credentials or raw runner diagnostics.

The event query uses the same tenant/actor scope. These repository methods are intended to back the student History view and a per-execution timeline endpoint; the HTTP route and frontend connection are a subsequent integration slice.

## What is deliberately not included yet

- Raw compiler output, stdout/stderr and per-test details are not placed into event JSON or this result row. A separate bounded, sanitized and access-controlled artifact path is required before exposing those outputs.
- The repository does not dispatch jobs, start the runner, compile code or execute a sandbox.
- The optional runtime image digest supports synthetic/local contract tests. Production execution must require a reviewed immutable runtime image digest before the runner is admitted.
- This migration remains part of the draft PR stack. It must not be applied to a production database until the API contract, roles/grants, retention policy and migration approvals are complete.

## Verification

CI applies this migration twice to a disposable PostgreSQL service and runs the integration tests. The tests cover:

- appending an event and replaying the same event ID;
- lease-fenced result completion and idempotent lost-ack replay;
- rejection of conflicting terminal results;
- stale lease rejection without terminal evidence;
- student/tenant-scoped history reads; and
- database rejection of UPDATE against immutable event and result evidence.

These checks establish PostgreSQL behaviour in CI only. They do not prove production database authorization, live runner authenticity, sandbox isolation or external custody qualification.
