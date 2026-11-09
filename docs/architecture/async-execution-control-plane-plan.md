# Asynchronous Execution Control Plane — Implementation Plan

- Status: Proposed implementation sequence; not an API or runner contract amendment.
- Scope: M1 Run/Submit orchestration after prerequisite contracts and security gates are approved.
- Architecture anchors: ADR-0006, ADR-0007, ADR-0012 and ADR-0014.

## 1. Current verified baseline

The API currently exposes liveness/readiness and authenticated problem-catalog GET routes. Run, Submit, status, timeline and feedback handlers are not implemented. The web execution adapter is a non-executing mock. The Go runner exposes health/readiness only and uses `UnconfiguredExecutor`, which fails closed.

The following are proposals, not approved implementation contracts:
- Runner result classification: PR #16.
- Runner request protocol gap analysis: PR #18.
- OpenAPI security/idempotency alignment: PR #21.
- Authenticated tenant-boundary tests: PR #26.

The gVisor smoke harness is not a completed adversarial isolation proof. M0 remains a release gate, not an assumption.

## 2. Non-negotiable invariants

- Never execute student code in Workers, Durable Objects, the API process or frontend.
- Every Run and Submit creates a new immutable attempt and exact source snapshot/hash.
- PostgreSQL is authoritative for attempts, jobs, idempotency, outbox and terminal results.
- Queue delivery is at-least-once; dispatch, claim and result persistence must be idempotent.
- Client cannot choose hidden tests, test bundle, image digest, comparison policy or resource limits.
- Hidden inputs/expected outputs never reach the browser, student logs or untrusted runner response.
- Student-code verdicts and infrastructure failures remain separate dimensions.
- A terminal result cannot be overwritten by a conflicting retry.
- The runner remains fail-closed until M0 evidence and review are accepted.

## 3. Proposed lifecycle

`REQUESTED -> QUEUED -> CLAIMED -> RUNNING -> EVALUATING -> COMPLETED`

Terminal alternatives: `FAILED_INFRASTRUCTURE`, `CANCELLED`, `EXPIRED`.

The job lifecycle is separate from the result dimensions:
- Infrastructure execution status.
- Compilation status.
- Student verdict.
- Sandbox cleanup status.

Exact enums and transitions must be finalized by approval of the request/result contracts before implementation.

## 4. API transaction boundary

For POST Run and Submit:

1. Authenticate user and resolve trusted tenant membership.
2. Authorize problem visibility, student identity, active batch/college scope and action quota.
3. Validate bounded request size, problem version, supported language/runtime policy and source encoding.
4. Derive action from route; derive test bundle, runtime image digest, comparison policy and limits from trusted server policy.
5. Compute source SHA-256 over exact accepted bytes.
6. Validate idempotency key scoped to tenant + user + endpoint.
7. In one PostgreSQL transaction:
   - reserve/resolve idempotency record;
   - create immutable attempt and source artifact metadata;
   - create execution job in QUEUED state;
   - append outbox event.
8. Commit before returning `202 Accepted`.
9. Return opaque submission/execution ID, QUEUED state, status URL and correlation ID. Never wait for compilation/execution in the request.

Same idempotency key + same canonical payload returns the same logical operation. Same key + different payload returns conflict. Database uniqueness constraints, not in-memory checks, enforce this under concurrency.

## 5. Outbox and queue dispatch

- Outbox publisher claims eligible rows with a bounded lease and publishes stable execution IDs.
- Mark published only after queue acknowledgement; lease expiry permits safe retry.
- Queue payload contains opaque IDs and protocol version, not source code or hidden tests.
- Queue delivery may duplicate. Consumer claim is conditional on valid job state and lease.
- Configure bounded retry/backoff and dead-letter handling with operator-only replay.
- Never use a queue message as the authoritative job record.

Cloudflare Queues remains the chosen transport per ADR-0006. Durable Objects are not required for the first implementation; use only if a demonstrated coordination or live-fan-out need exists.

## 6. Runner trust boundary

- API/control plane sends authenticated service-to-service work to the runner.
- Runner validates request schema, deadline, image digest allowlist, artifact hashes and resource limits.
- Runner retrieves source/test artifacts through narrowly scoped service credentials outside the sandbox.
- Sandbox receives only the minimum source, runtime and test inputs needed for that execution.
- No network, cloud credentials, database credentials or host mounts inside the sandbox.
- Result callback is authenticated, bounded, correlated to the claimed execution and idempotent.
- Runner returns aggregate hidden-test outcomes only; no hidden input or expected output.

No execution adapter or endpoint should invoke a real executor before M0 is accepted.

## 7. Persistence and state transitions

Use conditional updates and explicit state/version checks:
- Only QUEUED jobs can be claimed.
- Only the current lease owner can advance CLAIMED/RUNNING states.
- Cancellation/expiry must race safely with completion.
- Result persistence uses execution ID + result version/hash to reject conflicting duplicates.
- Terminal state is immutable; late callbacks are recorded as rejected/duplicate audit events.
- Retry only classified infrastructure failures, never compile errors, runtime errors or wrong answers.
- Keep attempt/source evidence immutable even if a job is retried.

## 8. Read/status API

- GET status verifies tenant and student/authorized trainer scope before lookup.
- Return state, timestamps, safe verdict, public-test aggregate and bounded sanitized output.
- Hidden test results are aggregate-only; never return hidden case identifiers, input or expected output.
- Timeline is derived from immutable attempt/audit events and is tenant-scoped.
- Feedback is advisory and separately versioned; it cannot alter deterministic verdicts.
- Polling is sufficient for first release. Do not add Durable Objects/WebSockets until measured load and latency justify them.

## 9. Implementation sequence and gates

| Stage | Work | Exit criteria |
| --- | --- | --- |
| A. Contract approval | Approve request/result DTOs, state machine, error taxonomy, idempotency semantics and OpenAPI | Reviewed normative specs; versioning decision recorded |
| B. Identity | Select provider, implement trusted principal/membership adapter and authorization | Identity test matrix passes; tenant isolation reviewed |
| C. Persistence | Migrations for idempotency, attempts, snapshots, jobs, outbox, result dimensions and audit | Constraints, rollback, retention and least-privilege tests pass |
| D. API intake | Run/Submit POST handlers with transactional persistence and 202 response | Concurrent idempotency and authorization tests pass |
| E. Dispatch | Outbox publisher and queue consumer with leases, retries and DLQ | Duplicate delivery/restart/replay tests pass |
| F. M0 runner proof | Linux host, pinned runtimes, gVisor isolation, resource limits and cleanup | All adversarial gates evidenced and reviewed |
| G. Runner integration | Authenticated protocol adapter and result callback | Protocol, deadline, cancellation, hash and idempotency tests pass |
| H. Read APIs | Status/timeline and sanitized results | Cross-tenant and hidden-test disclosure tests pass |
| I. Pilot | Staging load, monitoring, operator runbooks and controlled cohort | Explicit pilot approval and rollback plan |

Stages B and A can proceed in parallel as design work, but D/G must not bypass A, and real execution must not bypass F.

## 10. Operational acceptance tests

- Concurrent duplicate POST with same idempotency key.
- Same key with different payload.
- API crash before/after transaction commit.
- Outbox publish succeeds but acknowledgement is lost.
- Duplicate queue delivery and expired consumer lease.
- Runner restart while claimed/running.
- Duplicate and late result callbacks.
- Cancellation racing with completion.
- Deadline expiry before claim and during execution.
- Database outage, queue outage and DLQ replay.
- Cross-tenant status/timeline lookup.
- Hidden-test disclosure probes across API, logs, traces and runner response.
- Retention/deletion of source snapshots and attempt evidence.
- Load and concurrency measurement on the selected Linux host.

## 11. Explicit non-goals for first control-plane increment

- AI feedback, code-quality scoring or mastery inference.
- Durable Object live status fan-out.
- Multi-region execution.
- Arbitrary custom package installation or sandbox network access.
- Public launch or high-stakes assessment production approval.
