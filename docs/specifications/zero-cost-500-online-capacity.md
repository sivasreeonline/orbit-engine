# Zero-cost-first capacity plan: 500 online students

**Status:** Proposed engineering plan  
**Target:** 500 concurrently online students; execution is queued and capacity-controlled.  
**Cost rule:** Local development and CI must remain usable without paid cloud resources. No paid host or service may be provisioned without explicit owner approval.

## 1. Capacity contract

The initial capacity target means 500 authenticated students may be online concurrently, using normal platform features and submitting execution requests. It does **not** mean 500 programs execute simultaneously.

The system must:
- Keep API and student-facing reads responsive while execution is backlogged.
- Accept valid Run/Submit requests durably or reject them explicitly with retry guidance.
- Return an execution ID and a durable state (QUEUED, CLAIMED, RUNNING, or terminal).
- Preserve each Run and Submit as a distinct immutable attempt and source snapshot.
- Enforce per-student fairness so one student cannot monopolize all runner slots.
- Recover safely from duplicate delivery, worker crashes, expired leases and lost acknowledgements.
- Never report a student verdict for infrastructure failures; use NOT_EVALUATED where applicable.
- Keep hidden tests, expected outputs, raw diagnostics and other private artifacts out of student-facing status responses.

## 2. Cost-zero development topology

Use the existing repository stack and avoid adding a second queue product:

- Vite/React web app: local development server.
- API/control plane: local Wrangler Worker.
- PostgreSQL: local Docker container, using the same migrations and repository contracts as CI.
- Source/test artifacts: local private object-store adapter or bounded database fixture for development; production R2 remains a separate adapter.
- Queue authority: PostgreSQL job + outbox records already created transactionally by execution intake.
- Local dispatcher: a development-only poller that reads committed outbox records and invokes the same internal handoff contract.
- Runner: local Go process for protocol and orchestration tests; real untrusted-code execution remains disabled until Linux sandbox qualification passes.

No Redis, paid queue, hosted runner, Neon project, R2 bucket, Cloudflare paid plan or AWS resource is required for this development loop. The local poller is not a production replacement for Cloudflare Queues; it exercises the durable contracts without cloud spend.

## 3. Authoritative queue and delivery semantics

PostgreSQL remains the source of truth. A broker message is a wake-up/delivery mechanism, not the authoritative job record.

1. Intake transaction stores source snapshot, attempt, job, idempotency record and outbox event atomically.
2. Dispatcher claims outbox work with a bounded lease and publishes only opaque identifiers/metadata.
3. Consumer validates the message against authoritative database state and creates or reuses the durable runner-dispatch intent.
4. Runner dispatch is claimed with a database lease and a unique fencing token.
5. Runner acceptance receipt is persisted before the dispatch is treated as delivered.
6. Execution result finalization requires the active worker identity, lease token and unexpired lease.
7. Duplicate messages and lost acknowledgements resolve to the original durable identity; they never create a second attempt or overwrite evidence.

Keep the API intake outbox and runner-dispatch outbox separate. A Cloudflare Queue acknowledgement must never be treated as proof that a runner accepted or completed an execution.

## 4. Fair scheduling policy to implement

The existing FIFO job claim mechanism is not sufficient as the final multi-student fairness policy. Add fairness at the scheduler/dispatch layer without changing immutable attempt identity:

- Partition pending work by authenticated tenant and student identity derived from the stored attempt, never from a queue payload supplied by a client.
- Preserve FIFO order within each student's lane.
- Select lanes using a deterministic round-robin/deficit-round-robin policy; do not allow a single student's burst to occupy every dispatch slot.
- Apply a configurable per-student in-flight ceiling and a global runner concurrency ceiling.
- Keep Run and Submit distinct. Do not silently discard Runs; any future priority policy must be explicit, observable and preserve both histories.
- Use bounded leases, fencing tokens and idempotent dispatch receipts for crash recovery.
- Enforce queue age and retry limits with explicit terminal infrastructure outcomes and operator-visible dead-letter state. Never silently drop work.
- Make the fairness scheduler stateless between claims where possible; PostgreSQL stores the durable lane/claim cursor so restarts do not reset fairness.

Exact lane schema, per-student in-flight limit, global concurrency, queue TTL and retry budget are configuration decisions to be measured and reviewed, not guessed here.

## 5. Free-tier cloud posture

Cloud services are optional adapters, not prerequisites for local development. Before any free-tier deployment:
- Measure request volume, queue operations, database compute/egress, object storage and artifact retention against current provider limits.
- Keep the platform usable when execution capacity is exhausted: status reads and learning content must not be blocked by runner saturation.
- Apply bounded admission and backpressure rather than accepting an unbounded queue.
- Do not claim 500-online capacity from provider free-tier quotas alone; validate it with load tests.
- Do not run untrusted code inside Workers or Durable Objects.
- Treat any free-tier deployment as a non-production experiment until security, identity, retention and availability gates pass.

## 6. Capacity test plan

### A. Online-user simulation (target: 500)
Simulate 500 authenticated sessions with realistic mixes of:
- problem/catalog reads and navigation;
- timeline/history reads;
- status polling or live status updates;
- a smaller, explicitly parameterized percentage submitting Run/Submit jobs.

Measure API p50/p95/p99 latency, error rate, database connections/CPU, queue depth, queue age, memory, and status freshness. Avoid synchronizing all clients into a thundering herd.

### B. Execution burst tests
Test separately with controlled bursts (for example 10, 25, 50 and 100 queued requests) while runner concurrency is deliberately lower. Verify fairness, queue ordering, idempotency, lease recovery, cancellation and evidence completeness.

### C. Acceptance gates
- All accepted requests have durable job/attempt identities.
- No duplicate attempt or duplicate terminal result under redelivery/retry.
- No cross-student history or source access.
- Per-student fairness is demonstrated under a single-student burst plus other students' arrivals.
- Runner saturation causes queueing/backpressure, not API collapse.
- Infrastructure failures remain distinct from compilation errors and student verdicts.
- 500-session load test completes within an agreed latency/error budget, which must be set after a baseline run.

## 7. Explicit non-goals and gates

- This plan does not assert that 500 simultaneous code executions are possible or desirable.
- It does not enable real execution. The mock frontend adapter, unconfigured authenticator/executor and Linux/gVisor qualification gates remain.
- It does not approve AWS or any paid host.
- It does not select numerical fairness weights, queue limits, concurrency or retention periods without measurement.
- It does not replace the existing execution-intake, job-claim, outbox, dispatch-receipt or append-only evidence models.

## 8. Implementation sequence

1. Verify and reuse the existing PostgreSQL job-claim, intake outbox, runner-dispatch outbox and receipt contracts.
2. Add local development dispatcher/poller behind a development-only configuration flag.
3. Add durable per-student scheduling lanes and fair claim tests.
4. Add queue status API/read model with safe, owner-scoped fields.
5. Add 500-session API/load harness and execution burst/fault scenarios.
6. Only after local evidence: evaluate current Cloudflare free-tier adapters and limits.
7. Only after a measured gap and explicit approval: propose a paid runner capacity plan.

## 9. Current truth

The repository already contains transactional intake, PostgreSQL job claims, durable outbox/dispatch work, dispatch receipts and append-only execution evidence across stacked draft pull requests. Those foundations are not equivalent to a deployed queue consumer or a working isolated runner. The authenticator and executor remain fail-closed; the student Run/Submit adapter is still a mock. This document is a proposed capacity plan, not proof of implementation or scale.
