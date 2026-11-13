# Fair runner-dispatch scheduling

**Status:** Proposed implementation slice  
**Target:** Prevent one student's pending burst from monopolising dispatch batches while preserving FIFO order within each student's lane.

## Identity and lane ownership

A lane is keyed by (tenant_id, actor_user_id) from the authoritative immutable execution_attempts row. Queue payloads never supply scheduler ownership. The lane is created in the same PostgreSQL transaction that records the durable runner-dispatch intent.

## Selection policy

- Each scheduler batch selects at most one eligible dispatch from each student lane.
- Eligible lanes are ordered by a persisted monotonically increasing last_served_ticket, then tenant and actor IDs for deterministic tie-breaking.
- Within a selected lane, the earliest eligible dispatch is chosen by available_at, created_at, then dispatch ID.
- A lane's cursor is advanced using a PostgreSQL sequence only after a dispatch row was successfully claimed.
- Lane rows are locked with FOR UPDATE SKIP LOCKED, so concurrent fair schedulers claim different lanes where available.
- Dispatch rows receive the existing worker ID, lease token and expiry; stale workers remain fenced by the existing lease predicates.

The monotonic ticket avoids timestamp ties causing the same student to repeatedly win after each polling cycle.

## Scope and limits

This slice provides fair batch selection, not a per-student active-execution quota. A student with the only eligible lane may continue receiving dispatch capacity; fairness means sharing available batch slots when multiple students have eligible work. Global runner concurrency remains a separate runner/host admission control.

The scheduler does not prioritise Submit over Run, discard Run requests, or change immutable attempt identity. Both actions remain distinct jobs and evidence.

## Recovery

A worker crash leaves the dispatch leased until expiry. A later scheduler can reclaim it with a new fencing token. The lane cursor advances only when a claim succeeds. Duplicate delivery remains resolved by the existing unique dispatch intent.

## Validation

CI applies and re-applies migration 0006, checks monotonic cursor behavior, and runs PostgreSQL integration tests with two students each submitting multiple jobs while two schedulers claim concurrently. Tests verify one claim per student in the first round, the next queued job from each lane in the next round, and distinct persisted scheduler tickets.

## Not yet proven

This is not a 500-session load test, runner transport, authenticated machine dispatch, per-student in-flight cap, or real code execution proof. Numerical capacity and concurrency settings remain measurement decisions.
