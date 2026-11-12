# Evidence Engine E1.3 — Immutable attempt timeline

## Purpose

Present a student's coding activity as an ordered sequence of immutable Run and Submit attempts, with the safe execution lifecycle events and terminal result attached to each attempt.

The timeline is a read model over the existing execution intake and append-only evidence records. It does not create a second attempt store or modify historical evidence.

## API contract

`GET /api/v1/problems/{problemSlug}/timeline?limit=30`

- Requires an authenticated principal.
- Tenant and actor scope are taken only from that principal.
- The limit defaults to 30 and is bounded from 1 through 100.
- Each item represents one immutable attempt and includes its action, language/runtime, source digest/byte length, creation time, execution state and persisted terminal result fields.
- Each item contains its append-only execution events ordered by their database sequence ID.
- Event payload is restricted to allowlisted event type, actor kind, phase status, safe machine code, duration and timestamp.
- Raw source code, compiler/runtime diagnostics, hidden tests, expected outputs and judge internals are not included.
- The source can be reopened separately through the owner-scoped attempt source endpoint.

## Storage and query behavior

- The timeline is assembled in one SQL query using the existing `execution_attempts`, `execution_jobs`, `source_snapshots`, `execution_result_records` and `execution_evidence_events` records.
- Attempts are filtered by tenant, actor and problem slug.
- Events are joined using execution ID, exact attempt ID and the attempt's tenant/actor scope.
- Events are aggregated in ascending sequence order.
- Attempts are ordered newest first, with attempt ID as a deterministic tie-breaker.
- No derived timeline row is persisted; this is a read model over append-only records.

## Safety and semantics

- Run remains diagnostic; Submit remains the official submission action.
- Each Run/Submit remains a distinct attempt.
- Timeline ordering does not imply that an older result has been overwritten by a newer one.
- Historical attempts remain immutable; reopening source is a read operation.
- Student visibility is limited to safe, allowlisted lifecycle evidence.
- The API uses `Cache-Control: no-store`.

## Implemented in this slice

- `listProblemAttemptTimeline` in the existing PostgreSQL evidence repository.
- Authenticated API endpoint for problem-scoped timeline retrieval.
- Unit tests for the aggregated query, ownership predicates, event ordering and safe event mapping.
- API tests for authenticated scope, payload shape and limit validation.
- PostgreSQL integration test covering multiple events and exclusion of another student's attempt.
- CI step to execute the PostgreSQL integration test.

## Explicit exclusions

- No frontend history/timeline UI has been connected yet.
- No actual code execution is enabled by this work.
- No R2 private object reader is added.
- No raw diagnostic storage or disclosure policy is changed.
- No learning evaluation, confidence score, retention inference or recommendation is generated here.

## Validation status

The code and CI test steps have been added to the stacked draft PR. CI execution has not yet been confirmed; do not treat the tests as passed until the workflow reports success.
