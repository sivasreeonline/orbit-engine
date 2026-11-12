# Evidence Engine E1 — Owner-Scoped Source Snapshot Retrieval

- Status: implementation slice, stacked on the draft append-only execution evidence PR.
- API: `GET /api/v1/attempts/{attemptId}/source`
- Repository: `apps/api/src/db/execution-source-snapshot-repository.ts`
- Scope: retrieve the exact immutable source bytes already attached to one admitted Run or Submit attempt.

## Research alignment

This slice implements a missing read path over the existing immutable-attempt foundation; it does not create a second snapshot system.

- F2D-0005 establishes code snapshots/diffs and the coding journey as first-class evidence.
- F2D-0276 distinguishes diagnostic Run from official Submit; both contribute to coding-journey evidence, while only Submit is an official submission.
- F2D-0277 requires every meaningful Run to be durably recorded with an immutable code snapshot/reference, language/version, timestamp, outcome, errors, test outcomes, resource metrics where available, correlation/session identifiers and evidence links.
- F2D-0283 makes selected progress informational and the final persisted result authoritative.
- F2D-0284 requires rich internal recording with selective, policy-controlled disclosure.

This is per admitted execution snapshot retrieval. It does not introduce keystroke-level autosave or a new editor-revision event stream.

## Existing source-of-truth records

The proposed 0003 intake schema already defines:

- `source_snapshots`: exact source bytes or a private R2 object reference, SHA-256 and byte length.
- `execution_attempts`: immutable Run/Submit identity linked to one source snapshot and one problem version.
- `execution_jobs`: orchestration state.
- `execution_idempotency`: scoped request replay protection.
- `execution_outbox`: metadata-only durable dispatch intent.

The intake transaction creates the source snapshot, attempt, job, outbox intent and idempotency record together. This E1 slice reuses those records.

## Read contract

The API route:

1. Requires the existing authenticated principal.
2. Accepts a UUID attempt ID; malformed identifiers are rejected before database access.
3. Supplies tenant ID and actor user ID from the authenticated principal, never from request parameters.
4. Queries the attempt and source snapshot in one owner-scoped SQL read.
5. Returns the exact UTF-8 source only after checking the stored byte length and SHA-256.
6. Uses fatal UTF-8 decoding so invalid byte sequences are not silently replaced.
7. Returns `Cache-Control: no-store` through the existing API response policy.

A missing attempt and an attempt outside the caller's tenant/actor scope produce the same non-disclosing 404. Database failures produce a generic retryable 503. Integrity failures produce a generic non-retryable 500 and a correlation-only server log.

## Storage boundary

- `DATABASE` snapshots are supported by this slice.
- `R2` snapshots return a retryable unavailable response until an authenticated private-object reader is configured.
- No public object URL, presigned URL, hidden tests, expected outputs, judge diagnostics or runner artifacts are returned.
- The route does not change retention, deletion, encryption or R2 lifecycle policy.

This deliberately fails closed rather than treating an object key as a publicly readable URL.

## Validation

Unit tests cover:
- exact source reconstruction including CRLF, LF and Unicode;
- authenticated tenant/actor predicates in the SQL query;
- non-disclosing not-found behavior;
- unavailable R2 storage;
- byte-length mismatch;
- SHA-256 mismatch;
- invalid UTF-8;
- database outage mapping; and
- missing database configuration.

API tests cover authenticated route scoping, invalid UUID rejection, 404 behavior and the R2-unavailable response.

## Explicitly not claimed

This slice does not yet:
- connect the React editor's Run/Submit buttons to the API;
- configure a real identity provider;
- execute code in the Go runner;
- retrieve R2 objects;
- expose source snapshots to trainers or other students;
- implement code diff generation or editor draft autosave;
- finalize source retention, deletion or legal-hold policy.

Those are separate integration and policy gates. The local mock adapter remains non-production until the real API and M0 runner are connected.
