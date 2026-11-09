# Execution Intake Persistence Schema — Proposal

- Status: Draft for review; not approved for production use.
- Migration: `apps/api/migrations/0003_execution_intake_foundation.sql`
- Acceptance checks: `apps/api/migrations/tests/0003_execution_intake_foundation.sql`
- Scope: persistence foundation for immutable attempts, source snapshots, idempotency, execution jobs and transactional outbox.
- This proposal does not implement HTTP handlers, queue dispatch, runner execution or result persistence.

## Design mapping

| Table | Responsibility | Key safety property |
| --- | --- | --- |
| `source_snapshots` | Exact source bytes or private R2 object reference, SHA-256 and byte length | Immutable; tenant/actor-bound |
| `execution_attempts` | Immutable Run/Submit evidence and pinned problem/runtime/source identity | Immutable; composite FK pins version to problem |
| `execution_jobs` | Mutable orchestration state, retry counter and lease | One job per attempt; explicit state/lease constraints |
| `execution_idempotency` | Scoped idempotency reservation and request hash | Unique tenant + actor + endpoint + key |
| `execution_outbox` | Durable queue publication intent | One event per execution; bounded metadata-only payload |

## Transaction boundary intended for the future API

A future POST handler should, in one PostgreSQL transaction:
1. Insert or resolve the scoped idempotency record.
2. Insert the immutable source snapshot.
3. Insert the immutable execution attempt.
4. Insert its QUEUED execution job.
5. Insert the metadata-only outbox event.
6. Commit, then return `202 Accepted`.

The exact ordering of idempotency reservation versus attempt insertion, conflict replay behavior and canonical request hashing must be implemented together in a transaction service and tested under concurrent requests. This migration alone does not implement those semantics.

## Important constraints

- The source snapshot supports database bytes or a private R2 object key. No public URL or presigned URL is stored.
- The database storage location constraint checks exact byte length. It intentionally does not choose a universal R2 threshold; that belongs to an approved server policy.
- An insert trigger checks that attempt tenant, actor and source hash match the referenced snapshot metadata.
- Attempts and source snapshots reject UPDATE and DELETE. Retention/deletion needs a separately approved privileged workflow and legal/privacy policy.
- Job state values are constrained, but legal state transitions and lease-owner authorization are not yet enforced. A future state-transition service must use conditional updates and row locking.
- The outbox payload must include execution ID, attempt ID and protocol version; it rejects source code, hidden tests, expected output and credential-shaped fields.
- The outbox payload is metadata only. Source and test artifacts are fetched later by an authenticated runner service outside the sandbox.
- Result dimensions and terminal result payloads are intentionally omitted until the normative runner result contract is approved.
- Identity foreign keys are omitted because this repository does not own the platform identity schema. User and tenant identifiers must be supplied only by the trusted authentication/membership layer.

## CI coverage

The API CI applies the migration twice to a disposable PostgreSQL database and runs SQL acceptance checks for:
- source snapshot and attempt immutability;
- scoped idempotency uniqueness;
- rejection of source code in outbox payloads;
- terminal job completion timestamp consistency.

This proves PostgreSQL schema behavior in CI only. It does not prove production migration safety, tenant authorization, queue delivery, runner authentication or sandbox isolation.

## Decisions still required

1. Approve the normative request/result contracts and execution state machine.
2. Define source-size policy, R2 object lifecycle, encryption and retention/deletion.
3. Define request canonicalization and idempotency conflict/replay behavior.
4. Define legal job transitions, retry classification, lease duration and dead-letter policy.
5. Define database roles and exact grants for API intake, outbox publisher and operator tooling.
6. Review indexes and query plans against expected pilot load.
7. Approve migration ordering and rollback/forward-fix strategy.

Do not apply this migration to a production database until these decisions and the associated PR review are complete.
