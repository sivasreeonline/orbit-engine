# Transactional Execution Intake Repository — Prototype

- Status: isolated engineering prototype; not approved for production or route integration.
- Parent schema proposal: PR #28, `feat/execution-intake-persistence-foundation`.
- This prototype deliberately adds no HTTP handler, queue publisher, runner callback, result model or authentication provider.

## Transaction boundary

`PostgresExecutionIntakeRepository.create` performs the following writes on one PostgreSQL connection and transaction:

1. Snapshot source bytes and compute SHA-256 over the exact copied byte sequence.
2. Insert a tenant/actor-bound source snapshot.
3. Insert the immutable Run/Submit attempt.
4. Insert its queued execution job.
5. Reserve the scoped idempotency key with `ON CONFLICT DO NOTHING`.
6. Insert the metadata-only outbox event.
7. Commit.

The outbox event contains only execution ID, attempt ID and protocol version. Source bytes and hidden tests are not placed in the event.

## Concurrent idempotency behavior

The repository uses PostgreSQL's unique constraint on tenant, actor, endpoint and idempotency key as the concurrency arbiter. The idempotency reservation is inserted after the speculative snapshot/attempt/job writes, but before the outbox write.

- If the reservation succeeds, the outbox is inserted and the transaction commits.
- If a concurrent request already committed the same scoped key, `ON CONFLICT` waits for that transaction as required by PostgreSQL. A subsequent READ COMMITTED statement reads the winning reservation.
- The losing transaction rolls back its speculative source snapshot, attempt and job.
- If the stored request hash matches, the repository returns the original attempt and execution IDs as `REPLAYED`.
- If the stored request hash differs, it returns `IDEMPOTENCY_CONFLICT` after rollback.
- Any database failure before commit rolls back the transaction and returns a non-disclosing persistence error.

The implementation relies on PostgreSQL's default READ COMMITTED isolation. If the connection role/database changes the transaction isolation default, this assumption must be made explicit in deployment configuration or the transaction code before adoption.

## Trusted input boundary

The command type is internal and must not be populated directly from an HTTP body.

- Principal tenant and user IDs must come from a configured, trusted authentication and membership layer.
- Problem ID and published version ID must be resolved and authorized by the API.
- Runtime version must be selected from a server-side allowlist.
- `requestHash` must be computed by a server-side canonicalizer over the approved semantic request fields. This prototype validates the SHA-256 shape but does not define canonicalization.
- Source bytes are copied before hashing and persistence so the digest cannot be separated from the bytes by caller mutation during an asynchronous operation.

The current source storage implementation is DATABASE-backed and has a prototype 1 MiB input bound. R2 storage, approved size policy, retention and deletion are not implemented.

## Test coverage

The Vitest suite checks:
- atomic create path and metadata-only outbox;
- same-key/same-hash replay returns original identifiers;
- same-key/different-hash conflict;
- rollback when outbox insertion fails;
- missing database binding fails closed;
- invalid hash and oversized source rejected before connection.

These tests use a fake PostgreSQL client. They do not prove actual concurrent behavior, transaction isolation, PostgreSQL lock behavior, or migration compatibility under load. Those require a PostgreSQL integration test that runs two independent database connections concurrently against migration 0003.

## Adoption blockers

Before route integration:
1. Approve normative request/result contracts and state machine.
2. Define canonical request serialization and hash fields.
3. Approve identity provider and tenant membership resolution.
4. Approve source size, storage, encryption, retention and deletion policy.
5. Define database role grants and migration rollout strategy.
6. Add real PostgreSQL concurrency tests using two independent connections.
7. Review ambiguous commit outcomes and retry behavior.
8. Approve error-to-HTTP mapping and replay response semantics.

Do not wire this prototype into the API, deploy migration 0003 to production, or enable execution based solely on its unit tests.
