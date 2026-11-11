# M0 Authorization Transaction Enforcement Proposal

**Status:** Proposed database-enforcement design; not an approved migration.  
**Execution boundary:** No production migration, database role, stored procedure, signer, host execution or Phase A/Phase B/student/production authorization is created by this proposal.

## 1. Corrected data ownership

Immutable run-claim identity and changing execution outcome are separate records. A claim reserves one authorization budget slot exactly once. Its identity and request digest are immutable. Execution progress is represented by a separate append-only event stream; the claim row is never updated to change CLAIMED to COMPLETED/FAILED.

This corrects a contradiction in the earlier model, which described run claims as immutable while placing mutable `claim_status` on the claim row.

- `authorization_run_claims`: immutable identity, authorization ID, run ID, request digest, claim sequence, claimed state version and claimed time. Unique (authorization ID, run ID) and (authorization ID, claim sequence).
- `authorization_run_events`: append-only outcome history, claim ID, per-claim sequence, event type (CLAIMED/STARTED/COMPLETED/FAILED/QUARANTINED), request ID/digest, time and previous/current event digests. Unique (claim ID, sequence) and (claim ID, request ID).
- `phase_a_authorizations.consumed_runs`: denormalized counter maintained in the same transaction; it must equal the number of immutable claims. Drift causes quarantine/reconciliation, never a silent decrement.

The initial CLAIMED event commits atomically with the claim row, budget increment and authorization CONSUMED event. Later outcomes append run events; they never rewrite claim identity.

## 2. Database enforcement requirements

The final implementation must use reviewed, narrowly scoped PostgreSQL procedures. The API role receives EXECUTE on approved procedures only; it has no direct INSERT/UPDATE/DELETE on authorization projections, event tables or claim tables.

- Every security-definer procedure uses a fixed safe `search_path`, bounded statement/lock timeouts, no unsafe dynamic SQL, and explicit caller/tenant context checks.
- Global lock order: authorization projection row first; then claim/request identity; then append-only event rows. Acceptance, consumption and revocation follow the same order.
- Consumption locks the authorization row with `SELECT ... FOR UPDATE` and validates expected state version, ACCEPTED state, exact host epoch acceptance, fresh witness/revocation generation, key status, trusted time and budget inside the transaction.
- Unique constraints are final guards. Conflict resolution fetches the existing claim and compares exact request digest; digest mismatch is conflict, never idempotency.
- Claim insert, initial run event, authorization event, counter increment and state-version increment commit atomically.
- Serialization/deadlock retries reuse the exact request ID/digest. They never create a new logical run ID or refund a committed claim.
- Revocation and consumption lock the same authorization row. A claim committed before revocation remains consumed but cannot be resumed after revocation; a claim ordered after revocation is rejected.
- Database revocation does not terminate a running guest or fence a provider instance. Those remain independently evidenced actions.

## 3. Consume-run transaction algorithm

This is a normative sequence, not deployable SQL:

1. Begin SERIALIZABLE transaction; apply bounded lock and statement timeouts.
2. Lock authorization projection row.
3. Resolve an existing (authorization ID, run ID) claim. Same digest returns immutable claim identity; changed digest conflicts. If authorization is revoked or any trust/revocation/epoch anchor is uncertain, mark it non-resumable.
4. Require exact expected state version; ACCEPTED state; exact host enrollment/receipt/acceptance/epoch; fresh external checkpoint; active purpose/environment-correct key; valid review/qualification/evidence; trusted time within authorization window.
5. Require consumed count below maximum.
6. Insert immutable claim and initial CLAIMED run event.
7. Append authorization CONSUMED event with next sequence/digest; increment consumed counter and state version.
8. Assert counter equals immutable claim count and commit.
9. Dispatch the bounded calibration runner only after commit or deterministic read-only resolution of the same committed idempotency key.

## 4. Revoke transaction algorithm

1. Verify revocation request, authority, key status, signature and evidence; require current witness freshness.
2. Begin SERIALIZABLE transaction and lock the same authorization projection row first.
3. Resolve idempotency by request ID and exact request digest.
4. Append REVOKED event; set terminal REVOKED state; increment state version and revocation generation in the same transaction.
5. Commit. From this point, no new claim or claim resume is allowed.
6. Independently disable host admission and request provider fencing; persist operation references and independent verification. Do not claim that the database commit killed an existing process.

## 5. Deterministic crash and concurrency matrix

| ID | Injected boundary / ordering | Required invariant |
|---|---|---|
| TX-001 | Crash before transaction | No claim, event or counter change |
| TX-002 | Crash after claim insert before commit | Whole transaction rolls back |
| TX-003 | Commit succeeds, acknowledgement lost | Same run ID/digest resolves original claim; no second slot |
| TX-004 | Retry same run ID and digest | Idempotent read of original claim |
| TX-005 | Retry same run ID with changed digest | Conflict; no mutation |
| TX-006 | Two claimers race for one remaining slot | Exactly one claim commits |
| TX-007 | Claim commits before revocation | Slot remains consumed; no resume after revocation |
| TX-008 | Revocation commits before claim | Claim rejected |
| TX-009 | Stale witness/revocation generation | Claim rejected fail-closed |
| TX-010 | Authorization event digest altered | Independent chain check detects tamper |
| TX-011 | Update/delete claim identity | Database privilege/trigger guard rejects |
| TX-012 | Rewrite terminal run event | Append-only guard rejects |
| TX-013 | Counter differs from immutable claim count | Quarantine/reconcile; never refund |
| TX-014 | Crash after commit before runner dispatch | Budget remains consumed; same claim reconciled, not recreated |
| TX-015 | Runner outcome write retried | Same request resolves original event; changed digest conflicts |

## 6. Deterministic reference-model validator

`scripts/validate_m0_authorization_transaction_contract.py` is a pure-Python in-memory reference model. It tests pre-commit rollback, post-commit lost acknowledgement, idempotency, changed-digest conflicts, final-slot enforcement, both claim/revocation serial orderings, post-revocation resume denial, immutable claim identity, run-event terminality, digest-chain tamper detection and stale revocation freshness. Its companion fixture catalog `docs/schemas/m0-authorization-transaction-fixture-catalog.json` requires exactly 15 unique cases (TX-001 through TX-015), all mapped to this executable reference validator.

This is not PostgreSQL integration. Before migration approval, exact procedures and constraints must be tested against PostgreSQL with concurrent sessions, forced process termination, connection loss around COMMIT, serialization retries, role/privilege tests, backup/restore and independent witness reconciliation.

## 7. Approval gate

No production DDL or migration may be applied until the external authority/provider protocol, cryptographic profile and custody, witness implementation, evidence-store retention behavior, Neon role model and independent security review are approved. This proposal does not select Neon deployment settings or claim current Neon/R2 services meet these requirements.


## 8. Disposable PostgreSQL integration evidence

The General CI test harness at `apps/api/src/db/authorization-ledger.integration.test.ts` now exercises a uniquely named disposable schema against PostgreSQL 17. It creates only test-local tables, triggers, a NOLOGIN application role and the `pgcrypto` extension in the ephemeral CI database; it does not apply authorization production DDL.

Twelve integration cases are defined in the harness; exact-head CI execution is required before treating the new cases as passing:
- Independent database sessions race for the final budget slot; exactly one claim is committed.
- A committed claim is resolved by retrying the same request identity; changed digest conflicts. The test simulates an acknowledgement not consumed by the client after the helper returns; it does not simulate a TCP proxy dropping the COMMIT response.
- A separate controlled TCP proxy test forwards the PostgreSQL wire stream, detects the backend `CommandComplete` frame tagged `COMMIT`, drops that frame before it reaches the client, and closes the connection. A fresh connection verifies the claim, event and consumed counter committed exactly once; an identical retry replays and a changed digest conflicts.
- Explicit rollback removes tentative claim, event and counter writes together.
- Revocation-first and claim-first orderings serialize on the same authorization row.
- The application role cannot update/delete immutable claim or run-event rows.
- Deferred constraint triggers reject a transaction that would make the consumed counter differ from the immutable claim count. The attempted drift transaction rolls back, leaving the committed claim and counter intact.
- A test-only event trigger enforces contiguous event sequence, exact predecessor digest linkage, and a SHA-256 digest over the canonical test tuple; it rejects skipped sequence/forged predecessor inserts and all UPDATE/DELETE operations.
- PostgreSQL backend termination during an open transaction rolls back the claim, run event and counter update.
- An independent application-side verifier recomputes every persisted event digest, sequence and predecessor link; altered payload and reordered rows are rejected without relying on the database trigger.
- Two real PostgreSQL sessions acquire two authorization-row locks in opposite order; PostgreSQL detects the deadlock with SQLSTATE `40P01`, and the surviving transaction is released after the victim aborts.

The test-only event digest is an integrity-chain check, not a signature or independent cryptographic attestation. The database trigger cannot establish trust in an external signer, authority, host or provider. The deferred counter constraint demonstrates prevention of inconsistent committed state in this fixture; it does not provide production quarantine workflows or replace independent ledger reconciliation.

The backend-termination test covers server-side cancellation before COMMIT. The TCP proxy test now exercises a genuine lost-COMMIT-acknowledgement boundary in the disposable CI database. It is test-only fault injection, not a production proxy or proof of network behavior in every deployment environment. Serialization-failure (`40001`) retry behavior is also not yet exercised or implemented; the deadlock test proves PostgreSQL detection only and does not define a production retry policy.

These tests strengthen the proposed transaction semantics but do not approve production migrations, stored procedures, runtime signing, external fencing, guest execution or Phase A/Phase B/student/production authorization.
