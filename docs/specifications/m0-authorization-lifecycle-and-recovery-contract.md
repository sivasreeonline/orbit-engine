# M0 Phase A authorization lifecycle and recovery contract

**Status:** Design contract; not an implementation or authorization.  
**Scope:** External host-incarnation epoch issuance and the separate Phase A cleanup-calibration authorization artifact.  
**Safety:** This document does not select or implement an authority, provider API, cryptographic format, transactional store, or host agent. It does not authorize privileged implementation, Phase A, Phase B, student execution, or production execution.

## 1. Security properties

1. **Single-writer per enrolled host.** Issuance, replacement, revocation, and admission-acceptance operations serialize on the stable enrolled host identity. A lock, lease, or generation held only inside a restorable guest is insufficient.
2. **Monotonic epoch.** The authority commits an epoch strictly greater than the last committed epoch. Epoch allocation and predecessor-fence confirmation are one atomic authority transaction or a recoverable protocol whose intermediate states are never admissible.
3. **Nonce/request binding.** Every issuance request carries a cryptographically unpredictable single-use nonce and canonical request digest. The authority stores the nonce digest, request digest, enrolled host identity, predecessor-set digest, intended provider instance identity, and resulting epoch. Same nonce + same request digest returns the exact prior result; same nonce + changed request digest is a hard conflict. Nonces are never recycled after result expiry or compaction.
4. **Authenticated response.** A response binds protocol version, authority identity/key version, stable host identity, new provider instance identity, epoch, nonce digest, request digest, predecessor-set digest, aggregate predecessor-fence bundle immutable object-version/identity/digest, issuance time, and response identifier. The aggregate bundle contains the complete enumerated predecessor set and one distinct provider-fence attestation per predecessor; see `docs/specifications/m0-fence-001-predecessor-evidence-contract.md`. The consumer verifies the signature/MAC with independently pinned trust material and enforces algorithm/key-use policy. A reference string or signature_reference is not cryptographic verification.
5. **Fence before issue.** Complete predecessor/clone/snapshot enumeration and provider-enforced compute, storage-write, and privileged-control fencing must be verified before the authority commits an admissible epoch. Ambiguous provider outcome is non-admissible.
6. **Durable accept before privilege.** The guest persists the exact authenticated response, accepted epoch, authority/key identity, nonce digest, predecessor-set digest, provider instance identity and evidence references to durable storage. It then reads back and verifies the committed record before allocating a supervisor generation, enabling admission, opening privileged sockets, or allowing privileged operations.
7. **One active incarnation.** Authority serialization and provider fencing prevent two concurrent restore/clone requests from both obtaining admissible epochs. The guest refuses admission unless provider instance identity and accepted epoch match the latest authoritative enrollment result.
8. **Revocation is terminal.** Revocation is monotonic and records authorization/epoch identity, reason, issuer, time, and evidence. A revoked credential never becomes valid again. Re-authorization requires a strictly newer epoch and complete new predecessor-fence proof.
9. **Fail-closed recovery.** Unknown commit outcome, partial response, storage failure, replay, stale epoch, rollback, key uncertainty, revocation-feed inconsistency, or provider ambiguity leaves the instance in RECOVERY_ONLY/quarantine. Recovery never reconstructs trust from guest journal state alone.

## 2. Authority state machine

| State | Meaning | Admission |
|---|---|---|
| ENROLLED | Stable host identity exists; no new epoch is admissible | Denied |
| FENCING | Complete predecessor inventory and provider fence are being established | Denied |
| FENCED | Every predecessor is independently proven stopped or isolated; fence evidence is durable | Denied |
| ISSUED | Epoch/nonce/request binding and authenticated response are durably committed | Not yet admitted |
| ACCEPTED | Matching provider instance has durably read back and accepted the exact response | Eligible only after local readiness checks |
| REVOKED | Epoch/authorization is irreversibly revoked | Denied |
| QUARANTINED | Commit, provider, evidence, or recovery outcome is uncertain | Denied |

No transition may bypass FENCED. ISSUED does not assert that a guest durably accepted the epoch. ACCEPTED is bound to exactly one provider instance identity. A restore/clone creates a new issuance flow; it must never copy an ACCEPTED state from the predecessor.

## 3. Transaction and crash semantics

| Boundary | Required durable result | Recovery rule |
|---|---|---|
| Before predecessor enumeration | No epoch allocated | Retry discovery; no admission |
| During enumeration/fencing | FENCING plus complete observed set or quarantined incomplete set | Reconcile provider truth; never infer missing predecessors are stopped |
| Provider fence succeeded, response lost | Fence evidence durable; no admissible epoch until reconciled | Query provider by stable operation ID; same operation only |
| Before epoch commit | No epoch consumed unless commit is proven | Retry only same nonce/request digest after proving no commit |
| Epoch commit outcome uncertain | Authority record is authoritative; guest cannot guess | Query by nonce/operation ID; return exact committed result or quarantine |
| Response delivered, guest not persisted | Epoch remains issued but not admitted | Idempotently redeliver exact response to exact provider instance |
| Guest durable write interrupted | No readiness | Read back; accept only complete exact record; otherwise RECOVERY_ONLY |
| Guest write committed, acknowledgement lost | Durable accepted record may exist | Read back by response ID and digest; no second acceptance |
| Concurrent clone/restore issuance | At most one serialized successor | Loser receives conflict/denial; no second active instance |
| Revocation races acceptance | Serialized ordering | If revoke commits first, acceptance fails; if acceptance commits first, revocation disables admission and provider fencing follows before successor issuance |
| Key rotation/revocation uncertainty | Trust state not established | Deny new issuance/acceptance; retain old verification key only for audit validation per reviewed policy |
| Authority unavailable during startup | No new epoch proof | Remain RECOVERY_ONLY; do not use cached guest epoch to admit |
| Authority unavailable after admission | Existing instance may continue only within already-authorized bounded policy | Termination/cleanup remain local and independent; no new incarnation or privilege grant |

All authority mutations require a stable operation ID and compare-and-swap against the expected host record version. The transactional key is the enrolled host identity, not the guest instance ID. Provider side effects must themselves be idempotent or reconciled through provider operation IDs; a database transaction cannot atomically commit an external provider power-off.

## 4. Replay and retention rules

- Retain nonce digests, request digests, response IDs, epoch values, authorization IDs, revocation tombstones, and provider operation IDs for the full anti-replay/rollback period.
- Compaction preserves a non-reusable digest tombstone for every consumed nonce and revoked authorization for as long as that identifier could be replayed. If a bounded replay horizon cannot be justified, identifiers remain non-reusable for the lifetime of the enrolled host identity.
- Same nonce + same request digest is idempotent and returns the same response bytes/identity; it must not allocate another epoch.
- Same nonce + changed request digest, reused response ID with different bytes, stale epoch, predecessor-set mismatch, provider-instance mismatch, or authority/key-version mismatch is rejected and audited.
- Revocation and epoch advancement are serialized. Revocation cannot be undone by restoring an earlier snapshot, replaying a prior signed response, or restoring a guest database backup.
- Evidence and audit retention preserves provider fence proof, predecessor enumeration, response signature/attestation, guest durable acceptance readback, revocation state, and key trust metadata for the full approved review period.

## 5. Concurrency acceptance matrix

| Case | Concurrent actions | Required outcome |
|---|---|---|
| C-01 | Two issuers submit same nonce and same request digest | One epoch commit; both receive identical response identity |
| C-02 | Two issuers submit same nonce with different request digests | One request wins; the other conflicts; no second epoch |
| C-03 | Two independent clones request successor epochs simultaneously | One serialized successor only; other clone fenced/denied |
| C-04 | Acceptance races revocation | A single serial order; no admission after revocation commit |
| C-05 | Old predecessor resumes after successor accepted | Provider blocks compute, storage writes and privileged control paths; otherwise qualification fails |
| C-06 | Authority crashes before/after epoch commit | Recovery returns exact committed result or proves no commit; never allocates a second epoch for the same operation |
| C-07 | Guest crashes during epoch persistence | No privilege until complete durable readback verifies exact response digest |
| C-08 | Stale response replayed after newer epoch | Rejected; instance remains quarantined |
| C-09 | Authority key is revoked/rotated while a response is pending | No acceptance under ambiguous key state |
| C-10 | Revocation record is omitted by restored/replicated authority state | Anti-rollback check detects stale authority state; admission denied |

Every case requires deterministic scheduler/barrier control, transaction/version traces, provider observations, exact response/evidence digests, and independent verification. Timing-only stress tests are supplementary and cannot replace controlled interleavings.

## 6. Authorization artifact lifecycle

The Phase A calibration manifest is an immutable signed decision artifact, not a mutable status row. Its lifecycle is tracked separately by an append-only authorization ledger:

- PREPARED: draft bytes/digest exist; not valid for any action.
- ISSUED: independently approved signature verified and immutable manifest version committed.
- ACCEPTED: exact target host/epoch durably accepted the authorization after validating all bindings.
- CONSUMED: one permitted Phase A run atomically claimed the authorization within its run/attempt limits.
- REVOKED: terminal tombstone; no further claim or resume.
- EXPIRED: terminal tombstone after trusted time/authority policy confirms expiry.
- QUARANTINED: any unknown transaction, digest mismatch, missing evidence, time ambiguity, or contradictory ledger state.

The ledger binds authorization UUID and digest, exact host identity and incarnation epoch, authority/key version, security-review record digest, FENCE-001 pass reference/digest, host-qualification record digest, allowed calibration profile/scenario bundle, maximum run count, remaining budget, issuance/acceptance/consumption/revocation events, and immutable object versions.

A run claim is an atomic compare-and-swap that consumes a unique run ID and increments a monotonic consumed-run counter. Concurrent claims cannot exceed max_total_runs; retries of one run ID return the same claim result, while reuse with changed request digest conflicts. A crash after claim never silently refunds budget: recovery reconciles run state and either resumes the same run under the original authorization/deadline or permanently consumes/quarantines that claim. A revoked/expired/quarantined authorization cannot create or resume a run.

No authorization status may be inferred solely from a manifest status string or expiry timestamp. The verifier validates signature, exact immutable object version/digest, authoritative ledger state, revocation status, trusted time, host/epoch binding, and current host qualification/review validity.

## 7. Authorization ledger data model

The application-side relational model, event ledger, bounded run-claim transaction, role separation, evidence references and anti-rollback restore protocol are specified in `docs/specifications/m0-authorization-ledger-data-model.md`. Neon stores this ledger and verified receipt mirrors only; it is not the external provider fencing authority and cannot mint host epochs. The model is a proposal, not an approved or deployed migration.

## 8. Required implementation and evidence before approval

Before privileged implementation or any Phase A authorization, require:

1. A separately reviewed external authority/provider protocol and key lifecycle.
2. A transactional, anti-rollback authority store with unique constraints/CAS and independent recovery.
3. Provider adapter proving complete predecessor discovery and effective compute/storage/control-path fence.
4. Guest acceptance implementation with durable exact-response readback before readiness.
5. Append-only authorization ledger and atomic bounded run-claim operation.
6. Cryptographic implementation with pinned algorithms, signer roles, key rotation/revocation and test vectors.
7. Deterministic concurrency/crash/fault tests for the full matrices above.
8. Independently acquired provider, authority, guest, journal and evidence-store records, verified by a principal separate from the acquirer, host owner and security reviewer.
9. Real immutable evidence object retention/readback and signature/attestation verification.
10. Independent review of the exact implementation commit and host-specific evidence.

Passing synthetic validators does not satisfy any of these runtime or independent-review requirements.

## 9. Cryptographic trust and key lifecycle

The cryptographic trust, canonical encoding, signed-envelope, key-custody, rotation/revocation, trust-bundle, anti-rollback, fail-closed verification and test-vector requirements are specified in docs/specifications/m0-cryptographic-trust-and-key-lifecycle.md. The external authority response and Phase A authorization require distinct purpose-bound signing identities and domain-separated payloads. The document is a proposal: no algorithm, library, KMS/HSM, root, key or verifier is selected or deployed. Signature validity alone does not prove provider fencing or host safety.

## 10. Cryptographic schema enforcement

Machine-readable signed-envelope, trust-bundle, key-metadata and verification-report proposals plus their structural fixture catalog are maintained under docs/schemas/m0-crypto-*. The validator is scripts/validate_m0_crypto_contract.py. These schemas constrain representation; they do not authenticate signatures, establish provider fencing or authorize execution.


### Key lifecycle and trust-bundle transition contract

The append-only key lifecycle event schema is `docs/schemas/m0-crypto-key-lifecycle-event.schema.json`. It defines explicit generation, pending, activation, deprecation, revocation and destruction transitions. Revocation is terminal for signing and admission; a revoked key may never return to ACTIVE. Historical public-key verification is a separate, policy-bounded audit capability and does not restore signing authority.

Trust-bundle successors must increment generation by exactly one, bind the exact previous bundle digest, and preserve authority, root identity and environment. Revocation statements must identify an exact key ID/version and agree with that key's REVOKED status and revocation metadata. Duplicate key-version identities and duplicate revocation identities are rejected by semantic validation.

The ledger remains an application-side projection. An externally anchored anti-rollback checkpoint is required to detect Neon restore to an earlier event/revocation generation. A schema-valid event or bundle does not authenticate its signature or establish custody.


### External witness and evidence receipt schemas

The external anti-rollback checkpoint and immutable evidence-object receipt are machine-readable proposals at `docs/schemas/m0-ledger-anti-rollback-checkpoint.schema.json` and `docs/schemas/m0-immutable-evidence-object-receipt.schema.json`. Their synthetic structural and semantic checks run through `scripts/validate_m0_witness_evidence_contract.py`. Exact witness-anchor equality is required after restore; exact object-version and content-digest readback plus retention-horizon and principal-separation checks are required before evidence acceptance. These checks do not integrate with or prove Neon, an external witness, R2, object lock or signatures.


## 11. Authorization transaction enforcement and deterministic race model

The database enforcement proposal is maintained in `docs/specifications/m0-authorization-transaction-enforcement-proposal.md`. It corrects the run-claim model by separating immutable claim identity from append-only run outcome events, defines a global lock order, and specifies atomic budget reservation and revocation procedures.

The pure-Python reference model `scripts/validate_m0_authorization_transaction_contract.py` exercises before-commit rollback, after-commit lost acknowledgement, idempotent retries, digest conflicts, final-slot contention, both claim/revocation serial orderings, post-revocation resume denial, run-event terminality, event-chain tampering and stale revocation freshness. It is synthetic only and does not replace real PostgreSQL multi-session fault injection.
