# FENCE-001 trust-state rollback and recovery qualification

**Status: Proposed — design and qualification contract only.** This document does not authorize a production trust-store implementation, external writes, key provisioning, or deployment.

## 1. Current implementation boundary

The gateway currently persists two monotonic records per `(trustDomainId, witnessId)` in `WitnessTrustStateDO`:

- the latest accepted root-verified trust-bundle generation and digest;
- the latest accepted signed transparency tree head, including the trust-bundle envelope under which that head was verified.

The Durable Object serializes compare-and-set transitions. The gateway verifies the cryptographic envelopes and proofs before asking it to advance state. A tree head cannot be advanced without a stored trust bundle; a stale expected digest is rejected; a tree-size regression or same-size different head is rejected.

This is useful durable local state, but it is **not an independent anti-rollback anchor**. A Durable Object restore, account-level rollback, or coordinated restoration of the gateway's durable state can restore an older valid snapshot. The restored state has no inherent way to know that it is stale. Therefore this mechanism alone cannot establish production rollback protection.

## 2. Trust-bundle root rotation

Root keys are pinned out of band in gateway configuration. A trust bundle cannot introduce its own trust anchor, and the gateway must never learn a new root solely from an authority response.

A planned root rotation MUST follow an overlap sequence:

1. Independently approve and distribute a pin set containing both the currently trusted root and the successor root.
2. Verify the next trust-bundle generation against the exact prior generation/digest, with its signature made by the approved successor root.
3. Persist that new bundle using the trust-state compare-and-set.
4. Advance and persist a tree head verified under the new bundle. The stored tree-head record must capture the exact bundle envelope used for its verification.
5. Confirm the persisted snapshot references the successor-root bundle and a tree head verified under it.
6. Only then may operators remove the old root pin, subject to a separate recovery/retention policy.

If the trust-bundle CAS succeeds but tree-head advancement fails, the system is in a valid partial-progress state: the new bundle may be current while the previously accepted tree head still references the old bundle. Recovery MUST retain both root pins and retry verification/advancement. Removing the old pin in this interval makes the stored prior head unverifiable and MUST fail closed; it must not trigger trust reset.

Emergency response to a compromised root is different from ordinary rotation. A compromised root cannot be trusted to authorize its own replacement. The successor pin must be distributed through an independently authenticated governance channel, with explicit incident approval and a recorded trust-state reset/recovery decision. The gateway must not silently reset generation or predecessor digest.

## 3. Signing-key retirement and revocation

Receipt-signing and log-signing keys are separate purposes. A key is usable only for its declared purpose, witness and authority scope, validity interval, and revocation/retirement status.

- A retired key may validate historical evidence only under an explicitly defined historical verification policy; it must not sign a new tree head or receipt after its retirement boundary.
- A revoked key must not be accepted for new evidence. A revocation is monotonic: later bundles must not remove a previously published revocation or re-authorize the same key identifier.
- Key rotation adds a new key identifier and purpose-scoped public key; it does not mutate the public key behind an existing identifier.
- Root-pin removal and signing-key revocation are separate controls. Revoking a receipt/log key does not rotate the governance root, and rotating a governance root does not by itself revoke every signing key in the bundle.

The current verifier checks the supplied bundle's revocation list and key validity when verifying evidence. Production qualification must additionally prove that bundle transitions cannot erase historical revocations and that historical evidence policy is explicit.

## 4. Independent anti-rollback anchor

Before production claims, the accepted high-water mark MUST be mirrored to a control plane that is outside both the witness authority's restore domain and the gateway Durable Object restore domain.

The anchor record is scoped by trust domain and witness and contains at least:

- trust-bundle generation and digest;
- tree-head log ID, tree size, root hash, and canonical envelope digest;
- a monotonically increasing anchor sequence;
- the prior anchor-record digest;
- an authenticated writer identity and trusted observation time.

The anchor must provide authenticated compare-and-set semantics. It must reject lower sequence numbers, lower trust-bundle generations, lower tree sizes, same-size conflicting roots, changed log identity, and predecessor substitution. It must not accept a caller-provided expected value without checking the currently stored anchor.

The anchor is not another copy of the authority's database. It must have independent administration, credentials, backup/restore controls, and a documented failure domain. A read-only mirror or asynchronous best-effort log is insufficient if it can lag silently and authorize stale replay state.

No concrete external anchor provider is selected by this proposal.

## 5. Recovery decision table

Recovery compares three independently obtained views where available: local gateway trust state, the external anti-rollback anchor, and a freshly authenticated witness/monitor view.

| Condition | Required action |
|---|---|
| Local and anchor exactly agree; witness proves a valid extension | Continue and CAS the new high-water mark |
| Anchor is ahead of local state | Treat local state as stale; verify a consistency path from the anchor head, then repair local state forward only |
| Local state is ahead of anchor | Quarantine; do not publish or advance the anchor automatically. Require authenticated investigation of the missing anchor transition |
| Same tree size, different root hash | Detect fork/split view; quarantine the scope and require independent monitor evidence |
| Witness head is behind the anchor | Reject as rollback; retain the anchor and request consistency proof from the anchor head |
| Witness head is ahead and proves extension from anchor | Verify with independent monitor agreement, then advance anchor using CAS |
| Witness head is ahead without a valid consistency proof | Quarantine; no reset and no acceptance |
| Authority or anchor unavailable | Fail closed for operations requiring a new checkpoint; preserve pending intent and accepted local state |
| Trust bundle generation/digest regresses or conflicts | Reject; never initialize a fresh trust state as a fallback |
| Root pin set changes unexpectedly | Fail closed pending independently approved root-rotation procedure |

A local-ahead condition is deliberately not “fixed” by lowering local state or blindly advancing the anchor. It may indicate a lost anchor acknowledgement, a split view, an operator restore, or tampering; those cases require evidence.

## 6. Split-view and independent monitor agreement

A valid signature and a valid consistency proof establish that one presented tree head extends one prior head. They do not prove that every monitor received the same head.

Production qualification requires independent monitors in separate administrative and failure domains to:

1. fetch and verify signed tree heads independently;
2. exchange signed observations bound to log ID, tree size, root hash and observation time;
3. compare observations and report same-size root conflicts or incompatible histories;
4. retain observations outside the authority and gateway restore domains;
5. require a defined quorum or operator policy before a new head becomes eligible for anchor advancement.

A single authority response must never be treated as proof that no split view exists.

## 7. Required test model before implementation

Add a deterministic recovery model with injected snapshots for local state, anchor state, and witness state. At minimum, tests must cover:

- normal generation and tree-size advancement;
- two concurrent writers racing the same anchor predecessor;
- trust-bundle CAS succeeds but tree-head CAS fails, followed by restart recovery;
- root overlap, successor-root activation, and premature old-root removal;
- revoked and retired receipt/log keys;
- local state restored to an older valid bundle/head;
- anchor restored or unavailable (must be detected as a governance failure, not silently trusted);
- local-ahead and anchor-ahead reconciliation;
- witness rollback, same-size fork, and invalid consistency proof;
- two independent monitors reporting conflicting signed heads;
- duplicate/replayed anchor sequence and predecessor substitution.

Tests must distinguish cryptographic validity from freshness and from independent-view agreement. A green synthetic test suite is not production provider qualification.

## 8. Release gates

Production rollback protection remains **NOT QUALIFIED** until all of the following are independently evidenced:

- external anchor design and implementation reviewed;
- root rotation and emergency root recovery operationally approved;
- durable monotonic revocation semantics demonstrated;
- independent monitor gossip and split-view response exercised;
- restore/backup/partition/concurrency tests pass across separate failure domains;
- trusted time, retention, key custody, IAM and operator access reviewed;
- provider and anchor recovery evidence retained and independently audited.

Until then, the existing Durable Object trust state is a local monotonic guard only. Missing, corrupt, unavailable, or inconsistent trust state must fail closed; it must never be reset to generation zero as an automatic recovery path.


## 9. Deterministic recovery model implementation — 2026-11-25

Added `apps/witness-gateway/src/trust-recovery-model.ts` as a pure decision model and `trust-recovery-model.test.ts` as its unit suite.

The model classifies independently supplied local, external-anchor, witness and monitor observations. It covers:

- exact agreement and normal continuation;
- local snapshot repair to a newer anchor, including stale anchor-sequence metadata and a root-signed trust-bundle generation chain;
- anchor advancement only when both the tree-head consistency proof and any newer trust-bundle chain have been independently verified by the caller;
- local-ahead, witness rollback, same-size fork, monitor disagreement, insufficient monitor quorum, unavailable anchor/witness, and unproven transitions as quarantine outcomes;
- root-rotation overlap, successor bundle acceptance, successor tree-head acceptance, old-root removal, and emergency approval.

**Boundary:** this is a deterministic reference/decision model, not a connected anchor client or production recovery controller. It does not verify signatures, Merkle proofs, bundle signatures, monitor identities, or anchor compare-and-set itself. Those proofs must be verified by the calling layer before the corresponding boolean evidence is supplied. No external anchor provider is selected, no runtime recovery path invokes this model yet, and production rollback protection remains **NOT QUALIFIED**.

## 10. Deterministic anchor compare-and-set model — 2026-11-25

Added `apps/witness-gateway/src/anchor-cas-model.ts` and its unit tests. The pure model specifies a candidate external-anchor record with a monotonically increasing sequence, predecessor record digest, unique operation ID, canonical request digest, record digest, and trust checkpoint.

The decision contract covers:

- first-write creation against an explicit empty predecessor;
- exact idempotent retry after a lost acknowledgement (`ALREADY_APPLIED`);
- rejection when an operation ID is reused with different request/record bytes;
- compare-and-set against both the expected sequence and expected record digest, so two writers racing the same predecessor cannot both win;
- exact sequence increment and predecessor-digest linkage;
- immutable log identity, non-regressing trust-bundle generation and tree size, and same-size root conflict rejection;
- mandatory caller-verified trust-bundle chain evidence for generation advances and Merkle consistency evidence for tree-size advances.

**Boundary:** the model does not calculate or authenticate record digests, authenticate writer identity, provide trusted time, persist data, implement a transaction, or contact an independently administered anchor. The boolean proof inputs are trusted assertions from a future verifier boundary, not proof verification. The model therefore demonstrates decision semantics only; it is not an anchor implementation, does not close the external restore-domain problem, and does not change the production qualification status.
