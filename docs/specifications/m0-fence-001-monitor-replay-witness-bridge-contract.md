# FENCE-001 monitor replay witness bridge contract

**Status:** Integration contract only. No service binding, deployed gateway, provider, credential, or production rollback protection is implemented by this document.

## 1. Scope and dependency

This contract is the next layer after the provider-neutral replay snapshot checkpoint in PR #182. It defines the boundary required before `GossipReplayStateDO` can rely on an independent witness.

**Repository alignment:** the existing `sky-high-fence-witness-v1` profile, schema, synthetic signed vectors and validator already provide root-signed witness trust bundles, Ed25519 receipt signatures, receipt/checkpoint binding and key lifecycle checks. The existing `sky-high-fence-witness-merkle-v1` model already provides RFC 9162 inclusion and consistency proof algorithms and vectors. The bridge MUST reuse these exact contracts and implementations.

The remaining cryptographic integration gap is signed transparency tree-head authentication and composition of the existing receipt verifier with the existing Merkle proof verifier. The provider adapter's `consistencyToken` remains opaque metadata and MUST NOT be treated as a cryptographic proof.

The Cloudflare Worker and witness gateway are separate failure domains. A service binding is transport and routing, not by itself proof of independent administration, durable storage, linearizable reads, or production qualification.

## 2. Components and trust boundaries

1. **GossipReplayStateDO** owns the local replay state machine and serializes decisions for one sender/recipient/scope relationship.
2. **Cloudflare API Worker** owns the configured private service binding to the witness gateway. The binding must not be exposed as a public route.
3. **Witness gateway** authenticates the calling workload, validates request scope and canonical payload, and invokes the provider-neutral witness coordinator.
4. **Witness adapter** supplies atomic compare-and-append, immutable operation lookup, strongly consistent latest read, and exact idempotency. The adapter's provider-specific claims remain unqualified until WIT-001..WIT-014 evidence is independently reviewed.
5. **Receipt/proof verifier** reuses `docs/schemas/m0-fence-witness-v1.schema.json`, `scripts/validate_m0_fence_witness_profile.py`, and `scripts/validate_m0_fence_witness_merkle_proofs.py`. It additionally verifies a signed tree-head envelope using a key authorized by the root-signed witness trust bundle.

No component may treat a successful HTTP response, adapter metadata receipt, or non-empty opaque consistency token alone as proof of an independently durable checkpoint.

## 3. Internal service contract

The gateway exposes only a private Worker-to-Worker operation through a configured service binding. It has no public ingress route.

Every request is versioned and binds:
- protocol version and operation type;
- authenticated caller workload identity and intended audience;
- trust-domain, witness, authority, host, sender and recipient scope;
- deterministic operation ID and idempotency key;
- exact canonical snapshot bytes or their strictly defined transport encoding;
- SHA-256 digest, byte count and checkpoint phase;
- expected predecessor generation and digest, obtained from the witness coordinator rather than trusted from an unauthenticated caller.

The gateway independently recomputes the canonical snapshot digest and validates the complete schema before append. It rejects duplicate JSON members, invalid UTF-8, non-finite numbers, unknown fields where the version is closed, oversized payloads, scope substitution, and operation-ID/content mismatch.

Responses contain the exact checkpoint, existing signed receipt envelope, signed tree head, inclusion and consistency proofs, witness scope, generation, predecessor digest, operation ID, checkpoint digest and signer key IDs. The DO or shared verifier must validate these fields against the last accepted root-signed witness trust bundle and pinned tree head before treating the result as verified.

The bridge must not accept a caller-supplied trust root, verification key, witness head, generation, predecessor, or trust-bundle freshness decision.

## 4. Durable Object state machine

An external network call must never run inside a Durable Object storage transaction. Use a durable intent / external append / durable completion protocol:

1. In a short storage transaction, validate the incoming message and persist a **pending checkpoint intent** containing the exact next replay snapshot, snapshot digest, deterministic operation ID, base state version, and a state that prevents a competing transition from being reported accepted.
2. Outside the transaction, call the private gateway with the exact persisted intent. Every retry uses the same operation ID and identical canonical bytes.
3. On a response, verify the existing receipt signature and key authorization, signed tree head, inclusion proof, consistency proof and current witness head. A response with a malformed signature, wrong scope, wrong digest, wrong predecessor, stale head, missing proof, unverifiable trust state or unproven tree transition is not success.
4. In a second storage transaction, confirm the pending intent is unchanged and the local base version still matches. Persist the replay snapshot and verified witness receipt/tree-head reference together, then clear the pending intent.
5. Only after step 4 may the caller receive an outcome that means **witness-checkpointed acceptance**.

While an intent is pending, conflicting new messages for that replay relationship must be blocked or queued without mutating the accepted snapshot. Exact retries of the same message/intent may resume the same operation. They must not mint a new operation ID.

The state machine must distinguish at least:
- `CHECKPOINTED_ACCEPTED`: local state and exact verified witness receipt/proof are committed;
- `PENDING_WITNESS`: durable intent exists but no verified final acknowledgement is available;
- `BLOCKED_WITNESS_UNAVAILABLE`: retry/recovery cannot currently establish the outcome;
- `QUARANTINE`: local/witness state, receipt, scope, proof, or history conflicts.

Do not return the existing `ACCEPTED` or `ACCEPTED_WITH_GAP` result before the independent checkpoint has been verified and locally finalized. If compatibility requires retaining those names, their semantics must explicitly mean checkpointed acceptance.

## 5. Ambiguous acknowledgement and crash recovery

A timeout after sending an append is ambiguous. The DO must:
- retain the pending intent;
- query/retry using the same deterministic operation ID and exact bytes;
- require immutable operation lookup and strongly consistent latest-head readback;
- accept recovery only if the operation record, signed receipt, inclusion/consistency proofs and current head all match the exact intent and previously pinned tree head;
- quarantine if the operation exists with different content or the witness head has advanced incompatibly;
- remain blocked if the gateway/witness cannot establish the result.

Crash points to test: before intent commit; after intent commit but before request; after witness commit but before response; after response but before local finalize; during local finalize; after finalize but before response to caller.

A lost acknowledgement must never create a second checkpoint generation for the same snapshot. A newer snapshot must not overtake an unresolved prior intent.

## 6. Restore and rollback reconciliation

On object activation/recovery, admission for the replay relationship remains blocked until reconciliation completes.

- Empty local state + no witness checkpoint: `NO_CHECKPOINT_EMPTY_STATE`, subject to the explicitly configured genesis policy.
- Exact local snapshot and exact current witness head: `MATCH`.
- Local snapshot older than or different from the witness head: `QUARANTINE`.
- Local snapshot ahead of the witness: `QUARANTINE`; never auto-append it merely to make the histories agree.
- Pending intent: recover the exact operation first; do not process a successor.
- Witness unavailable, receipt/proof unverifiable, stale trust bundle, missing proof, tree-head regression, or ambiguous latest read: `BLOCKED`.
- Conflicting signed tree heads for the same log and tree size: `QUARANTINE` and emit an independently monitored equivocation alert.

Recovery must not rewrite either history or silently choose a fork. Any repair requires separately authenticated replay evidence and independent approval.

## 7. Concurrency and idempotency requirements

The DO's storage transaction serializes intent creation for one object identity. The witness compare-and-append serializes checkpoint succession across independent callers. Both are required.

The gateway must reject idempotency-key reuse with changed scope, phase, predecessor, digest, or canonical bytes. The DO must treat a compare-and-append conflict as a reason to re-read and reconcile, never as permission to automatically rebase.

A stale competing successor, concurrent duplicate delivery, two different messages at the same sender sequence, and two concurrent recovery attempts must each have deterministic outcomes. At most one successor may become the accepted local/witness state.

## 8. Required test matrix

All tests in this slice use synthetic keys, synthetic messages and local test services only.

- Existing witness-v1 receipt, trust-bundle and Merkle vectors remain unchanged and pass.
- Signed tree-head schema, signature domain, authorized log-key purpose, validity and revocation checks.
- Receipt-purpose key cannot sign a tree head; log-purpose key cannot sign a receipt.
- Invalid Merkle leaf, inclusion proof, consistency proof, tree-size regression and same-size conflicting roots.
- Timeout before commit and lost acknowledgement after commit.
- Immutable operation lookup with exact retry and changed-content retry.
- Witness latest read unavailable, stale, malformed or advanced by a competitor.
- Crash injection at every boundary in section 5.
- Concurrent conflicting messages and competing checkpoint successors.
- Restore to older snapshot, local-ahead state, witness-ahead state and pending-intent recovery.
- Public HTTP surface remains closed; no gateway endpoint is reachable through public Worker routing.
- Independent monitor tree-head gossip detects a split view.

The tests must clearly distinguish in-memory fixtures, local service-binding simulation, DynamoDB Local, and any future real-provider qualification. None of the first three establishes production independence or provider durability.

## 9. Explicit non-goals and gates

This contract does not:
- select or qualify AWS or another provider;
- claim DynamoDB Local is production durability evidence;
- create or use production credentials, roots or signing keys;
- enable host admission, supervisor startup, guest execution or student-code execution;
- claim that Cloudflare and the witness are independent merely because they are separate services.

Production rollback protection remains **NOT QUALIFIED** until signed tree-head verification is integrated with the existing receipt and Merkle validators, the authenticated bridge and failure-injection suite pass, independent monitor gossip is validated, and WIT-001..WIT-014 provider evidence is independently reviewed and approved.


## 10. Provider adapter output gap and integration boundary

The current TypeScript `WitnessProviderAdapter` contract returns a storage receipt containing scope, generation, operation ID, checkpoint digest, predecessor digest and an opaque `consistencyToken`. That is sufficient for provider-neutral compare-and-append orchestration, but it is **not** the evidence response required by this bridge. The token is explicitly non-cryptographic and must never be promoted into a signed receipt, tree-head digest, inclusion proof or consistency proof.

The current gateway checkpoint RPC therefore remains fail-closed with `provider_unavailable` after authenticating and validating the exact request. This is intentional until the following two responsibilities are connected without collapsing their trust boundaries:

1. **Storage adapter:** atomic compare-and-append, immutable generation and operation lookup, durable idempotency, strongly consistent latest read, and exact canonical checkpoint-byte readback.
2. **Independent witness evidence authority:** an independently administered signing/logging service that returns the signed receipt envelope, signed tree-head envelope, leaf index, inclusion proof and consistency proof for the exact committed checkpoint. Its receipt and log-signing keys must be authorized by the pinned root-signed trust bundle and must not be silently generated or held by the API Worker.

A future gateway adapter composition may expose a result shaped conceptually as:

- exact stored checkpoint bytes and scope;
- signed receipt envelope whose body binds scope, generation, operation ID, checkpoint digest and predecessor digest;
- signed tree-head envelope with witness, authority, host, log ID, tree size, root hash, timestamp and authorized log key ID;
- leaf index and RFC 9162 inclusion proof for the checkpoint leaf;
- consistency proof from the previously pinned tree size/root to the returned tree head;
- provider request/transaction identifiers and readback provenance as audit metadata, never as cryptographic substitutes.

The gateway must then verify the complete evidence bundle against the currently pinned trust bundle and tree head before constructing the canonical evidence-verification request for the API caller. The API must independently invoke the existing private `verifyEvidence` RPC and bind the verified operation, checkpoint digest, authority-state digest, predecessor, generation and tree-head data to its persisted pending intent before finalization.

### Required integration tests

- Exact provider readback bytes equal the pending canonical snapshot bytes and digest.
- Receipt signature and receipt-purpose key authorization are valid; wrong-purpose, revoked, expired and unknown keys fail closed.
- Tree-head signature and log-purpose key authorization are valid; receipt-purpose keys cannot sign tree heads.
- Inclusion proof binds the exact canonical receipt leaf at the returned leaf index.
- Consistency proof extends the previously pinned tree head; same-size conflicting roots, regression and invalid extensions quarantine or block.
- Provider commit followed by lost acknowledgement recovers the same immutable operation and exact evidence bundle without creating another generation.
- Operation record exists but latest head is incompatible: no automatic rebase or local finalization.
- Evidence authority unavailable after storage commit: pending intent remains and exact operation/evidence recovery is retried.
- The storage adapter's opaque consistency token is never consumed by cryptographic verification code.

No production adapter or evidence authority is selected by this specification. A DynamoDB Local run validates only local SDK/conditional-write wiring; the existing Python AWS adapter is a qualification harness implementation, not a Cloudflare Worker RPC binding or independent evidence authority. Real-provider and independent-key qualification remain separate gates.


## 11. Checkpoint profile mapping — blocking architecture decision

The replay snapshot digest and the signed witness checkpoint-body digest are separate values. The current provider-neutral coordinator treats them as the same value, while the existing `sky-high-fence-witness-v1` checkpoint body is an authority lifecycle record with fields (`responseDigest`, `epoch`, `recordVersion`, and lifecycle `phase`) that have no approved monitor-replay mapping.

Do not map sender sequence to authority epoch, local Durable Object state version to authority record version, or gossip message digest to authority response digest without a separately approved semantic contract. The API's current `authorityStateDigest === pending.snapshotDigest` check is specific to the existing authority-state profile and is not a generic replay checkpoint mapping.

[ADR-021](../decisions/ADR-021-monitor-replay-checkpoint-profile.md) proposes a dedicated `sky-high-fence-monitor-replay-v1` checkpoint-body profile while reusing the existing witness receipt envelope, trust-bundle key lifecycle, signed tree-head format and RFC 9162 proof algorithms.

ADR-021's initial schema and TypeScript receipt-verification slice is now implemented in PR #201. Provider integration remains blocked until architecture/security review is complete and the remaining dual-digest adapter/coordinator, evidence-authority and API-finalization changes are implemented. The future adapter/coordinator must persist and read back both exact canonical byte sequences and keep these digests distinct:

1. `snapshotDigest`: SHA-256 of exact canonical replay snapshot bytes; used in deterministic operation identity.
2. `checkpointDigest`: SHA-256 of exact canonical monitor-replay checkpoint-body JCS bytes; signed by the witness receipt.
3. `receiptLeafHash`: RFC 9162 leaf hash of the complete canonical signed receipt envelope.
4. `treeHeadDigest`: canonical identity of the signed tree-head envelope.

The current coordinator's `checkpointDigest = snapshotDigest` assumption must not be carried into the monitor-replay receipt bridge. No live provider append should be enabled before the separate profile, types, verifier, vectors and lifecycle binding exist.


## 12. Dual-digest coordinator and local finalization progress

PR #201 now stores exact canonical replay snapshot bytes and exact canonical monitor-replay checkpoint-body bytes as separate immutable values. The coordinator derives the deterministic operation ID from scope, persisted predecessor and snapshot digest; computes the checkpoint digest from the checkpoint-body JCS bytes; and requires both digests and both byte sequences to match on operation lookup, ambiguous-ack recovery and latest-head readback.

The API finalization evidence field is now `snapshotDigest`, not the authority-specific `authorityStateDigest`. The signed receipt's `checkpointDigest` remains independently bound to the canonical checkpoint body and is persisted as the witness-head digest.

This is provider-neutral orchestration plus synthetic/in-memory tests. A concrete provider adapter and independent evidence authority are still absent. No live append is enabled.


## 13. Message-bound durable checkpoint request

The durable API request now persists the triggering sender ID, recipient ID, canonical message digest and base replay-state version in addition to the exact snapshot bytes/digest, scope, predecessor and operation ID. The private gateway validates the closed canonical request, recomputes operation identity and snapshot digest, checks the sender/recipient against the decoded snapshot, and requires the message digest to occur in the retained message-history map before constructing the dedicated replay checkpoint body.

The final signed checkpoint body therefore binds both the resulting replay snapshot and the exact triggering message identity. This closes the gap where a snapshot could be paired with an unrelated triggering message.

The gateway still fails closed with `provider_unavailable` after validation. No concrete storage provider or evidence authority is configured.
