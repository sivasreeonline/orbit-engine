# FENCE-001 monitor replay witness bridge contract

**Status:** Integration contract only. No service binding, deployed gateway, provider, credential, or production rollback protection is implemented by this document.

## 1. Scope and dependency

This contract is the next layer after the provider-neutral replay snapshot checkpoint in PR #182. It defines the boundary required before `GossipReplayStateDO` can rely on an independent witness.

**Correction to the original contract:** repository inspection established that no cryptographic witness receipt verifier or witness-key authorization profile currently exists. The existing `sky-high-fence-manifest-trust-bundle-v1` authorizes COLLECTOR and INDEPENDENT_VERIFIER manifest keys only; it is not a witness receipt trust profile. The provider adapter's opaque non-empty `consistency_token` is not a cryptographic proof.

The bridge MUST implement and use the purpose-specific profile in `m0-fence-001-cryptographic-witness-receipt-profile.md`. That profile uses the existing out-of-band FENCE-001 governance-root pinning process with a distinct domain-separated witness-keyset authorization document. It does not silently broaden manifest key roles or introduce a self-authorized trust root. The bridge must not create a second checkpoint format or an alternate receipt verifier.

The Cloudflare Worker and witness gateway are separate failure domains. A service binding is transport and routing, not by itself proof of independent administration, durable storage, linearizable reads, or production qualification.

## 2. Components and trust boundaries

1. **GossipReplayStateDO** owns the local replay state machine and serializes decisions for one sender/recipient/scope relationship.
2. **Cloudflare API Worker** owns the configured private service binding to the witness gateway. The binding must not be exposed as a public route.
3. **Witness gateway** authenticates the calling workload, validates request scope and canonical payload, and invokes the provider-neutral witness coordinator.
4. **Witness adapter** supplies atomic compare-and-append, immutable operation lookup, strongly consistent latest read, and exact idempotency. The adapter's provider-specific claims remain unqualified until WIT-001..WIT-014 evidence is independently reviewed.
5. **Receipt/proof verifier** implements the exact `sky-high-fence-witness-receipt-v1` profile, including purpose-bound witness key authorization, Ed25519 receipt and tree-head signatures, RFC 9162 inclusion/consistency proofs, key lifecycle/revocation, and retained/gossiped tree-head state. The existing manifest trust-bundle verifier is not a substitute.

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

Responses contain the exact checkpoint, signed receipt envelope, signed tree head, inclusion and consistency proofs, witness scope, generation, predecessor digest, operation ID, checkpoint digest, signer key IDs and proof material required by the profile. The DO or shared verifier must validate these fields against the last accepted purpose-bound witness keyset and pinned tree head before treating the result as verified.

The bridge must not accept a caller-supplied trust root, verification key, witness head, generation, predecessor, or trust-bundle freshness decision.

## 4. Durable Object state machine

An external network call must never run inside a Durable Object storage transaction. Use a durable intent / external append / durable completion protocol:

1. In a short storage transaction, validate the incoming message and persist a **pending checkpoint intent** containing the exact next replay snapshot, snapshot digest, deterministic operation ID, base state version, and a state that prevents a competing transition from being reported accepted.
2. Outside the transaction, call the private gateway with the exact persisted intent. Every retry uses the same operation ID and identical canonical bytes.
3. On a response, verify the receipt, tree head, inclusion proof, consistency proof and current witness head. A response with a malformed signature, wrong scope, wrong digest, wrong predecessor, stale head, missing proof, unverifiable trust state or unproven tree transition is not success.
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
- Witness unavailable, receipt/proof unverifiable, stale keyset, missing proof, tree-head regression, or ambiguous latest read: `BLOCKED`.
- Conflicting signed tree heads for the same log and tree size: `QUARANTINE` and emit an independently monitored equivocation alert.

Recovery must not rewrite either history or silently choose a fork. Any repair requires separately authenticated replay evidence and independent approval.

## 7. Concurrency and idempotency requirements

The DO's storage transaction serializes intent creation for one object identity. The witness compare-and-append serializes checkpoint succession across independent callers. Both are required.

The gateway must reject idempotency-key reuse with changed scope, phase, predecessor, digest, or canonical bytes. The DO must treat a compare-and-append conflict as a reason to re-read and reconcile, never as permission to automatically rebase.

A stale competing successor, concurrent duplicate delivery, two different messages at the same sender sequence, and two concurrent recovery attempts must each have deterministic outcomes. At most one successor may become the accepted local/witness state.

## 8. Required test matrix

All tests in this slice use synthetic keys, synthetic messages and local test services only.

- Exact request/response schema and strict canonical JSON validation.
- Caller identity, audience, scope and service-binding route rejection.
- Tampered receipt, wrong key, revoked key, stale keyset and unknown root rejection.
- Wrong operation ID, digest, predecessor, generation and witness scope rejection.
- Invalid Ed25519 signatures and domain-separation substitution.
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

Production rollback protection remains **NOT QUALIFIED** until the receipt/proof verifier, authenticated bridge, failure-injection suite, independent monitor gossip, and WIT-001..WIT-014 provider evidence are independently reviewed and approved.
