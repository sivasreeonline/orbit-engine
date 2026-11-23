# ADR-021: Dedicated checkpoint profile for monitor replay evidence

**Status:** Proposed; initial schema and TypeScript validation slice implemented in PR #201; architecture/security approval and end-to-end integration remain open  
**Date:** 2026-11-23  
**Scope:** FENCE-001 monitor replay checkpoint bridge  
**Decision owners:** Sky High architecture and security review

## Context

The replay intent and provider-neutral coordinator currently identify a checkpoint using the SHA-256 digest of the canonical replay snapshot. The existing `sky-high-fence-witness-v1` checkpoint-body schema, however, describes authority lifecycle records and requires `phase` values `ISSUED`, `ACCEPTED`, or `REVOKED`, plus `responseDigest`, `epoch`, and `recordVersion`.

Those fields do not have established monitor-replay meanings. Mapping sender sequence to epoch, replay state version to record version, or message digest to response digest would invent semantics and could make a cryptographically valid receipt attest to the wrong event.

The current API finalization path also compares the replay snapshot digest with the existing checkpoint body's `authorityStateDigest`. That is a useful binding in the authority-state profile, but it must not be treated as a universal replay-checkpoint contract.

## Decision

Do not overload `sky-high-fence-witness-v1` authority lifecycle fields for monitor replay. Introduce a dedicated checkpoint-body profile while reusing the existing witness receipt envelope, root-signed trust bundle, key lifecycle, signed tree-head envelope, and RFC 9162 proof algorithms.

Proposed checkpoint body profile: `sky-high-fence-monitor-replay-v1`.

Proposed exact body fields:

| Field | Meaning |
|---|---|
| `profile` | `sky-high-fence-monitor-replay-v1` |
| `schemaVersion` | Integer 1 |
| `trustDomainId` | Exact configured trust domain |
| `witnessId` | Exact configured witness |
| `authorityId` | Exact authority scope |
| `hostId` | Exact enrolled host scope |
| `senderId` | Authenticated monitor sender in the replay relationship |
| `recipientId` | Authenticated monitor recipient in the replay relationship |
| `generation` | Expected predecessor generation plus one |
| `operationId` | Existing deterministic scope + predecessor + snapshot identity |
| `phase` | `MONITOR_GOSSIP_REPLAY_V1` |
| `previousCheckpointDigest` | Exact persisted predecessor digest |
| `snapshotDigest` | SHA-256 of exact canonical replay snapshot bytes |
| `snapshotByteLength` | Exact canonical replay snapshot byte length |
| `baseStateVersion` | Local version from which this pending transition was prepared |
| `messageDigest` | Digest of the already-verified canonical gossip message |

The checkpoint digest is SHA-256 over UTF-8 RFC 8785 JCS bytes of this exact closed-schema body. The body must reject unknown fields, duplicate JSON members, invalid UTF-8, non-canonical bytes, unsafe integers and out-of-scope identifiers.

The existing signed witness receipt envelope remains the attestation over the checkpoint digest. Its existing receipt signature domain, trust-bundle root chain, key purpose checks, validity and revocation rules remain unchanged. The receipt's generation, operation ID, checkpoint digest and predecessor digest must exactly match the monitor replay body. The existing signed tree-head profile and RFC 9162 inclusion/consistency proofs continue to bind the complete canonical signed receipt envelope.

## Digest and storage separation

The following values are distinct and must never be conflated:

1. **snapshotDigest** — SHA-256 of canonical replay snapshot bytes; deterministic operation identity includes this value.
2. **checkpointDigest** — SHA-256 of the dedicated monitor replay checkpoint-body JCS bytes; this is what the witness receipt signs.
3. **receiptLeafHash** — RFC 9162 leaf hash of the complete canonical signed receipt envelope.
4. **treeHeadDigest** — SHA-256 identity of the signed tree-head envelope (or the repository's explicitly defined canonical envelope digest).

The provider record must retain exact canonical snapshot bytes and exact canonical checkpoint-body bytes, plus their digests. The provider's atomic append predecessor is the prior witness checkpoint digest, not the replay snapshot digest. The adapter interface and coordinator must be updated so their current `checkpointDigest = snapshotDigest` assumption is removed for this profile.

The existing opaque `consistencyToken` remains diagnostic provider metadata only.

## Required verifier and lifecycle changes

- Add a strict TypeScript type and closed-schema validator for `MonitorReplayCheckpointBody`.
- Extend the existing receipt verifier through an explicit discriminated union or a separate typed entry point; preserve all current authority-profile vectors unchanged.
- Verify receipt key purpose and trust-bundle scope using the existing witness receipt trust bundle.
- Bind receipt generation, operation ID, checkpoint digest and predecessor digest to the monitor replay body.
- Return an explicitly named `snapshotDigest` and `checkpointDigest` in verified evidence; do not reuse `authorityStateDigest` as a generic alias.
- Finalization must compare the verified snapshot digest to the pending intent's snapshot digest and the verified checkpoint digest to the receipt/checkpoint record. It must not infer one digest from the other.
- Update the provider-neutral adapter and coordinator to store/read back both byte sequences and both digest values.
- The evidence authority must return the exact monitor replay checkpoint body, signed receipt, signed tree head, leaf index, inclusion proof and consistency proof. The gateway verifies all of them before returning canonical evidence to the API Worker.

## Why not reuse the authority lifecycle schema?

The authority profile's `responseDigest`, `epoch`, `recordVersion`, and lifecycle `phase` are domain-specific. A replay message sequence is not inherently an authority epoch; a Durable Object state version is not inherently an authority record version; and a gossip message digest is not inherently an authority response digest. Reusing those fields would create a hidden semantic coupling and make later independent verification ambiguous.

A separate checkpoint-body profile is the smallest change that preserves the established witness receipt and transparency machinery without redefining existing authority records.

## Security and qualification boundaries

This ADR does not select a cloud provider, create signing keys, configure service bindings, authorize external writes, or qualify durability or independence. The proposed profile must receive architecture/security review and fixed synthetic vectors before runtime use. Existing authority-profile and Merkle vectors must remain unchanged and pass.

No production adapter may be enabled until exact checkpoint/snapshot byte readback, signed receipt verification, signed tree-head verification, inclusion/consistency verification, trust-state pinning, lost-ack recovery, restore reconciliation and independent provider qualification are complete.

## Consequences

- Provider/evidence integration is intentionally blocked until the two digest domains are implemented distinctly.
- The existing authority checkpoint profile remains backward compatible.
- Existing provider-neutral coordinator tests must be revised to assert distinct snapshot and checkpoint digests.
- No current code may claim that a replay snapshot digest is itself the signed checkpoint-body digest.


## Implementation impact inventory and sequence

The following existing modules are expected to change when this proposal is approved:

1. `docs/schemas/m0-fence-witness-v1.schema.json` — add the dedicated checkpoint-body schema without changing the authority checkpoint schema or existing receipt/trust-bundle vectors.
2. `apps/api/src/witness/witness-profile-verifier.ts` — add the strict monitor-replay body type/validator and an explicit receipt-verification path for it. Preserve the authority-body verifier as-is.
3. `apps/witness-gateway/src/provider/witness-provider-adapter.ts` — store exact `canonicalSnapshotBytes` and exact `canonicalCheckpointBodyBytes` separately, with distinct `snapshotDigest` and `checkpointDigest`.
4. `apps/witness-gateway/src/provider/monitor-replay-checkpoint-coordinator.ts` — derive operation identity from the persisted scope/predecessor/snapshot digest, but append and read back the checkpoint-body digest and both exact byte sequences. Ensure ambiguous-ack recovery compares both byte sequences.
5. `apps/witness-gateway/src/index.ts` — construct the monitor replay body from the validated persisted intent, request signed evidence for that exact body, and compose receipt, signed tree-head, inclusion and consistency verification.
6. `apps/api/src/witness/witness-gateway-contract.ts` — return explicit `snapshotDigest` and `checkpointDigest` fields; never return a generic digest alias.
7. `apps/api/src/gossip/gossip-replay-checkpoint-lifecycle.ts` — bind verified snapshot digest to the pending intent and checkpoint digest to the receipt/checkpoint record as separate comparisons.
8. API, gateway, provider-adapter and Workers integration tests — cover wrong snapshot digest, wrong checkpoint-body bytes, receipt signing the snapshot digest instead of checkpoint digest, changed sender/recipient/message digest, lost acknowledgement and stale predecessor.

Suggested implementation order is 1–2 (profile and verifier) → 3–4 (provider-neutral data contract) → 5–6 (gateway/evidence response) → 7–8 (local finalization and integration qualification). Do not introduce a concrete cloud provider in the same change set as the profile migration; keep provider qualification independently reviewable.


## Initial implementation slice — 2026-11-23

PR #201 now adds:
- A closed JSON Schema definition for `monitorReplayCheckpointBody` and its `monitorReplayCheckpointArtifact`, while retaining the existing authority checkpoint schema unchanged.
- TypeScript `MonitorReplayCheckpointBody` and strict exact-key/field validation, including distinct trust scope, sender/recipient, snapshot digest, snapshot byte length, base state version, message digest and replay phase.
- Receipt verification support for the dedicated replay body: the receipt continues to use the existing `sky-high-fence-witness-v1` receipt envelope/profile and signing domain, while the checkpoint body is independently identified as `sky-high-fence-monitor-replay-v1`. The verifier checks the exact JCS checkpoint digest and binds receipt generation, operation, predecessor, authority/host scope and trust-domain identity.

Synthetic tests cover strict body shape, rejection of authority-profile field aliases, invalid sender/recipient identity, oversized snapshots, invalid phase, and a real Ed25519 receipt signature over the new checkpoint digest.

**Not yet implemented:** provider adapter dual-byte persistence/readback, coordinator digest separation, independent evidence authority issuance/recovery, signed proof response composition for the replay profile, and API finalization changes. The initial slice does not enable provider writes.


## Dual-digest coordinator and local-finalization progress — 2026-11-23

The initial profile slice has now been extended:

- `WitnessCheckpoint` stores `snapshotDigest` and `checkpointDigest` separately, plus exact canonical snapshot bytes and exact canonical checkpoint-body bytes.
- The provider-neutral coordinator requires a validated replay checkpoint body and persisted predecessor. It verifies scope, generation, predecessor, operation ID, snapshot digest, snapshot byte length, sender/recipient relationship and both exact byte sequences.
- Immutable operation recovery and latest-head readback compare both digests and both byte sequences. Ambiguous-ack recovery retains the same operation identity.
- Coordinator results expose explicit `snapshotDigest` and `checkpointDigest`; the ambiguous generic `digest` result field is removed.
- API evidence contract and replay finalization now bind `snapshotDigest` explicitly, while the signed receipt checkpoint digest remains the witness-head identity.

Exact-head CI run #2677 passed on `244de56ecc0188412c1d7f2b3b3ee56dff50e4f7` (API, private gateway and web jobs).

This remains provider-neutral logic and in-memory test evidence. It does not constitute a configured durable provider, an independent evidence authority, or production qualification.


## Durable request and message binding progress — 2026-11-23

The API's durable replay request now carries the triggering message's sender ID, recipient ID and canonical message digest, together with base state version, snapshot byte length, scope, predecessor and exact snapshot bytes. Pending-intent validation rechecks those fields and the canonical request bytes on restart; the pending transition wrapper rejects a message that differs from the identity persisted in the checkpoint intent.

The private gateway now parses this closed request, validates the caller scope and deterministic operation ID, decodes and re-hashes the exact snapshot bytes, verifies the sender/recipient identity against the snapshot, and requires the triggering message digest to appear in the snapshot's retained message history. It constructs and validates the dedicated monitor replay checkpoint body and computes its distinct checkpoint digest. The deployment still returns `provider_unavailable` after validation because no concrete provider/evidence authority is configured.

Exact-head CI run #2701 passed on `144131dbc691e0670b02b64da585ee9fe2984d91`, including API typecheck/unit tests/Workers runtime integration, private gateway typecheck/tests/dry-run, schema and cryptographic conformance, and the synthetic DynamoDB Local checks.


## Independent evidence-authority contract progress — 2026-11-23

Added `apps/witness-gateway/src/evidence/witness-evidence-authority.ts`, deliberately separate from the storage provider adapter. Its request carries the exact canonical monitor-replay checkpoint bytes and digest. Its response carries the exact checkpoint readback, root-signed trust bundle, signed receipt, signed tree head, leaf index and inclusion/consistency paths.

The contract requires idempotent `issueOrRecoverEvidence` and immutable `readEvidenceByOperation`. Its byte/identity guard checks canonical checkpoint bytes and digest, trust scope, receipt generation/operation/checkpoint/predecessor bindings, signed-head scope and proof metadata. It does **not** verify cryptographic signatures or proofs; the gateway's existing `verifyEvidence` path remains mandatory. Ambiguous issuance acknowledgements recover only by the same immutable operation ID and exact bytes.

Synthetic tests cover exact-byte mismatch, wrong operation identity and lost-ack recovery. The contract is not yet configured as a service binding or integrated into `checkpointReplay`; no provider writes are enabled.
