# ADR-021: Dedicated checkpoint profile for monitor replay evidence

**Status:** Proposed; synthetic end-to-end integration implemented in PR #201; architecture/security approval and production qualification remain open  
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

This ADR does not select a cloud provider, create signing keys, configure service bindings, authorize external writes, or qualify durability or independence. The proposed profile must receive architecture/security review before production runtime use. Fixed synthetic vectors and a workerd multi-Worker integration path now exercise the profile, but synthetic runtime success is not production qualification. Existing authority-profile and Merkle vectors must remain unchanged and pass.

No production adapter may be enabled until exact checkpoint/snapshot byte readback, signed receipt verification, signed tree-head verification, inclusion/consistency verification, trust-state pinning, lost-ack recovery, restore reconciliation and independent provider qualification are complete.

## Consequences

- Production provider/evidence integration remains blocked until the two digest domains are implemented distinctly and the independent production trust, durability and qualification gates below are satisfied.
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


## Gateway composition progress — 2026-11-23

The private gateway now has an explicit composition path behind two optional RPC bindings:
- `WITNESS_PROVIDER` implements the provider-neutral atomic append, immutable operation lookup, strong latest read and exact dual-byte readback contract.
- `WITNESS_EVIDENCE_AUTHORITY` implements independent signed receipt/transparency issuance and immutable evidence lookup.

After authenticated request validation, the gateway reconstructs the monitor replay checkpoint body, invokes the provider-neutral coordinator, compares the coordinator's checkpoint digest with the canonical builder's digest, requests evidence from the independent authority, verifies the authority response's structural identity and exact bytes, and returns the canonical evidence-verification request to the API Worker. The API still performs the cryptographic receipt/trust-bundle/tree-head/Merkle verification RPC before local finalization.

The new `buildMonitorReplayCheckpoint` helper has tests for valid canonical construction, absent triggering-message digest, sender/recipient mismatch and snapshot-digest mismatch. The gateway orchestration is wired to optional env interfaces, but neither binding is configured in `wrangler.jsonc` or deployed. Therefore the current deployed/test environment continues to return `provider_unavailable` before any append. No live writes are enabled.

Exact-head CI run #2728 passed on `af367fad6b6319287f18321946252143824106d6`, including all API, gateway and web jobs.


## AWS DynamoDB dual-digest adapter progress — 2026-11-23

Added `AwsDynamoDBWitnessProviderAdapter` implementing the provider-neutral contract against DynamoDB:
- partitioned by canonical witness scope hash;
- atomically writes immutable generation, operation and idempotency records plus the high-water head in one `TransactWriteItems`;
- stores exact canonical snapshot and checkpoint-body bytes in 32 KiB immutable binary chunks, avoiding DynamoDB's 400 KiB per-item ceiling while remaining under the transaction size/item-count limits;
- performs strongly consistent `GetItem` readback for latest head, immutable operation and every byte chunk;
- verifies both reconstructed byte digests before returning a stored record;
- recovers durable idempotency records after ambiguous transaction acknowledgement and rejects stale predecessor races or idempotency rebinding.

The local-only factory rejects non-loopback endpoints and does not enable live AWS writes. A DynamoDB Local integration test covers dual-byte persistence/readback, idempotent retry, changed-content idempotency conflict, stale predecessor rejection and independent-client concurrency. The API CI job starts the published DynamoDB Local container and runs this TypeScript integration test. The step passed in exact-head CI run #2747 on `1a0d7bd9d8a828705c24fb18b2a30003348673d6`.

**Qualification boundary:** this is synthetic DynamoDB Local evidence only. The adapter is not deployed or bound to the gateway, no live AWS account/table/credentials are configured, and no production durability or independent failure-domain claim is made. Cloudflare workerd transport compatibility and real AWS qualification remain separate gates.


## Fetch transport and live-write guard update — 2026-11-23

The local DynamoDB adapter factory now supplies an AWS SDK v3 request handler backed by the Web Fetch API rather than Node socket handlers. This removes an avoidable Node transport dependency from the intended Workers deployment path. The DynamoDB Local integration test now exercises this Fetch-based transport, including multi-client concurrent transactions; exact-head CI run #2758 passed on `cc30e9ad109fce91adf270f50251001389fec837`.

Additional tests prove that the local factory rejects both a real AWS DynamoDB endpoint and HTTPS loopback endpoints. The factory accepts only HTTP loopback endpoints. This is a hard local-test guard, not a live AWS configuration path.

Cloudflare workerd runtime compatibility remains unqualified until a dedicated workerd-to-DynamoDB-Local integration test is added. The adapter is not deployed, and no live AWS writes are possible through the local-only factory.


## Provider pre-append digest and endpoint hardening — 2026-11-23

The DynamoDB adapter now recomputes both SHA-256 values before opening a transaction and refuses to write if the exact snapshot bytes do not match `snapshotDigest` or the exact checkpoint-body bytes do not match `checkpointDigest`. Tests assert that either mismatch leaves the witness head empty.

The local factory additionally rejects endpoint URLs containing credentials, paths, query strings or fragments, as well as all non-loopback and non-HTTP endpoints. The only accepted form is a plain HTTP loopback endpoint.

Exact-head CI run #2767 passed on `1a953d88ccff6a188bee8a5743ede37508431995`, including the new negative preflight tests and DynamoDB Local integration.


## Workerd Fetch transport smoke test — 2026-11-23

Added `apps/witness-gateway/workers-tests/aws-dynamodb-fetch-handler.test.ts`. It runs under the Cloudflare workerd Vitest runtime, creates a real AWS SDK v3 `DynamoDBClient` configured with the custom Fetch request handler, sends a signed `GetItem` request through Worker `fetch`, and parses a synthetic DynamoDB JSON response. The test verifies the AWS SigV4 authorization header, DynamoDB target header and request body.

This is a workerd transport smoke test with a mocked HTTP response; it does not connect to AWS or DynamoDB Local. Separately, the Node integration suite exercises the same Fetch handler against DynamoDB Local for actual transaction/readback behavior.

Exact-head CI run #2773 passed on `79149fe4ef44d3373edaa08941b3da012ffa3b9c`, including the workerd transport test, gateway runtime tests, DynamoDB Local integration, API tests and web build.

The remaining gap is a single end-to-end workerd test that uses the gateway's optional provider binding against a real local DynamoDB service, plus a concrete separately administered evidence-authority service. No production provider or authority is configured.


## Synthetic positive end-to-end recovery checkpoint — 2026-11-25

PR #201 now exercises the positive recovery path in the local Cloudflare Workers (workerd) runtime across separate API, gateway and synthetic-services Workers:

- The test harness generates an ephemeral caller identity and an independent ephemeral evidence-authority root. The gateway receives the caller public key and pinned authority root public key; the synthetic authority Worker alone receives the authority root private key. The private root is not exposed through an RPC method or returned to the gateway.
- The gateway uses separate RPC service bindings for the synthetic provider and synthetic evidence authority. The API Durable Object stages the exact pending intent before making gateway calls.
- Fault injection first commits a provider operation while losing its acknowledgement, then makes evidence issuance unavailable once, then returns a shape-valid inclusion proof with a corrupted hash. Each failure preserves the exact pending intent and leaves the accepted replay state unchanged.
- A subsequent concurrent recovery attempt obtains the original immutable evidence for the already-committed operation. Independent cryptographic verification succeeds, and the API finalizes the replay snapshot and witness head atomically. Concurrent callers cannot both finalize; a later retry is a no-op.
- Additional lifecycle tests cover durable quarantine, restart alarm cleanup, stale replacement rejection, atomic quarantine clearing on successful staging, and preservation of quarantine when staging validation fails.

Exact-head CI run #2956 passed on `d76bc7bf16bfb00e202483c088ee1112cf179e47` (API, private witness gateway and web jobs).

**Qualification boundary:** this proves the synthetic positive and negative integration path, not production provider or authority independence. The synthetic provider and authority share a test Worker process boundary and in-memory state. The AWS DynamoDB adapter remains local-only and is not bound into this end-to-end workerd path. A separately administered production evidence authority, production provider qualification, durable anti-rollback trust state, restore/partition testing, independent operational failure domains, architecture/security approval and production root governance remain open. No live AWS credentials, production writes or deployments are enabled.
