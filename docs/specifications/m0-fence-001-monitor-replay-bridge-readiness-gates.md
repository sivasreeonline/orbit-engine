# FENCE-001 monitor replay bridge readiness gates

**Decision (updated 2026-11-23):** The local cryptographic verifier and authenticated Worker-to-Worker RPC gates now have implementation slices and exact-head CI evidence (PRs #188–#194, with the TypeScript runtime verifier in this branch). The remaining implementation blockers are the provider-neutral gateway append adapter, durable trust/head pinning, and the monitor replay Durable Object pending-intent/finalize/recovery lifecycle.

This remains a readiness audit, not a claim that monitor replay rollback protection is implemented. PR #185 remains the governing bridge protocol contract. Production rollback protection remains **NOT QUALIFIED**.

## 1. Evidence inspected

The audit was performed against the PR #182 checkpoint branch and its exact current source:

- `docs/schemas/m0-fence-witness-v1.schema.json`
- `scripts/validate_m0_fence_witness_profile.py`
- `docs/test-vectors/fence-witness-v1-001.json`
- `docs/test-vectors/fence-witness-v1-002-unicode.json`
- `docs/test-vectors/fence-witness-v1-003-trust-bundle.json`
- `scripts/validate_m0_fence_witness_merkle_proofs.py`
- `docs/test-vectors/fence-witness-v1-004-merkle-transparency.json`
- `scripts/validate_m0_witness_provider_adapter_conformance.py`
- `scripts/validate_m0_fence_monitor_replay_witness_checkpoint.py`
- `scripts/validate_m0_fence_provider_trust_bundle_checkpoint.py`
- `apps/api/src/gossip/gossip-replay-state-do.ts`
- `apps/api/src/env.ts`
- `apps/api/src/index.ts`
- `apps/api/wrangler.jsonc`

## 2. Gate A — signed transparency-head integration

The existing `sky-high-fence-witness-v1` profile already verifies:
- RFC 8785 canonical checkpoint and receipt bytes;
- SHA-256 checkpoint and trust-bundle digests;
- Ed25519 receipt signatures with the domain prefix `SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\0`;
- root-signed, monotonic witness trust bundles using the pinned governance root and domain prefix `SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\0`;
- receipt-to-checkpoint binding, witness/authority scope, key purpose, validity, retirement and revocation.

The existing `sky-high-fence-witness-merkle-v1` reference model separately verifies RFC 9162 SHA-256 inclusion and consistency proofs, including published vectors, negative cases and exhaustive model checks.

**The missing slice is the authenticated composition:** the repository does not yet verify a signed transparency tree head against a separately authorized log-signing key, then bind the existing signed receipt envelope to inclusion and consistency proofs and the client's pinned prior tree head in one verification path. The existing `consistencyToken` remains opaque adapter metadata and is not a cryptographic proof.

**Required before bridge implementation:**

1. Extend the existing witness key-purpose schema with a distinct `WITNESS_LOG_SIGNING` purpose while preserving `WITNESS_RECEIPT_SIGNING`, the existing root-signed trust-bundle envelope, domain prefixes and vectors.
2. Add a closed signed tree-head envelope bound to witness/authority/host/log ID/tree size/root hash/timestamp and a key authorized for the log-signing purpose.
3. Compose the existing receipt verifier and RFC 9162 proof functions; the Merkle leaf must bind the complete canonical signed receipt envelope.
4. Pin and retain each client's last accepted tree size/root; reject regression and same-size conflicting roots.
5. Integrate signed tree-head gossip with independent monitors so a single log signer cannot silently present split views.
6. Add synthetic positive/negative vectors for tree-head signature, key purpose, inclusion/consistency proof, rollback, fork and split-view detection.

Do not create a parallel receipt envelope, trust root, signature domain, or Merkle implementation. Do not reinterpret `consistencyToken` as proof.

## 3. Gate B — authenticated internal workload identity

The current API Worker environment declares Hyperdrive, CORS, app environment, and the `GOSSIP_REPLAY` Durable Object namespace. Its Wrangler config binds the Durable Object but has no witness service binding. The API entry point uses `UnconfiguredAuthenticator`; that application authenticator is not evidence of an authenticated Worker-to-Worker workload identity.

A Cloudflare service binding can provide private Worker-to-Worker routing, but routing alone does not define the authenticated caller identity or authorize a particular witness scope.

**Required before bridge implementation:**

1. Choose and document the supported Worker service-binding identity mechanism for this deployment.
2. Bind caller identity and audience to the bridge request; do not accept either from untrusted request JSON.
3. Define gateway-side authorization from caller identity to allowed trust-domain/witness/authority/host scopes.
4. Define binding configuration for local Workers tests and deployment environments without adding a public gateway route.
5. Test forged caller identity, wrong audience, unauthorized scope, absent binding, and public-ingress attempts.

No shared static secret, production credential, or caller-controlled identity field should be introduced as a shortcut.

## 4. Durable Object integration boundary

The current `GossipReplayStateDO.acceptVerifiedMessage` validates replay metadata and writes `replay-state-v1` inside a storage transaction. It currently returns `ACCEPTED` / `ACCEPTED_WITH_GAP` after local persistence. Its `fetch()` method returns 404.

The bridge must not add a network call inside that transaction. Once gates A and B exist, implementation must use the durable intent → external witness operation → verified receipt/tree-head/proof check → local finalize protocol from PR #185.

The pending intent must block conflicting successors. An ambiguous acknowledgement must resume the exact operation ID and exact canonical bytes. No accepted result may be returned before verified witness proof and local finalization. On activation, replay admission must remain blocked until pending-intent recovery and local-versus-witness reconciliation complete.

## 5. Sequenced implementation plan

| Order | Work item | Exit condition |
|---|---|---|
| 1 | Signed tree-head profile and verifier integration | Authorized STH signature and receipt inclusion/consistency vectors pass; no opaque-token success path |
| 2 | Worker workload identity and scope authorization | Authenticated service-binding caller and audience verified in local Workers tests |
| 3 | Private witness gateway adapter | Strict schema, canonical payload, exact idempotency and verified latest-head response |
| 4 | Durable Object pending-intent lifecycle | Crash/retry/concurrency tests pass; no network in storage transaction |
| 5 | Restore and rollback reconciliation | Witness-ahead, local-ahead, fork, stale proof and unavailable witness fail closed |
| 6 | Provider qualification | Independent evidence supports actual provider durability and failure-domain claims |

## 6. Explicit non-goals

This audit does not add a gateway, service binding, provider adapter, signed tree-head verifier, credentials, signing keys, production writes, host execution, or student-code execution. DynamoDB Local and in-memory fixtures remain test environments only.

**Current status:** Bridge implementation is blocked on gates A and B. This is an intentional security stop, not a claim of completed integration.


## 7. Implementation progress — 2026-11-23

- **Gate A — cryptographic profile:** PR #188 defines the signed tree-head profile; PR #189 adds the Python conformance composition; this branch adds a Cloudflare Worker-compatible TypeScript verifier that reuses the existing RFC 8785, receipt, trust-bundle, Ed25519 and RFC 9162 formats. Persistent trust-bundle and prior-head state are still required before production use.
- **Gate B — workload identity:** PRs #190–#191 implement signed workload identity and durable nonce replay. PR #192 adds the private gateway Worker; PR #193 adds the API caller proof signer; PR #194 verifies the real API-to-gateway named RPC boundary in local workerd. PR #194 exact-head CI run #2384 passed.
- **Gate C — local evidence verification:** PR #197 adds the private `verifyEvidence` RPC, pinned root/scope configuration, durable trust-bundle generation state, historical trust context for accepted tree heads, receipt verification, inclusion proof and prior-head consistency verification. Local workerd integration tests cover the full API-to-gateway path.
- **Gate D — provider-neutral append/readback coordinator:** this branch adds a TypeScript adapter contract and coordinator for RFC 8785 snapshot bytes, deterministic operation IDs, exact idempotency, ambiguous-ack recovery, immutable operation lookup and latest-head readback. Its in-memory unit tests are logic evidence only; no external provider is wired or qualified.
- **Next:** implement the durable pending-intent/finalize/recovery lifecycle around `GossipReplayStateDO`, keeping provider calls outside storage transactions and reconciling restore state against the verified witness head. Only then wire a concrete provider adapter behind the contract.
- **Still prohibited:** no live provider writes, production keys, public gateway ingress, or host/student-code execution. No rollback protection or independent provider durability claim is authorized by these local tests.
