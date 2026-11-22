# FENCE-001 monitor replay bridge readiness gates

**Decision:** Do not implement or expose the Cloudflare-to-witness bridge yet. The repository currently lacks two security-critical contracts needed to implement it without inventing trust semantics: a cryptographically verifiable witness receipt profile and an authenticated Worker workload-identity mechanism.

This is a readiness audit, not a claim that monitor replay rollback protection is implemented. PR #185 remains the governing bridge protocol contract. Production rollback protection remains **NOT QUALIFIED**.

## 1. Evidence inspected

The audit was performed against the PR #182 checkpoint branch and its exact current source:

- `scripts/validate_m0_witness_provider_adapter_conformance.py`
- `scripts/validate_m0_fence_monitor_replay_witness_checkpoint.py`
- `scripts/validate_m0_fence_provider_trust_bundle_checkpoint.py`
- `scripts/verify_m0_fence_rooted_trust_bundle.py`
- `apps/api/src/gossip/gossip-replay-state-do.ts`
- `apps/api/src/env.ts`
- `apps/api/src/index.ts`
- `apps/api/wrangler.jsonc`

## 2. Blocking gate A — witness receipt verification profile

The current provider-neutral adapter defines a `Receipt` with scope, generation, operation ID, checkpoint digest, predecessor digest, and a string `consistency_token`.

The conformance harness checks that these fields match and that the token is non-empty. The in-memory fixture generates values such as `fixture-token-1`. This is useful for testing adapter shape and idempotency, but it is not a signature, inclusion proof, consistency proof, or independently verifiable witness attestation.

The existing `verify_m0_fence_rooted_trust_bundle.py` verifies the Ed25519 root signature and monotonic trust-bundle contents. It does not verify witness checkpoint receipts or prove that a receipt is bound to an independently durable append. The trust-bundle checkpoint wrapper also checks the adapter receipt fields, not a cryptographic witness receipt.

**Required before bridge implementation:**

1. Define a versioned FENCE-001 witness receipt envelope and canonical signed payload.
2. Specify exactly which claims the receipt makes: witness identity, scope, generation, operation ID, checkpoint digest, predecessor digest, commit time, and any required log/tree checkpoint.
3. Define the cryptographic proof format and verifier inputs, including pinned witness keys, key validity, revocation, trust-bundle freshness, and domain separation.
4. Define how latest-head readback and consistency proofs are verified, including rollback/fork detection.
5. Add synthetic-key positive and negative vectors, including altered fields, wrong scope, stale head, revoked key, unknown key, malformed proof, and proof substitution.
6. Keep provider-specific durability and failure-domain claims separate from cryptographic receipt validity.

Do not reinterpret `consistency_token` as proof and do not add a second trust root or an ad hoc receipt verifier inside the Durable Object.

## 3. Blocking gate B — authenticated internal workload identity

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

The bridge must not add a network call inside that transaction. Once gates A and B exist, implementation must use the durable intent → external witness operation → verified receipt/latest-head check → local finalize protocol from PR #185.

The pending intent must block conflicting successors. An ambiguous acknowledgement must resume the exact operation ID and exact canonical bytes. No accepted result may be returned before verified witness proof and local finalization. On activation, replay admission must remain blocked until pending-intent recovery and local-versus-witness reconciliation complete.

## 5. Sequenced implementation plan

| Order | Work item | Exit condition |
|---|---|---|
| 1 | WIT receipt profile and verifier | Signed receipt and proof vectors pass; no opaque-token success path |
| 2 | Worker workload identity and scope authorization | Authenticated service-binding caller and audience verified in local Workers tests |
| 3 | Private witness gateway adapter | Strict schema, canonical payload, exact idempotency and verified latest-head response |
| 4 | Durable Object pending-intent lifecycle | Crash/retry/concurrency tests pass; no network in storage transaction |
| 5 | Restore and rollback reconciliation | Witness-ahead, local-ahead, fork, stale proof and unavailable witness fail closed |
| 6 | Provider qualification | Independent evidence supports actual provider durability and failure-domain claims |

## 6. Explicit non-goals

This audit does not add a gateway, service binding, provider adapter, receipt format, credentials, signing keys, production writes, host execution, or student-code execution. DynamoDB Local and in-memory fixtures remain test environments only.

**Current status:** Bridge implementation is blocked on gates A and B. This is an intentional security stop, not a claim of completed integration.
