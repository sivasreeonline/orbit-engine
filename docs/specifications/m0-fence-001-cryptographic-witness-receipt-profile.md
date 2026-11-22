# FENCE-001 witness receipt and signed transparency-head integration addendum

**Existing profile:** `sky-high-fence-witness-v1`  
**Merkle profile:** `sky-high-fence-witness-merkle-v1`  
**Status:** Integration addendum; not implemented or provider-qualified.

## 1. Existing repository contracts (authoritative starting point)

This addendum does not define a second receipt or trust-bundle format. The repository already has:

- `docs/schemas/m0-fence-witness-v1.schema.json`: checkpoint, signed receipt and root-signed witness trust-bundle schemas.
- `scripts/validate_m0_fence_witness_profile.py`: strict JSON, RFC 8785 canonicalization, SHA-256, Ed25519 receipt signature, root-signed trust-bundle succession, receipt/checkpoint binding, key purpose/scope/lifecycle/revocation checks, and synthetic negative cases.
- `docs/test-vectors/fence-witness-v1-001.json`, `fence-witness-v1-002-unicode.json`, and `fence-witness-v1-003-trust-bundle.json`: synthetic signed receipt and trust-bundle vectors.
- `scripts/validate_m0_fence_witness_merkle_proofs.py` and `docs/test-vectors/fence-witness-v1-004-merkle-transparency.json`: RFC 9162 SHA-256 Merkle inclusion/consistency algorithms, published vectors, negative cases and exhaustive model checks.

The existing receipt envelope is exactly `{body, signature}`; `body.keyId` identifies the signer. Its signature domain is `SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\0`. The root-signed trust-bundle envelope is `{body, bundleDigest, rootKeyId, rootSignature}`; its signature domain is `SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\0`. The current witness key purpose is `WITNESS_RECEIPT_SIGNING`, scoped to witness and authority IDs.

The receipt body includes a provider-defined `consistencyToken`. The existing validator correctly treats it as a non-empty opaque structural field; it is not an inclusion proof, consistency proof, signed tree head, or proof of provider durability.

## 2. Exact gap to close

The repository currently verifies receipt signatures and key authorization, and separately verifies RFC 9162 proof mathematics. It does not yet cryptographically bind a signed transparency tree head to an authorized log-signing key and connect that signed head to the receipt inclusion/consistency proof in one verifier path.

The next implementation must compose the existing verified receipt and trust-bundle state with the existing Merkle proof functions. Do not replace these algorithms or introduce a competing receipt envelope, trust bundle, root, signature prefix, or Merkle implementation.

## 3. Extend the existing witness key purpose model

Extend the existing `witnessSigningKey.purpose` schema from the single constant `WITNESS_RECEIPT_SIGNING` to the closed enum:
- `WITNESS_RECEIPT_SIGNING`
- `WITNESS_LOG_SIGNING`

Keep the existing root-signed trust-bundle profile, envelope, canonicalization, signature prefix, root pinning, generation/predecessor chain, key ID calculation, witness ID, authority ID scope, validity, retirement and revocation semantics.

Receipt and log signing keys MUST be distinct key IDs and distinct operational identities. A key authorized for `WITNESS_LOG_SIGNING` MUST NOT sign receipts; a receipt key MUST NOT sign tree heads. Existing vectors using `WITNESS_RECEIPT_SIGNING` remain valid and unchanged. Add synthetic trust-bundle vectors containing both purposes and prove wrong-purpose rejection.

Do not broaden the existing manifest trust bundle. The existing FENCE-001 governance-root pinning mechanism and witness trust-bundle envelope remain authoritative; no new root format is introduced.

## 4. Signed transparency tree head envelope

Add a closed-schema tree-head envelope with exactly `body` and `signature`. Its body fields are:

| Field | Meaning |
|---|---|
| `profile` | `sky-high-fence-witness-merkle-v1` |
| `schemaVersion` | Integer 1 |
| `witnessId` | Exact witness ID authorized by the trust bundle |
| `authorityId` | Exact authority scope authorized for the log key |
| `hostId` | Exact host scope for this log |
| `logId` | Stable transparency-log identity |
| `treeSize` | Non-negative integer |
| `rootHash` | Lowercase SHA-256 hex digest |
| `timestamp` | UTC RFC 3339 timestamp |
| `keyId` | Fingerprint of the authorized `WITNESS_LOG_SIGNING` key |

The Ed25519 signature input is:

`SKYHIGH-FENCE-001-WITNESS-TREE-HEAD-V1\0 || JCS(body)`

The verifier MUST validate the body schema, canonical signature encoding, key fingerprint, witness/authority/host scope, `WITNESS_LOG_SIGNING` purpose, key validity/retirement/revocation at the signed timestamp, and Ed25519 signature. The verifier MUST NOT infer trust from an unsigned tree head or from a key ID supplied outside the root-verified witness trust bundle.

## 5. Bind the existing signed receipt to RFC 9162 proofs

The transparency log entry is the complete canonical receipt envelope `JCS({body, signature})`, not a self-referential leaf-hash field inside the receipt body. The leaf hash is derived:

`SHA256(0x00 || JCS(receiptEnvelope))`

Use the existing RFC 9162 tree algorithm:
- leaf hash prefix `0x00`;
- node hash `SHA256(0x01 || leftHash || rightHash)`;
- SHA-256 hashes exactly 32 bytes.

The proof response must include:
- the exact signed receipt envelope;
- the signed tree-head envelope;
- receipt leaf index and inclusion path;
- consistency path from the caller's last pinned tree size/root to the returned tree head;
- the prior pinned tree-head identity or explicit genesis state.

The verifier MUST check that the receipt envelope's witness/authority/host/generation/operation/checkpoint digest/predecessor match the exact pending checkpoint and trust scope. It then computes the leaf hash from the complete canonical receipt envelope, verifies inclusion against the signed tree-head root using the existing `verify_inclusion`, and verifies extension from the locally pinned prior head using the existing `verify_consistency`.

Tree size MUST NOT regress. Equal tree size with a different root is QUARANTINE. A larger tree size without a valid consistency proof from the pinned prior tree head is BLOCKED/QUARANTINE. Same-size/same-root is acceptable only with an empty consistency proof.

The opaque `consistencyToken` remains available for provider diagnostics and adapter compatibility. It MUST NOT substitute for the signed tree head, inclusion proof, or consistency proof.

## 6. Anti-equivocation and independence limits

A valid receipt signature proves that an authorized key signed the receipt. A valid signed tree head plus inclusion and consistency proofs proves inclusion in an append-only view relative to a pinned prior head. Neither proves provider durability or independent failure-domain separation.

A single log signer can still present split views to different clients. Verifiers MUST durably retain accepted tree size/root per `logId` and gossip signed tree heads through the existing independent monitor-gossip channel. Conflicting signed roots at the same log ID/tree size MUST trigger an equivocation alert and quarantine. A single Worker-local cache or Durable Object is not an independent monitor.

Provider durability, account/operator/control-plane independence, restore behavior and retention remain subject to WIT-001..WIT-014 and independently collected evidence.

## 7. Required integration tests

Extend the existing validators and test vectors; do not fork their algorithms.

- Existing receipt and trust-bundle vectors remain unchanged and pass.
- Trust-bundle schema accepts both allowed key purposes and rejects unknown purposes.
- Receipt verifier rejects a log-purpose key; tree-head verifier rejects a receipt-purpose key.
- Valid signed tree head verifies against root-authorized log key and exact witness/authority/host scope.
- Wrong signature prefix, altered body, invalid signature, unknown/revoked/expired/retired key and scope substitution fail.
- Valid receipt inclusion and consistency proofs verify using the existing RFC 9162 implementation.
- Receipt envelope mutation, proof-node mutation, invalid leaf index, truncated/overlong path and malformed hash fail.
- Tree-size regression, equal-size conflicting roots, invalid consistency path and rewritten prefix fail.
- Lost acknowledgement recovery re-fetches the exact immutable receipt and re-verifies its inclusion proof against the latest signed head.
- Independent monitor gossip detects two valid but conflicting signed heads for the same log and tree size.
- Test results distinguish synthetic cryptographic tests, local service-binding simulation, DynamoDB Local and real-provider qualification.

## 8. Non-goals and qualification boundary

This addendum does not select AWS or another provider, assert that DynamoDB natively provides the transparency log, deploy a log, create production keys, authorize live writes, or establish independent failure domains.

Production rollback protection and witness anti-equivocation remain **NOT QUALIFIED** until signed tree-head verification is implemented, the existing receipt and Merkle validators are composed, monitor gossip is integrated, and WIT-001..WIT-014 provider evidence is independently reviewed.
