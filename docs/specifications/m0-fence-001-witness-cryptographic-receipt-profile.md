# FENCE-001 witness cryptographic receipt profile (proposal)

**Status:** Proposed cryptographic profile for independent review; not an approved implementation standard.  
**Scope:** Checkpoint digest construction, signed witness receipts, trust-root/key lifecycle, and receipt replay validation.  
**Safety boundary:** No provider, witness service, key custodian, KMS/HSM, production key, or runtime verifier is selected or connected. This document does not qualify witness independence, anti-equivocation, provider fencing, or host admission.

## 1. Design objectives and explicit non-claims

The verifier must establish that a receipt was signed by a currently trusted key for the configured witness and that the signature binds the exact checkpoint, scope, generation, operation and predecessor. It must reject malformed encodings, unknown keys, untrusted trust-bundle versions, revoked keys, scope substitution, altered checkpoint bytes and replay under a different lifecycle transition.

A valid Ed25519 signature proves only that the corresponding private key signed the specified bytes. It does **not** prove that the witness stored the record durably, returned a linearizable latest value, retained one non-forking history, or operates in an independent failure domain. Those properties require provider-specific evidence, independent monitors and adversarial qualification.

## 2. Proposed cryptographic suite

Profile identifier: `sky-high-fence-witness-v1`.

| Purpose | Proposed primitive / encoding |
|---|---|
| Structured canonical bytes | RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8 |
| Checkpoint and trust-bundle digest | SHA-256, lowercase 64-character hexadecimal |
| Receipt and trust-bundle signatures | Ed25519 |
| Signature wire encoding | Base64url without padding; decoded Ed25519 signature must be exactly 64 bytes |
| Public key wire encoding | Base64url without padding; decoded Ed25519 public key must be exactly 32 bytes |
| Key identifier | SHA-256 fingerprint of the raw public key, lowercase hexadecimal, with a purpose prefix in the trust-bundle record |

This suite is a proposed v1 baseline, not a claim that a provider supports it. Do not silently substitute algorithms or encodings. A future profile change requires a new profile identifier and test vectors.

## 3. Canonical checkpoint digest

The signed and hashed object is a versioned checkpoint body. It contains exactly these fields:

- `profile`: `sky-high-fence-witness-v1`
- `schemaVersion`: integer `1`
- `authorityId`: non-empty string
- `hostId`: non-empty stable enrolled-host string
- `generation`: positive safe integer
- `phase`: `ISSUED`, `ACCEPTED`, or `REVOKED`
- `operationId`: non-empty stable operation identifier
- `previousCheckpointDigest`: 64 lowercase hexadecimal characters
- `authorityStateDigest`: 64 lowercase hexadecimal characters
- `responseDigest`: 64 lowercase hexadecimal characters
- `epoch`: non-negative safe integer
- `recordVersion`: positive safe integer

The checkpoint digest is:

`lowercaseHex(SHA-256(UTF8(JCS(checkpointBody))))`

The digest field itself is not part of `checkpointBody`; this avoids self-reference. The API/storage envelope may carry `checkpointDigest` alongside the body, but it must equal the recomputed value. Unknown fields are rejected for profile v1 rather than silently omitted from the signed representation. JSON numbers must be finite safe integers; values outside the safe-integer range are rejected before canonicalization.

A checkpoint artifact is the exact UTF-8 JCS byte sequence. Its SHA-256 is the artifact digest. Implementations must not hash pretty-printed JSON, JSONB text output, delimiter-concatenated strings, platform-default encodings, or a parsed-and-reserialized representation that is not byte-identical to JCS.

JCS does not perform Unicode normalization. Protocol strings are hashed as their exact Unicode scalar sequence after UTF-8 encoding. NFC and NFD spellings that look identical to a person are distinct inputs and produce distinct digests. Implementations must not normalize, case-fold, trim, or otherwise rewrite identifiers before digesting; enrollment and identity policy must separately define which strings are admissible. The checked-in deterministic vectors are `docs/test-vectors/fence-witness-v1-001.json` (ASCII baseline) and `docs/test-vectors/fence-witness-v1-002-unicode.json` (Unicode identity values).

## 4. Receipt signature payload

The receipt body contains exactly:

- `profile`: `sky-high-fence-witness-v1`
- `schemaVersion`: integer `1`
- `witnessId`
- `authorityId`
- `hostId`
- `generation`
- `operationId`
- `checkpointDigest`
- `previousCheckpointDigest`
- `keyId`
- `committedAt`: RFC 3339 UTC timestamp with explicit `Z`
- `consistencyToken`: provider-defined opaque token, non-empty

The signature input is the concatenation of the UTF-8 domain-separation prefix

`SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\0`

and the UTF-8 JCS bytes of the receipt body. The `signature` property is excluded from the body. Ed25519 signs and verifies these exact bytes. The receipt envelope carries the base64url signature separately.

Verification order:

1. Strictly parse the envelope; reject duplicate JSON object member names and unknown v1 fields.
2. Validate field types, lengths, integer bounds, timestamp syntax and base64url canonical form.
3. Recompute the checkpoint digest from the checkpoint body and compare it to the checkpoint and receipt values.
4. Resolve `keyId` only from the configured, authenticated trust bundle; never trust a public key supplied by the receipt itself.
5. Check key purpose, witness identity, authority/environment scope, validity and revocation state.
6. Verify the Ed25519 signature over the exact domain-separated JCS payload.
7. Verify provider-specific consistency evidence and the exact append/readback semantics. A non-empty token alone is not verification.
8. Compare the receipt against the expected operation, phase, generation, predecessor and checkpoint, and against the current strongly consistent high-water record.

A verifier must fail closed on any parse, key-resolution, signature, scope, digest, consistency or freshness error.

## 5. Trust root and key lifecycle

The witness signing key and trust-bundle root key are separate roles. The root key is an offline governance trust anchor and must not be available to the witness runtime.

A trust bundle contains:

- profile and schema version;
- stable trust-domain and witness identity;
- monotonically increasing bundle generation;
- exact predecessor bundle digest (zero digest only for initial enrollment);
- each signing key's key ID, raw public key, purpose, permitted witness/authority scope, activation time and optional retirement time;
- explicit revoked-key records and revocation reason/effective policy;
- root signature over the domain-separated JCS bundle body.

The trust-bundle digest is SHA-256 over the exact JCS bundle body, excluding its digest and root-signature envelope fields. The root signature uses a separate domain prefix, `SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\0`.

Bootstrap requires the root public-key fingerprint to be pinned through an independently governed channel. A trust bundle must advance exactly one generation, link to the previously accepted digest, and verify under the pinned root. A restored or older bundle is rejected. The verifier must persist the highest accepted generation/digest outside the authority database's ordinary restore domain; if that protected state is unavailable or contradictory, verification is quarantined.

Rotation is additive before cutover: distribute and validate the successor key in a root-signed bundle, prove the witness can sign with it, then switch receipt issuance. Retired keys may remain available for historical verification only under an explicitly reviewed policy and independently trustworthy receipt-time evidence. The receipt's self-reported `committedAt` is not trusted time by itself.

Revocation is fail-closed. A key marked compromised is rejected for all receipts unless a separately approved incident procedure establishes a defensible compromise cutoff using independent trusted time and append evidence. No implementation may infer a safe cutoff from a timestamp signed by the compromised key. Revocation-bundle freshness is mandatory; stale or unavailable revocation state blocks anchoring.

## 6. Replay, rollback and equivocation controls

A receipt is accepted only for the exact tuple:

`(profile, witnessId, authorityId, hostId, generation, phase, operationId, checkpointDigest, previousCheckpointDigest, keyId)`.

The tuple is checked against the locally committed checkpoint intent and the latest independently read witness record. Operation IDs are not reusable across phases or checkpoint bodies. The same receipt may be replayed only as an idempotent response to the same exact transition while it remains the current high-water checkpoint; it must not be treated as current after a successor has appeared.

The verifier must also require:

- monotonic generation with no gaps;
- exact predecessor digest continuity;
- stable witness, authority and host identity;
- monotonic epoch and record-version rules enforced by the lifecycle contract;
- exact checkpoint artifact and receipt digest equality;
- fresh trust-bundle and revocation generations.

Ed25519 does not prevent a malicious or compromised witness from signing two conflicting successors. A signature plus a CAS API is not anti-equivocation proof. Qualification therefore additionally requires independently operated monitors or witness replicas that compare signed heads, durable signed consistency/inclusion proofs, and a documented detection and quarantine protocol. If two valid signed heads exist for the same predecessor/generation, the authority is quarantined; it must never select the locally preferred fork.

## 7. Consistency-token contract

The current provider-neutral TypeScript field `consistencyToken: string` is only a transport placeholder. Checking that it is non-empty is not a security check.

A production adapter must define, version and verify the token's exact semantics, including:

- which provider/witness API response generated it;
- whether it binds a linearizable read or a committed append;
- how it binds witness identity, scope, generation, checkpoint digest and predecessor digest;
- expiry/freshness and replay rules;
- whether it includes a signed tree head, inclusion proof or consistency proof;
- how independent monitors obtain and compare the same evidence.

Until a concrete adapter and independent reviewer prove those semantics, the receipt verifier must return failure. A provider-specific token must not be accepted merely because it is syntactically present.

## 8. Required conformance vectors and negative tests

Before runtime implementation is enabled, publish fixed vectors containing the exact JCS UTF-8 bytes, checkpoint digest, receipt payload bytes, Ed25519 public key, private test seed, signature and expected result. At least two independent implementations must reproduce the vectors byte-for-byte.

Negative tests must cover:

- field-order changes that preserve JCS bytes versus semantic changes that alter bytes;
- duplicate JSON keys, unknown fields, invalid UTF-8, non-finite or unsafe integers;
- altered checkpoint, response, predecessor, operation, phase, scope or witness identity;
- wrong domain prefix, wrong key purpose, wrong key ID and malformed/non-canonical base64url;
- unknown, expired, not-yet-active, retired and revoked keys;
- trust-bundle generation rollback, gap, predecessor fork and root-signature failure;
- stale revocation state and unavailable trust root;
- receipt replay after a later checkpoint, generation gap and predecessor fork;
- two conflicting validly signed heads for one predecessor;
- missing, malformed, expired or inconsistent provider consistency proofs.

The vectors must be independently reviewed and checked into the repository before a production verifier or adapter is approved. CI can establish deterministic conformance to the published vectors; it cannot establish key custody, provider independence or honest witness operation.

## 9. Implementation boundary and approval gates

The current `WitnessReceiptVerifier` interface may host this profile, but a production implementation must not be added until the canonical byte contract, vectors, trust-bundle governance, key-custody boundary and provider consistency semantics receive independent review.

No private key, production public key, trust bundle, provider credential or secret belongs in source control. No default or test key may be trusted in production. Test-only private seeds must be unmistakably scoped to fixtures and must never be loaded by a deployment configuration.

This proposal does not select an external witness provider or prove that any existing adapter provides strongly consistent reads, atomic compare-and-append, independent failure domains, anti-equivocation or durable retention. It does not change the locked Sky High application stack or authorize host/guest execution.

**Qualification remains blocked** until the selected witness implementation passes cryptographic vectors, key lifecycle, consistency, equivocation, restore and independent security review using independently acquired evidence.
