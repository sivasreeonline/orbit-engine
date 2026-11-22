# FENCE-001 cryptographic witness receipt and transparency proof profile

**Profile:** `sky-high-fence-witness-receipt-v1`  
**Status:** Proposed protocol contract; not implemented or provider-qualified.  
**Scope:** Authenticated checkpoint claims and append-only transparency evidence for monitor replay snapshots and other FENCE-001 witness records.

## 1. Security claims and limits

This profile separates three claims that must never be conflated:

1. **Receipt authenticity:** an authorized witness signing key signed a statement binding one exact checkpoint, scope, operation and predecessor.
2. **Append-only log consistency:** a signed transparency-log checkpoint and cryptographic inclusion/consistency proofs show that the receipt is included in a particular log history and that the observed history extends a previously pinned tree head.
3. **Provider durability and independence:** the provider actually retains the record under the claimed failure model and is operationally independent of the authority/monitoring system.

Ed25519 verification establishes claim 1 only. Merkle inclusion and consistency verification establish claim 2 only, relative to pinned tree heads and the log's cryptographic assumptions. Neither proves claim 3. Provider qualification still requires independently collected operational evidence under WIT-001..WIT-014.

A single log signer can still equivocate by showing different valid tree heads to different clients. Clients MUST retain and gossip observed signed tree heads; independent monitors MUST compare them. A detected fork or unproven consistency transition is QUARANTINE/BLOCKED, never success.

## 2. Trust authorization

The existing `sky-high-fence-manifest-trust-bundle-v1` is specifically for COLLECTOR and INDEPENDENT_VERIFIER manifest keys. It does not authorize witness keys and MUST NOT be silently reused as if it did.

Define a separate purpose-bound authorization envelope, `sky-high-fence-witness-keyset-v1`, signed by an out-of-band pinned FENCE-001 governance root using a distinct signature domain:

`SKYHIGH-FENCE-001-WITNESS-KEYSET-V1\0`

The envelope contains exactly `body`, `keysetDigest`, `rootKeyId`, and `rootSignature`. The body is canonicalized with RFC 8785; `keysetDigest` is SHA-256 of JCS(body); `rootKeyId` is SHA-256 of the raw 32-byte pinned Ed25519 governance public key; and `rootSignature` is a 64-byte Ed25519 signature over the domain prefix concatenated with JCS(body). Root signatures use canonical unpadded base64url encoding. The keyset body MUST have a closed schema.

The keyset body MUST include:
- profile and schema version;
- trust-domain ID;
- monotonically increasing generation and exact previous keyset digest;
- creation time;
- unique witness signing keys with key ID, witness identity, role, public key, not-before/not-after, optional retirement time, approval identity and approval reference;
- explicit revocations with key ID, effective time and reason.

Allowed roles are `WITNESS_RECEIPT_SIGNER` and `WITNESS_LOG_SIGNER`. These roles MUST use distinct keys and identities. A witness key MUST NOT be authorized by a manifest attestation, a receipt itself, a caller request, or an unpinned keyset. The root public key is pinned out of band; the keyset cannot self-authorize its root or freshness.

The keyset verifier MUST check canonicalization, schema closure, root fingerprint, root signature, trust-domain, generation/predecessor, key fingerprints, duplicate IDs, validity intervals, retirement, revocation and approval metadata. Keyset freshness is determined from the locally pinned last-accepted generation/digest or an independently verified current keyset—not from the receipt being checked.

This is a new purpose-specific key authorization profile under the existing FENCE-001 governance-root pinning process, not a new self-signed root and not an extension that silently broadens the manifest-key roles. Governance must explicitly authorize the root's use for this profile before implementation.

## 3. Canonical receipt statement

The receipt statement is a closed JSON object canonicalized with RFC 8785 (JCS), UTF-8 encoded, then signed with Ed25519. Duplicate JSON members, invalid UTF-8, non-finite numbers, unknown fields, non-canonical base64url, and ambiguous numeric representations MUST be rejected.

Required statement fields:

| Field | Meaning |
|---|---|
| `profile` | Exact value `sky-high-fence-witness-receipt-v1` |
| `schemaVersion` | Integer 1 |
| `trustDomainId` | FENCE-001 trust domain |
| `witnessId` | Authorized witness identity |
| `scope` | Exact trust-domain, witness, authority, host, sender and recipient tuple |
| `operationId` | Deterministic immutable operation ID |
| `idempotencyKeyDigest` | SHA-256 digest of the idempotency key, not the secret/raw key |
| `phase` | Checkpoint phase |
| `generation` | Positive monotonic generation within the exact scope |
| `checkpointDigest` | SHA-256 of the exact canonical checkpoint bytes |
| `previousDigest` | Exact predecessor checkpoint digest (zero digest only for approved genesis) |
| `committedAt` | Witness commit time in timezone-qualified RFC 3339 |
| `witnessSequence` | Monotonic append sequence in the witness log |
| `logId` | Stable transparency-log identity |

The signed envelope contains exactly `statement`, `signingKeyId`, and `signature`. The signature input is:

`SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\0 || JCS(statement)`

The signature is a 64-byte Ed25519 signature encoded as canonical unpadded base64url. `signingKeyId` is SHA-256 of the raw 32-byte Ed25519 public key. The verifier resolves it only through the currently accepted witness keyset and requires role `WITNESS_RECEIPT_SIGNER`, exact witness identity, validity at commit time, and no effective revocation.

The verifier recomputes the checkpoint digest from the exact checkpoint bytes and computes the Merkle leaf hash as specified below; the derived leaf hash is proof metadata and MUST NOT be included in the signed statement (which would create a self-referential hash). It MUST compare every statement field against the pending intent and the exact witness scope. A receipt that only repeats caller-supplied fields without a valid signature is rejected.

## 4. Transparency tree and proof envelope

Use the RFC 9162 Merkle Tree Hash construction, SHA-256:
- leaf hash: `SHA256(0x00 || JCS(statement))`;
- node hash: `SHA256(0x01 || leftHash || rightHash)`;
- tree size and leaf index are non-negative integers with `leafIndex < treeSize`.

The proof envelope contains:
- signed tree head: profile, log ID, tree size, root hash, timestamp, signing key ID and Ed25519 signature;
- derived leaf hash, leaf index and receipt inclusion proof (ordered sibling hashes and directions sufficient to recompute the root for the stated leaf index/tree size);
- consistency proof from the client's previously pinned tree size/root to the new tree size/root;
- the prior pinned tree-head identity, or an explicit genesis marker for a first observation.

The tree-head signature input is domain-separated:

`SKYHIGH-FENCE-001-WITNESS-TREE-HEAD-V1\0 || JCS(treeHeadStatement)`

Tree heads MUST be signed by a distinct authorized `WITNESS_LOG_SIGNER` key. A verifier MUST validate the keyset, tree-head signature, inclusion proof, and consistency proof. Tree size MUST NOT regress. Equal tree size with a different root is an immediate fork. A larger tree size without a valid consistency proof from the pinned prior head is BLOCKED/QUARANTINE.

The gateway MUST return a signed latest-head response and the proof material for the exact receipt. A generic opaque `consistency_token` is not accepted as a substitute. The adapter may retain provider-specific opaque tokens for diagnostics, but they have no cryptographic authority in this profile.

## 5. Anti-equivocation and state retention

A valid signature plus a valid inclusion proof does not alone prove global uniqueness of the log history. Each verifier/monitor MUST durably retain its last accepted tree size/root per log ID and MUST gossip signed tree heads through the independent monitor channel.

If two monitors observe different roots for the same log ID and tree size, or cannot establish a valid consistency path, they MUST publish an equivocation alert and quarantine the affected witness scope. A witness MUST NOT be allowed to reset the client's pinned head by presenting a lower tree size, a new log ID, a new key, or a replacement keyset without separately approved recovery.

Tree-head retention, monitor gossip, independent monitor identities, and external evidence collection are mandatory for anti-equivocation qualification. A single Worker-local cache or Durable Object is not an independent monitor.

## 6. Verification order and fail-closed outcomes

For a checkpoint append or recovery, verification order is:

1. Validate exact request/intent scope, operation ID, checkpoint bytes, digest and predecessor.
2. Load the last accepted witness keyset and pinned log tree head from protected state.
3. Verify keyset signature, freshness, generation/predecessor, signer role, validity and revocation.
4. Verify receipt schema, canonical bytes, Ed25519 signature and exact pending-intent binding.
5. Verify tree-head schema/signature, log identity and monotonic tree size.
6. Verify receipt inclusion proof and consistency proof from the previously pinned tree head.
7. Independently read latest witness head and verify it is the same head or a proven valid successor.
8. Only then allow the Durable Object's local finalize transaction.

Outcomes:
- `VERIFIED_CHECKPOINT`: all cryptographic checks pass and local finalize may proceed.
- `PENDING_PROOF`: receipt or proof material is incomplete; retain intent and block successors.
- `BLOCKED_TRUST_STATE`: keyset, latest head, or proof service is unavailable/stale/unverifiable.
- `QUARANTINE`: signature, scope, digest, predecessor, tree root, key status, generation, or history conflicts.

No outcome called ACCEPTED may be returned before local finalize succeeds.

## 7. Required test vectors

Use synthetic Ed25519 keys only. The verifier test suite MUST cover:
- valid receipt and valid tree inclusion/consistency proof;
- altered statement field, checkpoint bytes, digest, scope, predecessor or operation ID;
- wrong signature domain, invalid signature length, unknown/revoked/not-yet-valid/retired key;
- unauthorized signer role and key/identity reuse between receipt and log roles;
- keyset root substitution, stale generation, forked predecessor and rollback;
- duplicate JSON members, unknown fields, invalid UTF-8, NaN/Infinity and non-canonical base64url;
- invalid leaf hash, inclusion path, tree size, leaf index and sibling ordering;
- invalid consistency proof, smaller tree size, equal-size different root and larger tree without proof;
- two signed conflicting tree heads at the same size;
- lost acknowledgement followed by exact operation lookup and exact proof re-verification;
- key rotation and revocation across a pending intent;
- unavailable proof service and unavailable latest-head read.

Test output MUST distinguish pure synthetic cryptographic tests, local service-binding simulation, DynamoDB Local, and real-provider qualification. Passing synthetic tests does not qualify production durability, independent operation, or anti-equivocation.

## 8. Compatibility with the provider-neutral adapter

The current adapter's `Receipt` shape and non-empty `consistency_token` are structural only. This profile is an authenticated envelope layered above the provider adapter. The gateway must map adapter commit metadata into the signed statement only after it has obtained authoritative commit/readback evidence and proof material from the selected provider/log implementation.

No adapter may fabricate a Merkle proof or claim a log append solely because a metadata token is non-empty. If the selected provider cannot supply the required proof and independent log semantics, it cannot satisfy this profile without an explicitly qualified transparency-log component.

## 9. Non-goals and qualification boundary

This document does not select AWS or another provider, assert that DynamoDB supports this transparency-log profile natively, deploy a log, create production keys, or authorize live writes. It does not establish independent failure domains.

Production rollback protection and witness anti-equivocation remain **NOT QUALIFIED** until the verifier and vectors are implemented, key governance is approved, the log/proof service is implemented and independently monitored, and WIT-001..WIT-014 provider evidence is independently reviewed.
