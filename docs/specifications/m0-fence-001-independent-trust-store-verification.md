# FENCE-001 independent trusted-key store and verification

**Status:** Offline trust-policy implementation and synthetic tests. This is not a production qualification approval.  
**Verifier:** `scripts/verify_m0_fence_independent_trust_store.py`  
**Policy tests:** `scripts/test_m0_fence_independent_trust_store.py`

## Trust boundary

The manifest is not allowed to establish its own trust anchors. The verifier receives a separate trust-store file, maintained through an independent approval process. The trust store contains public Ed25519 keys only; private keys must never be copied into it.

The verifier first validates trust-store governance metadata and the exact manifest-selected key records, then delegates cryptographic verification to the existing FENCE-001 validator. It then runs the combined CloudTrail digest custody, S3 inventory and dual-principal STS evidence validators against the materialized artifact directory.

## Trust-store format

The top-level object requires:
- `profile`: `sky-high-fence-trusted-key-store-v1`
- `schemaVersion`: `1`
- stable `storeId`
- `status`: `ACTIVE`
- accountable `approvedBy` and external `approvalReference`
- a `keys` array of public-key records

Each key record requires:
- `keyId`: SHA-256 fingerprint of the raw 32-byte Ed25519 public key
- `identity` and authorized `role` (`COLLECTOR` or `INDEPENDENT_VERIFIER`)
- canonical unpadded `publicKeyBase64Url`
- `status`: `ACTIVE` or `REVOKED`
- timezone-aware `notBefore` and `notAfter`
- accountable `approvedBy` and external `approvalReference`

Revoked records remain in the store as tombstones and additionally require `revokedAt`. They are never eligible to verify a manifest. Retaining tombstones makes revocation history explicit and prevents silent key reuse. A selected key must be ACTIVE and the manifest's signed `createdAt` must fall within its validity interval. This permits historical verification after a key naturally expires, but a revoked key always fails closed.

A trust-store file is only an input to the verifier; creating or editing the file does not itself constitute an approval. Approval references must resolve to an independently governed record outside this repository.

## Example structure

```json
{
  "profile": "sky-high-fence-trusted-key-store-v1",
  "schemaVersion": 1,
  "storeId": "sky-high-production-fence-keys",
  "status": "ACTIVE",
  "approvedBy": "security-approver-identity",
  "approvalReference": "SECURITY-CHANGE-REFERENCE",
  "keys": [
    {
      "keyId": "<64-character-public-key-sha256>",
      "identity": "collector-role-identity",
      "role": "COLLECTOR",
      "publicKeyBase64Url": "<unpadded-base64url-public-key>",
      "status": "ACTIVE",
      "notBefore": "2026-11-01T00:00:00Z",
      "notAfter": "2027-11-01T00:00:00Z",
      "approvedBy": "security-approver-identity",
      "approvalReference": "KEY-APPROVAL-REFERENCE"
    }
  ]
}
```

The example is a structure only; it contains no usable key and must not be copied as a production trust configuration.

## Verification command

```bash
python scripts/verify_m0_fence_independent_trust_store.py \
  --manifest ./cloudtrail-evidence-manifest.json \
  --trust-store ./independently-approved-trusted-keys.json \
  --artifact-root ./cloudtrail-bundle
```

The command does not accept a test-only bypass. It requires a non-test-only manifest, verifies both Ed25519 attestations against the independently supplied trust store, and invokes the combined CloudTrail evidence validators.

## Fail-closed cases

- missing or inactive trust store;
- missing accountable approver or external approval reference;
- duplicate key IDs, malformed public keys or invalid key fingerprints;
- missing or invalid key validity interval;
- a manifest selecting a revoked key;
- a manifest created outside the selected key's validity interval;
- signer identity or role not matching the trusted-key record;
- same key or identity used for both roles;
- invalid manifest digest, signature, schema or artifact identity binding;
- missing, modified or incomplete CloudTrail custody, inventory or STS evidence.

## Limits

A valid signature and evidence gate do not prove AWS account ownership, S3 Object Lock configuration, complete CloudTrail delivery, operational key custody or production qualification. Those require external controls and independently acquired AWS evidence. The combined validator deliberately keeps `productionQualificationReady=false` and `externalQualificationStatus=REQUIRED`.

CI tests use only the repository's public synthetic test vector. They do not use production keys, AWS credentials, live provider APIs, host execution or student-code execution.
