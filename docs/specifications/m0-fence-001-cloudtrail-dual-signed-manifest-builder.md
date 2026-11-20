# FENCE-001 dual-signed CloudTrail evidence manifest builder

**Status:** Synthetic contract implementation. No production qualification is implied.  
**Builder:** `scripts/build_m0_fence_cloudtrail_evidence_manifest.py`  
**Validator:** `scripts/validate_m0_fence_cloudtrail_manifest_binding.py`

## Purpose

Convert a materialized read-only CloudTrail collection bundle into the existing FENCE-001 evidence manifest envelope. The generated manifest uses the established canonical JSON digest and dual Ed25519 attestation contract; it does not invent a parallel signature format.

## Required inputs

- A materialized collection bundle directory produced by `CloudTrailReadOnlyEvidenceBundle.write_to()`.
- An externally provisioned Ed25519 collector private key.
- A separately provisioned Ed25519 independent-verifier private key.
- The exact 40-character adapter Git commit.
- A SHA-256 digest of the reviewed adapter configuration.
- An operator-selected manifest ID.

Private keys may be unencrypted PEM or exactly 32 raw Ed25519 private-key bytes. The builder never generates or persists signing keys. Collector and verifier keys must be different. Their signed identities are taken from the separate STS caller-identity evidence records and must differ.

## Artifact binding

The builder binds the exact raw compressed S3 digest and log bytes by `(bucket, key, VersionId)` using the provider-exchange catalog. It binds regional public-key DER bytes by the reported fingerprint and the validity interval. It also binds the serialized verification report itself.

The manifest records:
- stable artifact ID;
- artifact type and required CT test IDs;
- S3 URI plus exact non-null VersionId, or regional public-key reference plus validity interval;
- raw SHA-256 and byte count;
- acquisition timestamp;
- collector and independent-verifier identities and signing-key fingerprints;
- provider request IDs;
- redaction state.

The generated envelope is canonicalized using RFC 8785 for its manifest digest and attested using the existing FENCE-001 signature domain separator and payload.

## Trust and security boundary

The optional public-key output is a convenience export only. It is **not** an independently governed trust configuration. Before verification, the trust records must be reviewed and provisioned through the independent trust process; the existing validator must receive that separately trusted key set.

The builder does not authenticate possession or governance of the supplied private keys beyond successful local signing. A signed manifest proves integrity relative to the signing keys, not AWS origin, Object Lock compliance, complete CloudTrail delivery, or production readiness.

The builder preserves the bundle's `testOnly` value. Test-only manifests remain ineligible for external qualification mode. The manifest's presence or successful signature verification never changes the qualification state automatically.

## CLI

```bash
python scripts/build_m0_fence_cloudtrail_evidence_manifest.py \
  --bundle-dir ./cloudtrail-bundle \
  --output ./cloudtrail-evidence-manifest.json \
  --collector-private-key ./keys/collector-ed25519.pem \
  --verifier-private-key ./keys/verifier-ed25519.pem \
  --adapter-commit <40-character-git-sha> \
  --configuration-digest <64-character-sha256> \
  --manifest-id <operator-selected-id>
```

Optional `--public-keys-output` writes the derived public keys for a separate trust-governance workflow. Never treat this generated file as its own trust anchor.

## Validation

CI uses ephemeral Ed25519 keys and synthetic CloudTrail fixtures only. It generates a manifest and verifies it through the existing FENCE-001 manifest validator and CloudTrail raw-artifact custody validator. Negative cases reject same-key reuse and post-signing raw-artifact tampering.

No AWS credentials, live provider API calls, cloud resources, host execution or student-code execution are used.
