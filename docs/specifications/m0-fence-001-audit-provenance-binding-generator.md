# FENCE-001 audit provenance binding generator

The generator creates the separate dual-attested binding envelope consumed by `validate_m0_fence_audit_provenance_manifest_binding.py`.

## Inputs

- The already dual-signed evidence manifest and its independently provisioned trusted-key file.
- A completed, non-test-only PR #100 provider audit provenance report.
- A mapping JSON array with one entry for each report artifact:
  - `pages` → `rawResponseArtifact`
  - `authenticationEvidence` → `authenticationEvidenceArtifact`
  - `events` → `artifact`
- Two separately provisioned Ed25519 private-key files, one for the manifest collector and one for the manifest independent verifier.
- An independently provisioned binding trusted-key file authorizing those exact identities and key fingerprints.

Each private-key file has this structure:

```json
{
  "role": "COLLECTOR",
  "identity": "collector-identity",
  "keyId": "<sha256-of-raw-ed25519-public-key>",
  "privateKeyBase64Url": "<32-byte-ed25519-private-seed-as-unpadded-base64url>"
}
```

The verifier file uses role `INDEPENDENT_VERIFIER`. Never commit private keys or include them in evidence artifacts. The generator checks that each private key matches its declared fingerprint and the corresponding independently trusted public key, and that the two signers are exactly the same identities as the original manifest attestations.

## Generate and verify

```sh
python scripts/create_m0_fence_audit_provenance_binding.py \
  --manifest evidence-manifest.json \
  --manifest-trusted-keys /secure/trust/evidence-manifest-keys.json \
  --audit-report provider-audit-provenance-run.json \
  --mapping-file audit-artifact-mapping.json \
  --binding-trusted-keys /secure/trust/audit-binding-keys.json \
  --collector-signing-key /secure/keys/audit-collector-ed25519.json \
  --verifier-signing-key /secure/keys/audit-verifier-ed25519.json \
  --output audit-provenance-binding.json

python scripts/validate_m0_fence_audit_provenance_manifest_binding.py \
  --manifest evidence-manifest.json \
  --manifest-trusted-keys /secure/trust/evidence-manifest-keys.json \
  --audit-report provider-audit-provenance-run.json \
  --binding audit-provenance-binding.json \
  --binding-trusted-keys /secure/trust/audit-binding-keys.json \
  --artifact-root /secure/materialized-evidence/run-123
```

The generator only signs the canonical report digest and mapping after validating manifest signatures, report status and identity/scope equality. The independent validator must still verify the binding signatures, all mappings, and the materialized artifact bytes. The generator does not upload evidence, choose a provider, or approve a qualification.

## Security boundary

The checked-in self-test creates ephemeral keys and proves only local key authorization and envelope-signing behavior. Production key custody, rotation/revocation, trusted time, signer independence and provider audit authenticity remain external requirements. Never use fixture keys for qualification.
