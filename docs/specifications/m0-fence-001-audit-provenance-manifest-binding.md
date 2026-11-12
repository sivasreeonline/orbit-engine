# FENCE-001 audit provenance evidence-manifest binding v1

## Purpose

PR #100 produces an authenticated audit provenance report and preserves raw audit pages, provider authentication evidence and individual event bytes. This binding contract connects those exact outputs to the existing independently signed evidence manifest without changing the manifest v1 schema.

The binding is a separate, dual-attested envelope. It references the existing manifest digest and exact RFC 8785 JCS digest of the audit provenance report. It maps every page, authentication-evidence file and event file to one unique manifest artifact.

## Required checks

The validator:

- Verifies the existing evidence manifest digest and its collector/verifier Ed25519 attestations using independently supplied trusted keys.
- Requires a non-test-only completed audit provenance report in external mode.
- Requires provider name, account, region and service to match the signed manifest exactly.
- Requires the report's independent verifier identity to match the manifest's independent-verifier signer.
- Binds the exact canonical audit report bytes by SHA-256.
- Requires one unique manifest artifact mapping for every raw page, provider authentication evidence file and event file.
- Requires exact SHA-256 and byte-count equality, correct artifact type and WIT-012/WIT-014 control coverage.
- Requires each event artifact to include its originating provider request ID.
- Materializes every mapped artifact under its manifest artifact ID and rechecks exact bytes against the signed manifest.
- Verifies two distinct collector and independent-verifier Ed25519 attestations over the binding digest using a separate domain-separation prefix.

## Binding signature profile

The binding digest is SHA-256 over UTF-8 RFC 8785 JCS bytes of `bindingBody`.

Each detached signature covers:

```
SKYHIGH-FENCE-001-AUDIT-PROVENANCE-BINDING-V1\0
|| JCS({bindingDigest, role, signerIdentity, keyId})
```

The binding collector and independent-verifier keys are supplied through a separately governed trusted-key file. They must be distinct and authorized for their respective roles. The binding does not accept public keys embedded in its own envelope.

## External invocation

```sh
python scripts/validate_m0_fence_audit_provenance_manifest_binding.py \
  --manifest evidence-manifest.json \
  --manifest-trusted-keys /secure/trust/evidence-manifest-keys.json \
  --audit-report provider-audit-provenance-run.json \
  --binding audit-provenance-binding.json \
  --binding-trusted-keys /secure/trust/audit-binding-keys.json \
  --artifact-root /secure/materialized-evidence/run-123
```

The audit report and binding must be generated after the provider audit provenance run. Manifest artifact IDs in the binding must identify the immutable materialized objects containing the exact raw bytes. The manifest must already be independently signed; this validator does not upload or mutate evidence objects.

## Synthetic CI scope

The self-test constructs ephemeral in-memory Ed25519 keys and synthetic manifest, report and evidence bytes. It verifies the positive binding and rejects report substitution. CI proves only the local verifier logic and schema wiring. It does not prove provider audit authenticity, key governance, evidence-store immutability or signer independence.

## Remaining limits

The binding does not prove the provider emitted a complete audit stream, that the provider's audit API is honest, that the trust roots are authentic, or that the evidence store enforces retention. Those require a real provider adapter, independently governed trust material, provider-native audit verification and operational review. No provider is selected and no production qualification or host admission is authorized.
