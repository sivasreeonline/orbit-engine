# FENCE-001 provider audit provenance adapter

## Purpose

The privileged-bypass harness in PR #98 records provider request IDs and fetches audit events. Matching event fields and raw bytes are not, by themselves, proof that those bytes came from the claimed provider audit service. This contract adds an independent verification boundary between raw audit collection and evidence-manifest packaging.

The collector adapter returns raw provider audit pages. A separately provisioned verifier authenticates each exact page using trust material pinned outside the provider response and outside the evidence store. The verifier must return a structured result bound to the SHA-256 of the exact raw response bytes.

## Required guarantees

For every page, the harness requires:

- Exact provider, account, region and audit-service identity equality with operator-pinned expected values.
- A source service principal authenticated by the verifier and distinct from the independent verifier principal.
- A page cursor that starts at the previously accepted cursor and advances; the verifier authenticates the exact page bytes.
- Non-empty raw response and provider-native authentication evidence, preserved as artifacts.
- A verifier result of `VERIFIED` for both provider-native authentication and authenticated transport, using the pinned trust-root ID and SHA-256 fingerprint.
- A supported, explicitly declared authentication method: `PROVIDER_SIGNED_AUDIT_ENVELOPE` or `AUTHENTICATED_AUDIT_API_RESPONSE`.
- A complete, contiguous event sequence with unique event IDs and exact correlation to every provider request ID in the PR #98 run report.
- Exact actor, action, denial outcome, object reference and immutable version binding for each privileged request.

The verifier factory is separate from the collector factory. It must not accept trust roots or identity claims from the provider page itself. The trusted root fingerprint and expected provider scope are supplied out of band by the qualification operator.

## Adapter interfaces

The collector factory exposes:

```python
fetch_page(cursor, *, verifier_principal_id) -> AuditPage
```

The independent verifier factory exposes:

```python
verify_page(
    page,
    *,
    expected_identity,
    pinned_trust_root_id,
    pinned_trust_root_sha256,
    verifier_principal_id,
) -> Verification
```

See `scripts/validate_m0_fence_provider_audit_provenance.py` for the exact dataclass fields and fail-closed checks.

External invocation:

```powershell
$env:FENCE_PROVIDER_AUDIT_ADAPTER_FACTORY = "provider_adapter:create_adapter"
$env:FENCE_PROVIDER_AUDIT_VERIFIER_FACTORY = "provider_verifier:create_verifier"
$env:FENCE_PROVIDER_AUDIT_EXPECTED_PROVIDER = "<operator-pinned-provider>"
$env:FENCE_PROVIDER_AUDIT_EXPECTED_ACCOUNT_ID = "<qualification-account-id>"
$env:FENCE_PROVIDER_AUDIT_EXPECTED_REGION = "<qualification-region>"
$env:FENCE_PROVIDER_AUDIT_EXPECTED_SERVICE = "<audit-service-id>"
$env:FENCE_PROVIDER_AUDIT_TRUST_ROOT_ID = "<independently-governed-root-id>"
$env:FENCE_PROVIDER_AUDIT_TRUST_ROOT_SHA256 = "<64-lowercase-hex-root-fingerprint>"
$env:FENCE_PROVIDER_AUDIT_VERIFIER_PRINCIPAL_ID = "<independent-verifier-principal>"
python scripts/validate_m0_fence_provider_audit_provenance.py `
  --run-report ./provider-privileged-bypass-run.json `
  --initial-cursor "<provider-audit-start-cursor>" `
  --output-dir ./provider-audit-provenance-evidence
```

The run report must be the non-test-only completed output of PR #98. The adapter and verifier are provider-specific and are not included in this repository. No provider has been selected.

## Authentication method interpretation

A provider-signed audit envelope can be verified cryptographically against a separately pinned provider trust root. An authenticated audit API response may instead rely on an independently authenticated API session and provider-documented response semantics; its verifier must preserve the authentication evidence and bind the exact response bytes. These methods are not interchangeable and neither alone proves audit-log completeness, retention, immutable storage, or provider control-plane honesty.

The verifier implementation must document its provider-specific trust chain, algorithm, key lifecycle, certificate or key revocation handling, authenticated endpoint identity, and how the captured bytes are bound to the verified response. A boolean supplied by the collector is not sufficient.

## Synthetic CI coverage

The self-test exercises a successful synthetic page and rejects wrong provider account, unverified page, invalid signature, unpinned trust-root substitution and duplicate request IDs. These fixtures prove only that the harness rejects those malformed contract results. They are not provider evidence and do not establish the authenticity of any real audit source.

## Remaining qualification gaps

- No provider-native collector or verifier adapter is selected or implemented.
- No provider trust root, certificate chain, endpoint identity or key lifecycle is pinned for production.
- No evidence proves audit stream completeness, retention, anti-tampering or privileged administrator non-repudiation.
- No real provider account, role assignment, service identity or failure-domain independence has been independently authenticated.
- The output still requires materialization, byte verification, the dual-signed evidence manifest, and independent review.

This harness does not authorize host admission, execution, production deployment, or a FENCE-001 pass.
