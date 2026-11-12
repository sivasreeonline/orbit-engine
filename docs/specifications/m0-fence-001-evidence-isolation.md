# FENCE-001 evidence-store privileged-bypass and independence qualification

**Status:** Provider-neutral qualification contract. No provider has been selected or qualified.
**Validator:** `scripts/validate_m0_fence_evidence_isolation.py`.
**Fixture:** Synthetic and test-only; never acceptable as external qualification evidence.

## Objective

The existing object-store contract tests ordinary deletion denial and metadata claims. This milestone adds two controls that the ordinary contract cannot establish:

1. Whether privileged identities can bypass retention, overwrite an exact version, or alter recovery/version mappings.
2. Whether storage, collection, independent verification and two monitors actually occupy separate administrative and operational failure domains.

A provider's `COMPLIANCE` label or a denied request from an ordinary writer is not sufficient.

## Mandatory privileged bypass attempts

A candidate qualification run must execute and preserve provider-native request and audit evidence for all seven actions against the same retained exact object version:

- Delete as object owner.
- Shorten retention as object owner.
- Delete as account owner.
- Disable object lock as organization administrator.
- Delete through the recovery administrator.
- Overwrite the exact version.
- Replace or rebind the version mapping.

Every operation must be denied by the provider. A successful mutation, missing request ID, missing audit event, changed exact-version bytes, or inability to obtain the provider audit event independently is a hard failure. The attempts must be performed in an isolated qualification account with a disposable retained artifact and approved test window; do not test destructive actions against production evidence.

The structured attestation binds each action to its privileged actor, provider request ID, audit event ID, audit-event digest and independent verifier acquisition identity. The raw provider request/response and audit-event artifacts must also be materialized, byte-verified and included in the existing dual-signed evidence manifest. The manifest, not this JSON document alone, supplies integrity and independent attestations.

## Required independence topology

Five distinct operating domains are required:

- Evidence storage.
- Evidence collection.
- Independent evidence verification.
- Monitor A.
- Monitor B.

For each domain, the attestation records account ID, organization ID, administrative boundary, deployment control plane, failure domain and principal identity. All five values must be distinct across all five domains. The four privileged bypass principals must be mutually distinct and must not overlap any of the five domain principals.

This is a deliberately strong qualification bar. Two processes, two IAM users in one account, or two monitors controlled by one administrator do not count as independent. If a candidate provider cannot meet this topology, document the residual risk and keep the provider blocked; do not weaken the validator silently.

## Validation

Fixture validation:

```sh
python scripts/validate_m0_fence_evidence_isolation.py
```

External attestation validation:

```sh
python scripts/validate_m0_fence_evidence_isolation.py --attestation /secure/evidence/isolation-attestation.json
```

The external mode rejects test-only attestations. It validates schema, distinct account/organization/administrative/deployment/failure domains, role separation, all seven unique bypass actions, designated privileged actors, DENIED outcomes and independent verifier acquisition identity.

## Evidence limitations and fail-closed rule

The validator checks declarations; it does not authenticate cloud audit logs, prove that an actor truly held the declared role, or establish that the provider enforced the denial. The independent reviewer must authenticate the provider-native audit events and account ownership through a channel outside the storage account. Those raw records must be covered by the dual-signed manifest and exact-byte verification.

Any ALLOWED result, missing action, missing audit event, duplicate identity/domain, collector/verifier overlap, shared privileged principal, or unresolved provider evidence keeps the candidate BLOCKED. This package cannot grant production approval.
