# FENCE-001 combined CloudTrail qualification manifest gate

**Status:** Synthetic combined gate. Production qualification remains false.  
**Validator:** `scripts/validate_m0_fence_cloudtrail_qualified_manifest.py`

## Purpose

The CloudTrail custody, digest inventory and AWS STS dual-principal validators are separate fail-closed checks. This gate requires all three to pass against the same dual-signed manifest and materialized artifact root.

## Required checks

1. CloudTrail report-to-manifest custody:
   - dual signatures and trusted signer keys;
   - exact digest, log and regional public-key artifacts;
   - raw and decompressed hash/byte-count consistency;
   - digest RSA signature and predecessor-chain re-verification.
2. Digest inventory reconciliation:
   - signed ListObjectVersions index and page artifacts;
   - complete pagination markers;
   - exact current S3 VersionId for every standard/backfill digest in scope;
   - no unlinked or missing digest keys;
   - separate backfill chain coverage.
3. Dual-principal AWS STS identity:
   - exactly one COLLECTOR and one INDEPENDENT_VERIFIER identity artifact;
   - both match the manifest AWS account;
   - expected IAM roles match the actual assumed-role ARNs;
   - caller roles, ARNs and STS request IDs are distinct.

The combined validator returns `CUSTODY_IDENTITY_AND_INVENTORY_RECONCILED` only when all three independent validators pass against the same manifest.

## No production readiness claim

The combined result always reports `productionQualificationReady=false` and `externalQualificationStatus=REQUIRED`. The following remain external prerequisites:
- AWS CLI `cloudtrail validate-logs` differential against an independently acquired real digest fixture;
- real, separately governed collector and verifier STS clients;
- live read-only qualification of S3 versioning, Object Lock, retention, IAM and delete-marker policy;
- repeat or independently governed point-in-time S3 inventory to address non-atomic pagination;
- verified backfill coverage and explicit CloudTrail delivery time-window scope;
- separate canonical runtime/containerd qualification before host admission.

No AWS account, credentials, provider API calls, live writes, host execution or student-code execution are used by CI.
