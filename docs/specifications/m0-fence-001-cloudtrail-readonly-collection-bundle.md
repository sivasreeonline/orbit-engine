# FENCE-001 read-only CloudTrail evidence collection bundle

**Status:** Injected-client collection orchestrator with synthetic integration tests. Not a production qualification or signed manifest.  
**Implementation:** `scripts/aws_cloudtrail_readonly_collection_bundle.py`  
**Tests:** `scripts/test_m0_fence_cloudtrail_readonly_collection_bundle.py`

## Purpose

The provider adapters, digest-chain verifier, inventory reconciler and STS identity verifier can now be composed into one read-only collection operation. The caller must explicitly supply already-configured AWS clients. This module never discovers credentials or creates SDK clients.

## Collection sequence

1. Verify collector STS caller identity against its pinned account and IAM role.
2. Verify independent-verifier STS caller identity against its separately pinned role.
3. Reject identical caller ARNs or STS request IDs.
4. Capture all S3 object versions and delete markers under the pinned CloudTrail digest prefix.
5. Verify the explicitly supplied exact latest standard digest VersionId and optional separate backfill digest VersionId.
6. During chain verification, capture every exact-version digest and referenced log object returned by S3 GetObject.
7. Capture regional CloudTrail public-key DER bytes, fingerprints, validity windows and ListPublicKeys request IDs.
8. Reconcile the verified standard/backfill digest records against the captured ListObjectVersions pages.
9. Emit a deterministic artifact map containing raw source objects, DER public keys, inventory index/pages, STS identity reports, provider-exchange metadata, verification report and bundle index.

## Caller-supplied inputs

- two independently configured STS clients;
- one regional CloudTrail client;
- one S3 client;
- pinned account, Region, bucket, digest prefix and allowed log prefixes;
- exact latest standard digest tuple `(bucket, key, VersionId)`;
- optional exact latest backfill digest tuple;
- explicit collection time window and boolean test-only classification.

The collector does not silently discover the latest digest key or select a version on the caller's behalf. The caller must select the exact version from independently reviewed inventory output. The collector then reconciles that exact version against the captured inventory and rejects any uncovered digest keys.

## Output and safety status

The returned bundle contains artifact bytes and a summary. It is intentionally **not signed**. It does not create a FENCE-001 evidence manifest or claim that the artifacts have been independently notarized.

Every summary reports:
- `manifestSigningStatus=NOT_SIGNED`;
- `productionQualificationReady=false`;
- `externalQualificationStatus=REQUIRED`;
- absolute snapshot completeness as not proven by non-atomic ListObjectVersions pagination.

A separate signing ceremony and manifest validator must bind these artifacts to trusted collector and independent-verifier signatures before the package can be considered signed evidence.

## Side-effect boundary

All clients are injected. Importing or constructing the collector does not make AWS calls. Calling `collect()` invokes only STS GetCallerIdentity, CloudTrail ListPublicKeys, S3 ListObjectVersions and S3 GetObject. It contains no S3 writes, deletes, restores, Object Lock bypass, host execution or student-code execution.

CI exercises the entire flow with synthetic RSA/gzip fixtures and fake clients. No AWS credentials, account, provider APIs or cloud resources are used.
