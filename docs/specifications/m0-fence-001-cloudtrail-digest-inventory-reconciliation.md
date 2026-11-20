# FENCE-001 CloudTrail digest inventory reconciliation

**Status:** Offline synthetic reconciliation contract. Not an AWS provider qualification result.  
**Depends on:** PR #168 CloudTrail raw-evidence manifest binding.  
**Validator:** `scripts/validate_m0_fence_cloudtrail_digest_inventory.py`

## Purpose

The digest verifier follows predecessor links from one supplied digest. That proves the reachable chain and referenced log objects, but it does not establish that every digest object delivered within a requested time window was discovered.

This slice adds a second, independent inventory input based on captured S3 `ListObjectVersions` responses. It reconciles every standard digest key in the requested window against the verified chain and exact current S3 version.

## Evidence inputs

The existing dual-signed FENCE-001 manifest must include:
- exactly one `CLOUDTRAIL_DIGEST_INVENTORY` artifact;
- one `CLOUDTRAIL_INVENTORY_PAGE` artifact per captured `ListObjectVersions` response;
- the existing CloudTrail verification report, digest, log and regional public-key artifacts.

The inventory index pins account, Region, bucket, digest prefix, requested time window, collection interval, pagination status and ordered page artifact references.

Each raw page artifact preserves the S3 response fields including:
- `Versions` and `DeleteMarkers`;
- `IsLatest` and `VersionId`;
- `KeyMarker`, `VersionIdMarker`;
- `NextKeyMarker`, `NextVersionIdMarker`;
- `IsTruncated`.

The manifest authenticates the raw inventory index and every raw page response.

## Reconciliation rules

1. Verify the dual-signed CloudTrail manifest and every materialized artifact.
2. Require inventory account, Region, bucket and digest prefix to agree with the signed CloudTrail report.
3. Require page markers to form one continuous sequence from the first page through a final `IsTruncated=false` page.
4. Require each page response's bucket, prefix, request markers, next markers and truncation flag to match the signed inventory index.
5. Reject duplicate object versions, null version IDs, malformed keys, missing `IsLatest` markers, or more than one latest version for a logical key.
6. Parse the digest-end timestamp from each standard or backfill digest key and filter by the requested window.
7. Require every standard digest key in the captured inventory window to appear in the verified digest chain.
8. Require every verified standard digest in the requested window to appear in the inventory.
9. Require the report's S3 VersionId to equal the unique current `IsLatest` object version from the inventory.
10. Reject a current delete marker for a digest key in the requested window.
11. Detect backfill digest keys separately. If any are present, require a matching verified `BACKFILL` report chain and exact latest S3 VersionId before overall captured-inventory completeness can be true.

## Result semantics

- `STANDARD_CHAIN_INVENTORY_RECONCILED`: every standard digest key in the captured inventory window matches the verified chain and exact current version; no backfill keys were found.
- `STANDARD_CHAIN_RECONCILED_BACKFILL_PRESENT`: standard digests reconcile, but backfill keys exist and are not verified by this standard-chain verifier.

Even the first status is deliberately scoped to the captured inventory. The result records:

`absoluteSnapshotCompleteness = NOT_PROVEN_NON_ATOMIC_LISTOBJECTVERSIONS_PAGINATION`

S3 `ListObjectVersions` pagination is not treated as an atomic snapshot across pages. A collector must preserve its collection interval, and production qualification will require a repeat inventory or an independently governed S3 Inventory snapshot plus an AWS CLI differential check. The reconciler does not claim that CloudTrail delivered every event or that no service-side delivery gap occurred outside the captured S3 scope.

## Synthetic validation

CI uses a dual-signed test-only manifest, synthetic gzip digest evidence and two synthetic `ListObjectVersions` pages. The pages split two versions of the same digest key across a continuation marker, verifying that page-token continuity and `IsLatest` reconciliation work across pagination.

Negative tests reject:
- broken pagination markers;
- a latest delete marker;
- an inventory latest-version mismatch;
- an unlinked digest key present in inventory;
- tampering with the signed inventory index bytes.

No AWS account, credentials, S3/CloudTrail API calls or cloud resources are used.
