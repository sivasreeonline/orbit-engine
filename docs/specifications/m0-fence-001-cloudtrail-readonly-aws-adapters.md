# FENCE-001 read-only AWS CloudTrail and S3 adapters

**Status:** Injected read-only adapter implementation with synthetic clients. No live AWS qualification.  
**Implementation:** `scripts/aws_cloudtrail_readonly_adapters.py`  
**Tests:** `scripts/test_m0_fence_cloudtrail_readonly_adapters.py`

## Purpose

The CloudTrail verifier and digest-inventory reconciler now have provider-neutral contracts. This slice adds concrete AWS SDK-shaped adapters while keeping credentials, sessions, clients and network access outside the module.

All AWS clients are injected by the caller. The module does not:
- discover credentials or profiles;
- create sessions or clients;
- assume roles;
- make calls during import or construction;
- create, update or delete cloud resources;
- perform S3 writes, restores or retention bypasses.

## Adapters

### `AwsCloudTrailPublicKeyProvider`

- Wraps an injected CloudTrail `list_public_keys` client.
- Pins the expected AWS Region and checks `client.meta.region_name` when available.
- Paginates using `NextToken`, rejects repeated/invalid tokens and caps page count.
- Normalizes DER `Value` bytes, accepting the SDK's bytes form and base64 string form.
- Preserves API request IDs in `last_request_ids`.
- Returns the regional public-key fingerprint and validity interval expected by the verifier.

### `S3VersionedEvidenceReader`

- Wraps an injected S3 `get_object` client.
- Pins one expected bucket and optional allowed key prefixes.
- Requests an explicit VersionId when supplied.
- Requires every response to contain an exact non-null VersionId and rejects a different version than requested.
- Reads and closes the response body, checks ContentLength and normalizes user metadata keys to lowercase.
- Performs read-only GetObject operations only.

### `S3ListObjectVersionsInventoryCollector`

- Wraps an injected S3 `list_object_versions` client.
- Pins bucket and the account/Region CloudTrail digest prefix.
- Paginates with `KeyMarker` and `VersionIdMarker`, rejecting repeated markers and incomplete/truncated final pages.
- Preserves every object version, delete marker, IsLatest flag, LastModified, ETag and storage class in normalized JSON page artifacts.
- Preserves request IDs and exact page continuation markers.
- Emits the inventory index and page artifact bytes in the format consumed by the existing manifest and inventory validators.

## Security boundary

The adapters accept only explicitly supplied clients and pinned scope. The SDK client may still carry credentials; caller governance must establish the AWS principal, account, role session and region before injecting it. This module does not prove those identities.

The S3 inventory uses paginated `ListObjectVersions`. Pagination is captured and reconciled, but it is not an atomic snapshot. A second inventory pass or independently governed S3 Inventory report remains necessary for stronger completeness evidence.

## Synthetic validation

CI uses fake clients with no AWS SDK session and no network access. Tests cover:
- regional public-key pagination and request IDs;
- wrong-region client rejection;
- exact-version GetObject and metadata normalization;
- wrong bucket/prefix and null-version rejection;
- two-page ListObjectVersions marker continuity;
- compatibility of the generated inventory index/pages with the existing completeness reconciler.

No AWS account, credentials, provider API calls or cloud resources are used.
