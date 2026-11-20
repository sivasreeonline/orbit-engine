# FENCE-001 CloudTrail report-to-manifest custody binding

**Status:** Synthetic contract implementation. Not an AWS qualification result.  
**Depends on:** PR #165 offline CloudTrail digest-chain verifier prototype.  
**Validator:** `scripts/validate_m0_fence_cloudtrail_manifest_binding.py`

## Purpose

Bind the CloudTrail verifier's output and every raw source object needed to reproduce its result into the existing dual-Ed25519 FENCE-001 evidence manifest.

A successful signature/hash walk is not enough for evidence custody. The manifest must authenticate the exact bytes acquired, the exact S3 versions read, the regional public-key DER bytes, and the serialized verification report.

## Two distinct measurements

For digest and log objects, the verifier records both:
- SHA-256 and byte count of the exact compressed bytes returned by the injected evidence reader;
- SHA-256 and byte count of the decompressed bytes used by CloudTrail's cryptographic validation.

For public keys, it records SHA-256 and byte count of the DER-encoded PKCS#1 key bytes returned by the injected regional key provider, plus fingerprint and validity interval.

For every digest and log object, the report retains the exact non-null S3 VersionId. The manifest separately records the same version in `objectVersion`.

## Manifest artifact classes

The shared evidence manifest schema now recognizes:
- `CLOUDTRAIL_DIGEST`
- `CLOUDTRAIL_LOG`
- `CLOUDTRAIL_PUBLIC_KEY`
- `CLOUDTRAIL_VERIFICATION_REPORT`

CloudTrail test IDs are `CT-001` through `CT-006`. Required IDs are enforced by artifact class in the binding validator.

S3 object references use `s3://<bucket>/<key>` and their exact VersionId. Public-key evidence uses `cloudtrail-public-key://<region>/<fingerprint>` with a version string composed of the key validity interval. The verification report is itself a manifest artifact, so its exact serialized bytes are covered by the dual-signed manifest.

## Fail-closed binding checks

The validator:
1. Verifies the existing manifest schema, canonical digest and distinct collector/verifier Ed25519 attestations against independently supplied trusted keys.
2. Verifies all materialized artifact files against their manifest SHA-256 and byte counts, rejecting symlinks and path escapes.
3. Requires exactly one CloudTrail verification report artifact.
4. Checks report profile, schema version, testOnly flag, AWS account, Region and CloudTrail service against signed manifest scope.
5. Requires the report to state that chain and referenced-object verification succeeded while explicitly retaining `NOT_ESTABLISHED_BY_CHAIN_WALK` as its completeness status.
6. Requires every digest/log record to carry an exact non-null S3 VersionId and both raw and uncompressed measurements.
7. Requires each digest's regional public-key fingerprint, DER digest, DER byte count and validity interval.
8. Matches the report's full digest/log/public-key inventory exactly against manifest artifact type, object reference, object version, raw SHA-256 and byte count. Extra, duplicate or missing source artifacts fail.
9. Verifies the report's own raw serialized bytes against the manifest artifact record.

The manifest remains the single dual-signed custody envelope. No separate weaker unsigned mapping file is introduced.

## Important limits

- The chain verifier walks predecessor links reachable from the selected latest digest. It does not enumerate the S3 prefix or prove no unreferenced digest is missing.
- This binding proves that the local materialized bytes match the dual-signed manifest. It does not independently prove the AWS principal that acquired them, remote S3 Object Lock behavior, or provider-origin authenticity.
- The verifier currently excludes CloudTrail backfill chains; they require a separate chain profile.
- The verifier's byte-level signature and genesis handling still require comparison with the official AWS CLI `cloudtrail validate-logs` and an independently acquired real digest fixture.
- A valid manifest is not equivalent to a completed FENCE-001 provider qualification. `testOnly=true` is rejected for external qualification mode.

## Synthetic validation

CI creates ephemeral Ed25519 signing keys, a synthetic RSA public key and synthetic raw artifact files. It checks successful binding and rejects:
- tampered raw log bytes;
- a report that claims a null S3 VersionId;
- an account/Region mismatch between the report and signed manifest.

No AWS account, credentials, S3/CloudTrail API calls or cloud resources are used.
