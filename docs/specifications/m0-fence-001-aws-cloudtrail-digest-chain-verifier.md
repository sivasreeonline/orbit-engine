# FENCE-001 AWS CloudTrail digest-chain verifier

**Status:** Offline synthetic verifier prototype. It is not yet an AWS-qualified implementation.  
**Implementation:** `scripts/verify_m0_fence_cloudtrail_digest_chain.py`  
**Synthetic tests:** `scripts/test_m0_fence_cloudtrail_digest_chain.py`

## Purpose

The existing provider audit-provenance contract verifies that a separately supplied provider verifier authenticates raw audit pages. It does not parse or verify AWS CloudTrail's native S3 digest chain. This slice adds an offline, dependency-injected verifier for the documented digest/signature/log-hash structure.

The verifier has no AWS SDK, credential discovery, network client, account access or provisioning path. It accepts:
- an `EvidenceReader` that returns object bytes, the exact S3 VersionId and object metadata;
- a regional `PublicKeyProvider` that returns CloudTrail `ListPublicKeys` records for a digest time range.

The test suite uses generated synthetic RSA keys and synthetic gzip objects only.

## Implemented checks

For each digest in the supplied latest-to-oldest chain, the verifier:

1. Requires the exact pinned account, Region and digest bucket.
2. Requires the digest's declared bucket/key to equal the location from which it was read.
3. Requires a non-null exact S3 VersionId for each digest and referenced log object.
4. Decompresses the digest JSON with compressed and uncompressed size limits and rejects duplicate JSON keys.
5. Validates the digest time interval and supported `SHA256withRSA` algorithm.
6. Retrieves regional CloudTrail public keys for the digest interval, matches the exact public-key fingerprint and checks its validity interval.
7. Verifies the RSA PKCS#1 v1.5 / SHA-256 digest signature.
8. Validates every referenced log object's pinned account/Region path and SHA-256 over its uncompressed bytes.
9. Follows the exact previous digest bucket/key/signature/hash binding, checks predecessor hash and chronological order, and rejects partial links, cycles and excessive chain depth.
10. Records exact object version IDs, hashes and byte counts in the verification report.

An empty `logFiles` array is valid; it represents a digest interval in which no log files were delivered. Standard and backfill digest chains are now verified through separate invocations. Backfill digest keys must end in `_backfill.json.gz`, and every backfill digest object must carry the S3 user metadata `backfill-generation-timestamp`. Regional public keys are requested for the one-hour window before and after that generation timestamp, matching the AWS CLI behavior. The report labels each digest `STANDARD` or `BACKFILL` and preserves the generation timestamp.

## Important AWS compatibility qualification

AWS documents the signature input as the digest end timestamp, original S3 bucket/key, SHA-256 of the current digest file content, and previous digest signature. It documents regional RSA public keys and SHA-256 hashes over uncompressed CloudTrail log contents.

The digest hash is computed over the decompressed digest JSON bytes. The starting-chain null `previousDigestSignature` is encoded as the literal string `null` in the signature input, matching the AWS CLI implementation in `awscli/customizations/cloudtrail/validation.py` (`Sha256RSADigestValidator._create_string_to_sign`). This is source-level compatibility evidence; a real independently acquired AWS digest fixture is still required before provider qualification. Do not use this prototype to issue a provider qualification PASS or make a production security claim.

Before any real qualification:
- run a differential fixture against AWS CLI `cloudtrail validate-logs` for the same exact digest objects, including a starting digest whose `previousDigestSignature` is null;
- test current digest signature metadata versus predecessor signatures carried in the next digest;
- test key rotation and overlapping regional public-key validity intervals;
- test standard and backfill chains separately;
- test delayed/out-of-order delivery, missing digest intervals, log deletion, digest deletion, wrong bucket/key, and version/delete-marker behavior;
- preserve the exact S3 VersionId for every digest and log object and independently bind the reader's AWS principal identity;
- bind the resulting report and all raw artifacts into the existing dual-signed FENCE-001 evidence manifest.

This verifier follows only the predecessor references reachable from the supplied latest digest. It does not enumerate S3 prefixes or prove that no unreferenced digest object exists; complete discovery and gap analysis remain separate evidence requirements.

## Synthetic validation

CI generates an ephemeral RSA key and a two-digest synthetic chain, then verifies:
- both digest signatures and predecessor hash binding;
- both referenced compressed log objects;
- exact S3 version IDs and regional public-key selection;
- rejection of tampered log bytes;
- rejection of a digest moved from its original key;
- rejection of a null S3 VersionId.

These tests establish deterministic verifier behavior against synthetic vectors only. They do not call AWS or qualify managed CloudTrail.
