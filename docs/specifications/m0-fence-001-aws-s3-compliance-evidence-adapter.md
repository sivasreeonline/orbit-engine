# FENCE-001 AWS S3 COMPLIANCE evidence object-store adapter

**Status:** Adapter implementation candidate with synthetic S3 API conformance tests. No AWS bucket, account, credential or provider qualification is connected.  
**Adapter:** `scripts/aws_s3_evidence_object_store.py`  
**Provider-neutral contract:** `scripts/validate_m0_fence_evidence_object_store.py`  
**Live mode:** Disabled by default; report-bound run approval and separate writer/verifier principals are mandatory.

## 1. Object/version model

The adapter implements the provider-neutral `EvidenceObjectStore` contract using an existing S3 general-purpose bucket with Versioning and Object Lock already enabled. It never creates or configures a bucket.

Each logical object key maps to one deterministic opaque S3 key under:

`skyhigh-fence-evidence/v1/<first-two-logical-key-hash-bytes>/<SHA-256(object_key)>`

Every logical version of that object uses the same S3 key and receives a distinct S3 `VersionId`. The idempotency key is recorded as a SHA-256 metadata binding on that immutable version; it is not part of the physical key. The logical object key and idempotency key are never written in plaintext S3 metadata. S3 user metadata records the content SHA-256, byte count, authenticated writer identity, logical-key hash and idempotency-key hash.

The returned `ObjectVersion` contains the physical S3 object key and the exact non-null S3 `VersionId`. Consumers must retain both. The adapter never substitutes a mutable `latest` alias.

## 2. Conditional immutable writes

The first version uses one `PutObject` request with `IfNoneMatch="*"`. A later logical version uses `IfMatch=<current ETag>`, creating a new S3 version only if the exact current predecessor is unchanged. Every request also specifies:
- `ObjectLockMode="COMPLIANCE"`;
- `ObjectLockRetainUntilDate` set to the requested future UTC deadline;
- explicit byte length and `ChecksumSHA256`;
- metadata binding the content hash, byte count, writer identity, logical-key hash and idempotency-key hash.

A successful response must return a non-empty, non-null `VersionId`. An absent/null version ID is an infrastructure/configuration failure, never accepted as an immutable object.

Before writing, the adapter searches the exact key's version history for the same idempotency-key hash. An exact retry returns the original version only when logical-key hash, writer identity, content digest, byte count and COMPLIANCE retention all match. If no prior version exists, it conditionally creates the first version with `IfNoneMatch`. If a prior version exists with a different idempotency key, it conditionally appends with `IfMatch` against the current ETag. A 409/412 conflict causes a bounded re-read/retry; after the retry limit, the adapter fails closed. If a delete marker hides the current object, exact version history is examined and old matching versions remain addressable by their VersionIds. It never retries with an unconditional PUT.

## 3. Exact-version verification and deletion probe

- `get_exact_version` requires the configured independent verifier identity and always calls `GetObject` with the exact S3 `VersionId`.
- `head_exact_version` uses the verifier client and requires the same exact version ID, COMPLIANCE lock mode, retention deadline, digest, byte count and writer metadata.
- The adapter independently recomputes SHA-256 and byte count from the retrieved bytes.
- `delete_version` addresses the exact version and requests the governance-bypass path as a negative probe. An S3 denial is mapped to `ObjectMutationDenied`; a successful deletion is a hard conformance failure.

The writer and verifier are separate AWS profiles with separately pinned exact role ARNs. The live factory resolves both through STS and rejects identical principals. The verifier client performs exact-version GET/HEAD operations; the writer client performs the put and negative-delete probe.

The verifier requires `s3:ListBucketVersions` for exact idempotency recovery and `s3:GetObjectVersion` for version-specific GET/HEAD. The writer requires `s3:PutObject` with conditional-write support and the permission to attempt the exact-version delete/bypass negative probe. The bucket must be a general-purpose versioned bucket (not a directory bucket or S3 on Outposts). The owner must review the exact IAM statements and bucket policy separately; adapter startup does not establish that a role policy is least-privilege.

A denied delete alone does not prove that COMPLIANCE retention caused the denial rather than an IAM permission denial. The external qualification procedure must ensure the probe principal has the permissions needed to attempt the operation and must preserve provider-native request/audit evidence. Independent privileged-bypass testing remains mandatory.

## 4. Live write gate

The adapter does not provision buckets, change bucket policies, enable versioning, configure Object Lock, set retention defaults or create IAM roles.

Without the exact `FENCE_AWS_S3_ALLOW_LIVE` opt-in token, the live factory refuses to initialize. Live mode also requires:
- exact 12-digit AWS account, Region, general-purpose bucket name and bucket ARN;
- exact writer and verifier role ARNs, with distinct profiles and distinct STS identities;
- a unique qualification run ID and approval ID;
- a non-symlink approval JSON file bound to the exact read-only preflight report bytes by SHA-256;
- an approval profile, scope, operation, approver identity and UTC validity interval no longer than eight hours;
- explicit account/Region/bucket pins matching the preflight report;
- preflight result `READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION`, read-only marker and false mutation/restore/production/admission flags;
- direct read-only checks showing bucket Region, Versioning Enabled, Object Lock enabled, default COMPLIANCE retention, complete Block Public Access and explicit default KMS/AES256 encryption.

The approval file is a local operator gate, not a signed security-review attestation. It does not replace FENCE-001 provider approval, independently verified evidence, trust-root governance, retention-bypass review or production authorization.

Live environment inputs:
- `FENCE_AWS_S3_ALLOW_LIVE`
- `FENCE_AWS_S3_EXPECTED_ACCOUNT_ID`
- `FENCE_AWS_S3_REGION`
- `FENCE_AWS_S3_BUCKET_NAME`
- `FENCE_AWS_S3_BUCKET_ARN`
- `FENCE_AWS_S3_EXPECTED_WRITER_ARN`
- `FENCE_AWS_S3_EXPECTED_VERIFIER_ARN`
- `FENCE_AWS_S3_WRITER_PROFILE`
- `FENCE_AWS_S3_VERIFIER_PROFILE`
- `FENCE_AWS_S3_QUALIFICATION_RUN_ID`
- `FENCE_AWS_S3_APPROVAL_ID`
- `FENCE_AWS_S3_PREFLIGHT_REPORT`
- `FENCE_AWS_S3_APPROVAL_FILE`

No credentials, approval files, account IDs or provider output belong in GitHub. No AWS account or credentials were used to implement or test this adapter.

## 5. Synthetic CI boundary

`python scripts/aws_s3_evidence_object_store.py --self-test` runs the nine existing provider-neutral object-store cases against a thread-safe synthetic S3 API double. It covers exact-version byte readback, idempotent retry, content/key binding, later-version immutability, COMPLIANCE metadata, denied exact-version deletion, independent verifier identity, concurrent conditional puts and no fallback to a latest alias. It also tests report-hash approval binding, bucket-scope mismatch, modified preflight report and default live-mode refusal.

The synthetic API double is not an S3 service emulator. The suite exercises first-version If-None-Match and successor If-Match request logic, but it does **not** qualify AWS S3, provider-enforced COMPLIANCE retention, IAM separation, retention-bypass resistance, privileged account administrators, bucket policy, replication, restore, audit completeness or durability. Passing CI is not provider qualification.

## 6. External qualification still required

Before any real provider qualification:
1. Obtain explicit account-owner and budget approval for a dedicated disposable bucket/account and test window.
2. Confirm the read-only preflight pins the exact bucket, compliance retention, versioning, encryption, public-access block and audit coverage.
3. Provision writer and verifier identities with separate trust principals and least-privilege policies; independently review the writer's conditional-write requirements and verifier read-only scope.
4. Run the provider-neutral nine-case harness against the exact S3 bucket using the two approved identities.
5. Preserve exact VersionIds, request IDs, raw responses, compliance metadata, retention deadlines, denied delete/bypass results and authenticated CloudTrail events as immutable evidence.
6. Perform the separately authorized privileged-retention-bypass, restore and failure-domain qualification; the ordinary adapter harness cannot replace these controls.
7. Obtain independent review of the exact adapter commit, bucket/account, roles, retention configuration and raw evidence.

Production approval and host admission remain false. This adapter does not authorize M0 runner execution or any student-code workload.

## 7. References

- [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [Botocore S3 PutObject API](https://docs.aws.amazon.com/botocore/latest/reference/services/s3/client/put_object.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
