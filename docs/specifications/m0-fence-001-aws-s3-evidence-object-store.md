# FENCE-001 AWS S3 exact-version evidence adapter

**Status:** Synthetic adapter contract implementation only. No AWS account, credentials, bucket, or provider API is used by CI.  
**Implementation:** `scripts/aws_s3_evidence_object_store.py`  
**Synthetic test:** `scripts/test_m0_fence_aws_s3_evidence_object_store.py`  
**Shared contract:** `scripts/validate_m0_fence_evidence_object_store.py`

## Adapter behavior

The adapter implements the existing provider-neutral `EvidenceObjectStore` surface:

- `put_immutable`
- `get_exact_version`
- `head_exact_version`
- `delete_version`

The caller supplies separately constructed writer and verifier S3 clients. The adapter does not discover credentials, create a bucket, modify bucket policy, enable versioning, enable Object Lock, or change retention configuration.

At construction, the writer client must confirm that bucket versioning is `Enabled` and S3 Object Lock is `Enabled`. Any missing or unknown prerequisite fails closed.

### Deterministic idempotency key

S3 does not provide a multi-object transaction for an evidence object plus a separate idempotency ledger. This implementation avoids that split-write problem by deriving a deterministic physical object key from the SHA-256 of the caller's logical key and idempotency key:

```text
<prefix>/<sha256(idempotency-key)>
```

The object is created with `IfNoneMatch="*"`, explicit SHA-256 checksum, metadata binding the logical key/content/idempotency key/writer identity, COMPLIANCE Object Lock mode, and the requested retention deadline.

An exact retry addresses the same physical key. If the acknowledgement was lost or the conditional create reports that the key already exists, the adapter performs HEAD and accepts the existing object only when all metadata, byte count, retention mode, retention deadline and non-null VersionId match. A changed payload under the same idempotency key is rejected as an idempotency conflict. Different idempotency keys produce distinct physical keys, so later evidence writes cannot replace the earlier physical object.

The idempotency key is unique within the configured adapter prefix; its deterministic key is independent of the logical key so reuse against a different logical key is detected as a binding conflict. The returned `ObjectVersion.object_key` is the physical S3 key, not the original logical key. Evidence manifests must preserve that returned key and the exact S3 `VersionId`; callers must not reconstruct either value.

### Read and mutation boundary

- Exact reads always pass the explicit S3 `VersionId`; aliases such as `latest` and the null version are rejected.
- Readback uses the separately injected verifier client and requires the configured verifier identity, distinct from the writer identity.
- Exact-version metadata readback checks COMPLIANCE mode and exposes the stored digest, byte count, retention deadline and writer identity.
- `delete_version` is intentionally unavailable and always rejects. Retention-bypass testing belongs to the separately governed privileged-bypass harness, not this ordinary evidence writer.

The identity strings are configuration assertions, not proof of AWS principal identity. A future external qualification adapter must construct the writer and verifier clients from separately governed credentials and independently bind each to STS caller identity before treating the identities as evidence.

## Validation

CI runs the shared nine-case object-store conformance suite against a synthetic S3 API double, plus negative checks for mutable aliases, same-principal readback, expired retention and writer-identity mismatch.

The shared harness now uses a future retention deadline. Its former fixed Unix timestamp was in 1970 and could not be passed to a real Object Lock API; the corrected vector makes the contract usable by a future real provider adapter.

These tests validate adapter request construction and contract behavior only. They do not prove managed S3 semantics, IAM separation, provider-enforced retention, administrative bypass resistance, cross-account independence, remote durability, replication, restore, or CloudTrail audit completeness.

## Explicitly deferred

- No `create_adapter` live factory is provided.
- No AWS credentials or sessions are discovered.
- No bucket or object is created in AWS.
- No real S3 or S3-compatible endpoint is called.
- No Object Lock configuration, bucket policy, retention, lifecycle, replication or CloudTrail setting is changed.
- No privileged delete/bypass or restore test is executed.
- Production approval remains false and host admission remains disabled.

The next provider-qualification slice must add a separate read-only S3 environment preflight and a run-bound live-write approval contract before any disposable-account write is considered.
