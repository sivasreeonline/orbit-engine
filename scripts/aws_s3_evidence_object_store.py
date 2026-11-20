#!/usr/bin/env python3
"""AWS S3 Object Lock adapter for the FENCE-001 immutable evidence contract.

The self-test uses a synthetic S3 API double only. Live mode is fail-closed and
requires two distinct AWS principals plus a run-bound approval tied to the
exact read-only preflight report. No bucket is created by this adapter.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import io
import json
import os
import re
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

LIVE_OPT_IN = "I_APPROVE_S3_COMPLIANCE_OBJECT_LOCK_CONFORMANCE_WRITES_TO_THIS_DISPOSABLE_BUCKET"
APPROVAL_PROFILE = "sky-high-fence-aws-s3-evidence-write-approval-v1"
APPROVAL_OPERATION = "AWS_S3_COMPLIANCE_EVIDENCE_OBJECT_STORE_WRITES"
MAX_FUTURE_SKEW = timedelta(minutes=2)
MAX_APPROVAL_WINDOW = timedelta(hours=8)
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
SAFE_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _contract_types():
    """Preserve class identity when imported by the provider-neutral harness."""
    main_module = sys.modules.get("__main__")
    required = ("ObjectIdempotencyConflict", "ObjectMutationDenied", "ObjectVersionNotFound",
                "ObjectVersion", "ObjectMetadata")
    if main_module is not None and all(hasattr(main_module, item) for item in required):
        return main_module
    return importlib.import_module("validate_m0_fence_evidence_object_store")


def _error_code(error: Exception) -> str | None:
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return None
    detail = response.get("Error", {})
    return detail.get("Code") if isinstance(detail, dict) else None


def _is_not_found(error: Exception) -> bool:
    return _error_code(error) in {"NoSuchKey", "NoSuchVersion", "NotFound", "404"}


def _utc_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{label} is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RuntimeError(f"{label} must be explicitly UTC")
    return parsed.astimezone(timezone.utc)


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"duplicate JSON member in qualification evidence: {key}")
        result[key] = value
    return result


def _read_json_object(path_value: str, label: str) -> tuple[dict[str, Any], bytes]:
    path = Path(path_value)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be an existing regular, non-symlink file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
        raise RuntimeError(f"{label} must be strict UTF-8 JSON without duplicate members") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must contain a top-level JSON object")
    return value, raw


def _load_run_bound_approval(config: dict[str, str]) -> None:
    approval, _ = _read_json_object(config["approvalFile"], "S3 evidence approval file")
    report, report_raw = _read_json_object(config["preflightReport"], "AWS read-only preflight report")
    now = datetime.now(timezone.utc)
    expected = {
        "profile": APPROVAL_PROFILE,
        "approvalId": config["approvalId"],
        "runId": config["runId"],
        "accountId": config["accountId"],
        "region": config["region"],
        "bucketName": config["bucketName"],
        "bucketArn": config["bucketArn"],
        "writerArn": config["writerArn"],
        "verifierArn": config["verifierArn"],
        "operation": APPROVAL_OPERATION,
        "preflightReportSha256": hashlib.sha256(report_raw).hexdigest(),
    }
    for field, value in expected.items():
        if approval.get(field) != value:
            raise RuntimeError(f"S3 evidence approval {field} does not match the pinned run scope")
    if not isinstance(approval.get("approvedBy"), str) or not approval["approvedBy"].strip():
        raise RuntimeError("S3 evidence approval must identify the approving operator")
    issued = _utc_timestamp(approval.get("issuedAt"), "approval issuedAt")
    expires = _utc_timestamp(approval.get("expiresAt"), "approval expiresAt")
    if issued > now + MAX_FUTURE_SKEW or expires <= now or issued >= expires:
        raise RuntimeError("S3 evidence approval is future-dated, expired or has an empty window")
    if expires - issued > MAX_APPROVAL_WINDOW:
        raise RuntimeError("S3 evidence approval window must not exceed eight hours")

    if report.get("result") != "READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION":
        raise RuntimeError("AWS read-only preflight is not ready for adapter implementation")
    if report.get("qualificationRunId") != config["runId"]:
        raise RuntimeError("AWS preflight run ID differs from approval")
    if report.get("accountId") != config["accountId"] or report.get("region") != config["region"]:
        raise RuntimeError("AWS preflight account/Region differs from approval")
    if report.get("readOnlyInspection") is not True:
        raise RuntimeError("AWS preflight report is not a read-only inspection")
    if report.get("resourcePins", {}).get("evidenceBucketName") != config["bucketName"]:
        raise RuntimeError("AWS preflight evidence bucket differs from approval")
    for field in ("resourceMutationsPerformed", "privilegedMutationAttemptsPerformed",
                  "restoreOperationsPerformed", "productionApproval", "hostAdmissionEnabled"):
        if report.get(field) is not False:
            raise RuntimeError("AWS preflight report does not preserve its no-mutation/no-admission boundary")


def _storage_key(prefix: str, object_key: str) -> tuple[str, str]:
    if not isinstance(object_key, str) or not object_key.strip() or len(object_key.encode("utf-8")) > 1024:
        raise ValueError("object_key must be non-empty and at most 1024 UTF-8 bytes")
    logical_hash = hashlib.sha256(object_key.encode("utf-8")).hexdigest()
    return f"{prefix.rstrip('/')}/{logical_hash[:2]}/{logical_hash}", logical_hash


def _physical_key(prefix: str, object_key: str, idempotency_key: str) -> tuple[str, str, str]:
    if not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key.encode("utf-8")) > 512:
        raise ValueError("idempotency_key must be non-empty and at most 512 UTF-8 bytes")
    key, logical_hash = _storage_key(prefix, object_key)
    idempotency_hash = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    # All logical versions of one caller key share one S3 key. The opaque
    # physical path never escapes through the public EvidenceObjectStore DTO.
    return key, logical_hash, idempotency_hash

class AWSS3EvidenceObjectStore:
    """S3 general-purpose bucket adapter using conditional immutable writes.

    Every put requires If-None-Match='*', Versioning and per-object COMPLIANCE
    retention. Exact reads and HEADs use a separate verifier client/principal.
    """

    def __init__(
        self, writer_client: Any, verifier_client: Any, bucket_name: str,
        writer_identity: str, verifier_identity: str, *, prefix: str = "skyhigh-fence-evidence/v1",
    ) -> None:
        if not bucket_name:
            raise ValueError("S3 bucket name is required")
        if not writer_identity.strip() or not verifier_identity.strip() or writer_identity == verifier_identity:
            raise ValueError("writer and independent verifier identities must be non-empty and distinct")
        self._writer = writer_client
        self._verifier = verifier_client
        self._bucket = bucket_name
        self._writer_identity = writer_identity
        self._verifier_identity = verifier_identity
        self._prefix = prefix

    def _head(self, object_key: str, version_id: str) -> dict[str, Any]:
        if not isinstance(version_id, str) or not version_id or version_id == "null" or version_id == "latest":
            raise _contract_types().ObjectVersionNotFound("an exact non-null S3 version ID is required")
        try:
            response = self._verifier.head_object(Bucket=self._bucket, Key=object_key, VersionId=version_id)
        except ClientError as exc:
            if _is_not_found(exc):
                raise _contract_types().ObjectVersionNotFound("exact S3 object version does not exist") from exc
            raise
        if response.get("VersionId") != version_id:
            raise RuntimeError("S3 HEAD returned a different version ID than requested")
        return response

    def _read(self, object_key: str, version_id: str) -> bytes:
        if not isinstance(version_id, str) or not version_id or version_id == "null" or version_id == "latest":
            raise _contract_types().ObjectVersionNotFound("an exact non-null S3 version ID is required")
        try:
            response = self._verifier.get_object(Bucket=self._bucket, Key=object_key, VersionId=version_id)
        except ClientError as exc:
            if _is_not_found(exc):
                raise _contract_types().ObjectVersionNotFound("exact S3 object version does not exist") from exc
            raise
        if response.get("VersionId") != version_id:
            raise RuntimeError("S3 GET returned a different version ID than requested")
        body = response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise RuntimeError("S3 exact-version GET returned no readable body")
        return body.read()

    def _metadata(self, object_key: str, version_id: str) -> Any:
        response = self._head(object_key, version_id)
        metadata = response.get("Metadata", {})
        mode = response.get("ObjectLockMode")
        retain_until = response.get("ObjectLockRetainUntilDate")
        if mode != "COMPLIANCE" or not isinstance(retain_until, datetime) or retain_until.tzinfo is None:
            raise RuntimeError("exact S3 object version is not under inspectable COMPLIANCE retention")
        sha = metadata.get("sha256", "")
        byte_count_text = metadata.get("byte-count", "")
        writer = metadata.get("writer-identity", "")
        if SHA256.fullmatch(sha) is None or not byte_count_text.isdigit() or not writer:
            raise RuntimeError("exact S3 object version lacks canonical integrity/writer metadata")
        byte_count = int(byte_count_text)
        if response.get("ContentLength") != byte_count:
            raise RuntimeError("S3 HEAD byte count differs from immutable metadata")
        return _contract_types().ObjectMetadata(
            object_key=object_key,
            version_id=version_id,
            sha256=sha,
            byte_count=byte_count,
            retention_until=int(retain_until.timestamp()),
            object_lock_mode=mode,
            writer_identity=writer,
        )

    def _version_from_existing(
        self, object_key: str, public_object_key: str, version_id: str, *, requested_sha: str,
        requested_bytes: bytes, logical_hash: str, idempotency_hash: str,
        requested_retention: int, writer_identity: str,
    ) -> Any:
        metadata = self._metadata(object_key, version_id)
        raw_head = self._head(object_key, version_id)
        user_metadata = raw_head.get("Metadata", {})
        if user_metadata.get("idempotency-key-sha256") != idempotency_hash:
            raise _contract_types().ObjectIdempotencyConflict("S3 idempotency key is already bound to another record")
        if user_metadata.get("logical-object-key-sha256") != logical_hash:
            raise _contract_types().ObjectIdempotencyConflict("S3 idempotency key is already bound to another object key")
        if metadata.sha256 != requested_sha or metadata.byte_count != len(requested_bytes):
            raise _contract_types().ObjectIdempotencyConflict("S3 idempotency key is already bound to different bytes")
        if metadata.writer_identity != writer_identity:
            raise _contract_types().ObjectIdempotencyConflict("S3 idempotency retry changed the writer identity")
        if metadata.object_lock_mode != "COMPLIANCE" or metadata.retention_until < requested_retention:
            raise RuntimeError("existing exact S3 version does not satisfy requested compliance retention")
        stored = self._read(object_key, version_id)
        if stored != requested_bytes or hashlib.sha256(stored).hexdigest() != requested_sha:
            raise _contract_types().ObjectIdempotencyConflict("S3 exact version bytes differ from the idempotent retry")
        return _contract_types().ObjectVersion(public_object_key, version_id, requested_sha, len(requested_bytes))

    def _find_idempotency_version(
        self, object_key: str, public_object_key: str, *, requested_sha: str, requested_bytes: bytes,
        logical_hash: str, idempotency_hash: str, requested_retention: int,
        writer_identity: str,
    ) -> Any | None:
        response = self._verifier.list_object_versions(
            Bucket=self._bucket, Prefix=object_key, MaxKeys=1000
        )
        if response.get("IsTruncated") is True:
            raise RuntimeError("S3 version history exceeds 1000 entries; refusing incomplete idempotency lookup")
        matches: list[Any] = []
        for item in response.get("Versions", []):
            if item.get("Key") != object_key:
                continue
            version_id = item.get("VersionId")
            if not version_id or version_id == "null":
                raise RuntimeError("S3 version listing contains a null version ID")
            head = self._head(object_key, version_id)
            metadata = head.get("Metadata", {})
            if metadata.get("idempotency-key-sha256") == idempotency_hash:
                matches.append(self._version_from_existing(
                    object_key, public_object_key, version_id, requested_sha=requested_sha, requested_bytes=requested_bytes,
                    logical_hash=logical_hash, idempotency_hash=idempotency_hash,
                    requested_retention=requested_retention, writer_identity=writer_identity,
                ))
        if len(matches) > 1:
            raise _contract_types().ObjectIdempotencyConflict(
                "S3 version history contains multiple versions for the same idempotency key"
            )
        return matches[0] if matches else None

    def _current_etag(self, object_key: str) -> str | None:
        try:
            current = self._verifier.head_object(Bucket=self._bucket, Key=object_key)
        except ClientError as exc:
            if _is_not_found(exc):
                return None
            raise
        version_id = current.get("VersionId")
        etag = current.get("ETag")
        if not version_id or version_id == "null" or not isinstance(etag, str) or not etag:
            raise RuntimeError("current S3 object lacks a non-null version ID or ETag")
        return etag

    def put_immutable(
        self, object_key: str, content: bytes, *, retention_until: int,
        idempotency_key: str, writer_identity: str,
    ) -> Any:
        if not isinstance(content, bytes) or not content:
            raise ValueError("evidence content must be non-empty bytes")
        if writer_identity != self._writer_identity:
            raise PermissionError("evidence write identity differs from the authenticated S3 writer principal")
        if type(retention_until) is not int or retention_until <= int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("retention_until must be a future UTC Unix timestamp")
        key, logical_hash, idempotency_hash = _physical_key(self._prefix, object_key, idempotency_key)
        sha = hashlib.sha256(content).hexdigest()
        checksum = base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")
        retain_until = datetime.fromtimestamp(retention_until, timezone.utc)
        metadata = {
            "sha256": sha,
            "byte-count": str(len(content)),
            "writer-identity": writer_identity,
            "logical-object-key-sha256": logical_hash,
            "idempotency-key-sha256": idempotency_hash,
        }

        # S3 object versioning is the history mechanism: first put is conditional
        # on absence; subsequent logical versions are conditional on the exact
        # current ETag. A 409/412 refreshes the history and retries only a bounded
        # number of times. Exact idempotency retries return the original VersionId.
        for _attempt in range(5):
            prior = self._find_idempotency_version(
                key, object_key, requested_sha=sha, requested_bytes=content, logical_hash=logical_hash,
                idempotency_hash=idempotency_hash, requested_retention=retention_until,
                writer_identity=writer_identity,
            )
            if prior is not None:
                return prior

            current_etag = self._current_etag(key)
            request = {
                "Bucket": self._bucket,
                "Key": key,
                "Body": content,
                "ContentLength": len(content),
                "ContentType": "application/octet-stream",
                "ChecksumSHA256": checksum,
                "ObjectLockMode": "COMPLIANCE",
                "ObjectLockRetainUntilDate": retain_until,
                "Metadata": metadata,
            }
            if current_etag is None:
                request["IfNoneMatch"] = "*"
            else:
                request["IfMatch"] = current_etag
            try:
                response = self._writer.put_object(**request)
            except ClientError as exc:
                if _error_code(exc) in {"PreconditionFailed", "ConditionalRequestConflict", "412", "409"}:
                    continue
                raise

            version_id = response.get("VersionId")
            if not isinstance(version_id, str) or not version_id or version_id == "null":
                raise RuntimeError("S3 PutObject returned no immutable VersionId")
            return _contract_types().ObjectVersion(object_key, version_id, sha, len(content))

        # A bounded optimistic retry is safer than silently falling back to a
        # non-conditional write when concurrent version creators keep racing.
        prior = self._find_idempotency_version(
            key, object_key, requested_sha=sha, requested_bytes=content, logical_hash=logical_hash,
            idempotency_hash=idempotency_hash, requested_retention=retention_until,
            writer_identity=writer_identity,
        )
        if prior is not None:
            return prior
        raise RuntimeError("S3 conditional version append kept conflicting; no non-conditional fallback was attempted")
    def get_exact_version(self, object_key: str, version_id: str, *, reader_identity: str) -> bytes:
        if reader_identity != self._verifier_identity or reader_identity == self._writer_identity:
            raise PermissionError("evidence readback must use the independently authenticated verifier principal")
        physical_key, _logical_hash = _storage_key(self._prefix, object_key)
        content = self._read(physical_key, version_id)
        metadata = self._metadata(physical_key, version_id)
        if len(content) != metadata.byte_count or hashlib.sha256(content).hexdigest() != metadata.sha256:
            raise RuntimeError("S3 exact-version readback failed SHA-256 or byte-count verification")
        return content

    def head_exact_version(self, object_key: str, version_id: str) -> Any:
        physical_key, _logical_hash = _storage_key(self._prefix, object_key)
        metadata = self._metadata(physical_key, version_id)
        return _contract_types().ObjectMetadata(
            object_key=object_key,
            version_id=metadata.version_id,
            sha256=metadata.sha256,
            byte_count=metadata.byte_count,
            retention_until=metadata.retention_until,
            object_lock_mode=metadata.object_lock_mode,
            writer_identity=metadata.writer_identity,
        )

    def delete_version(self, object_key: str, version_id: str) -> None:
        physical_key, _logical_hash = _storage_key(self._prefix, object_key)
        metadata = self._metadata(physical_key, version_id)
        if metadata.object_lock_mode != "COMPLIANCE" or metadata.retention_until <= int(datetime.now(timezone.utc).timestamp()):
            raise RuntimeError("refusing to characterize a non-retained or expired S3 object as protected")
        try:
            self._writer.delete_object(
                Bucket=self._bucket,
                Key=physical_key,
                VersionId=version_id,
                BypassGovernanceRetention=True,
            )
        except ClientError as exc:
            if _error_code(exc) in {"AccessDenied", "InvalidRequest", "ObjectLockConfigurationNotFoundError"}:
                raise _contract_types().ObjectMutationDenied("S3 denied deletion of the COMPLIANCE-retained exact version") from exc
            raise
        raise RuntimeError("S3 deleted an exact version that was expected to remain COMPLIANCE-retained")


def _validate_live_bucket(s3_client: Any, bucket: str, region: str, retention_days: int) -> None:
    location = s3_client.get_bucket_location(Bucket=bucket).get("LocationConstraint") or "us-east-1"
    if location != region:
        raise RuntimeError("S3 evidence bucket Region differs from the pinned Region")
    versioning = s3_client.get_bucket_versioning(Bucket=bucket)
    if versioning.get("Status") != "Enabled":
        raise RuntimeError("S3 evidence bucket must have Versioning Enabled")
    lock = s3_client.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration", {})
    if lock.get("ObjectLockEnabled") != "Enabled":
        raise RuntimeError("S3 evidence bucket does not have Object Lock enabled")
    default = lock.get("Rule", {}).get("DefaultRetention", {})
    if default.get("Mode") != "COMPLIANCE":
        raise RuntimeError("S3 evidence bucket default retention must use COMPLIANCE mode")
    days = default.get("Days", 0)
    years = default.get("Years", 0)
    if days < retention_days and years < 1:
        raise RuntimeError("S3 evidence bucket default COMPLIANCE retention is shorter than the approved profile")
    public_block = s3_client.get_public_access_block(Bucket=bucket).get("PublicAccessBlockConfiguration", {})
    if any(public_block.get(field) is not True for field in (
        "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
    )):
        raise RuntimeError("S3 evidence bucket public-access-block configuration is incomplete")
    encryption = s3_client.get_bucket_encryption(Bucket=bucket).get("ServerSideEncryptionConfiguration", {})
    rules = encryption.get("Rules", [])
    algorithms = {
        item.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
        for item in rules
    }
    if not algorithms.intersection({"aws:kms", "AES256"}):
        raise RuntimeError("S3 evidence bucket must have explicit default KMS or AES256 encryption")


def create_store():
    """Create the live store only after explicit report-bound qualification approval."""
    if os.getenv("FENCE_AWS_S3_ENDPOINT_URL"):
        raise RuntimeError("custom S3 endpoints are not used by the live adapter factory; tests use a synthetic API double")
    if os.getenv("FENCE_AWS_S3_ALLOW_LIVE") != LIVE_OPT_IN:
        raise RuntimeError("live S3 evidence writes are disabled; explicit disposable qualification opt-in is required")

    config = {
        "accountId": os.getenv("FENCE_AWS_S3_EXPECTED_ACCOUNT_ID", ""),
        "region": os.getenv("FENCE_AWS_S3_REGION", ""),
        "bucketName": os.getenv("FENCE_AWS_S3_BUCKET_NAME", ""),
        "bucketArn": os.getenv("FENCE_AWS_S3_BUCKET_ARN", ""),
        "writerArn": os.getenv("FENCE_AWS_S3_EXPECTED_WRITER_ARN", ""),
        "verifierArn": os.getenv("FENCE_AWS_S3_EXPECTED_VERIFIER_ARN", ""),
        "runId": os.getenv("FENCE_AWS_S3_QUALIFICATION_RUN_ID", ""),
        "approvalId": os.getenv("FENCE_AWS_S3_APPROVAL_ID", ""),
        "preflightReport": os.getenv("FENCE_AWS_S3_PREFLIGHT_REPORT", ""),
        "approvalFile": os.getenv("FENCE_AWS_S3_APPROVAL_FILE", ""),
    }
    if not ACCOUNT_ID.fullmatch(config["accountId"]) or not config["region"]:
        raise RuntimeError("pinned 12-digit account ID and AWS Region are required")
    if not SAFE_BUCKET.fullmatch(config["bucketName"]):
        raise RuntimeError("a valid pinned general-purpose S3 bucket name is required")
    if config["bucketArn"] != f"arn:aws:s3:::{config['bucketName']}":
        raise RuntimeError("pinned S3 bucket ARN does not match bucket name")
    if not config["writerArn"] or not config["verifierArn"] or config["writerArn"] == config["verifierArn"]:
        raise RuntimeError("distinct exact writer and independent-verifier ARNs are required")
    if not SAFE_ID.fullmatch(config["runId"]) or not SAFE_ID.fullmatch(config["approvalId"]):
        raise RuntimeError("qualification run ID and approval ID must be safe identifiers")
    if not config["preflightReport"] or not config["approvalFile"]:
        raise RuntimeError("exact preflight report and report-bound approval file are required")
    _load_run_bound_approval(config)

    writer_profile = os.getenv("FENCE_AWS_S3_WRITER_PROFILE", "")
    verifier_profile = os.getenv("FENCE_AWS_S3_VERIFIER_PROFILE", "")
    if not writer_profile or not verifier_profile or writer_profile == verifier_profile:
        raise RuntimeError("separate explicit AWS writer and verifier profiles are required")
    writer_session = boto3.Session(profile_name=writer_profile, region_name=config["region"])
    verifier_session = boto3.Session(profile_name=verifier_profile, region_name=config["region"])
    writer_sts = writer_session.client("sts")
    verifier_sts = verifier_session.client("sts")
    writer_identity = writer_sts.get_caller_identity()
    verifier_identity = verifier_sts.get_caller_identity()
    for identity, expected, label in (
        (writer_identity, config["writerArn"], "writer"),
        (verifier_identity, config["verifierArn"], "verifier"),
    ):
        if identity.get("Account") != config["accountId"] or identity.get("Arn") != expected:
            raise RuntimeError(f"live S3 {label} principal does not match pinned account/ARN")
    if writer_identity["Arn"] == verifier_identity["Arn"]:
        raise RuntimeError("S3 writer and independent verifier must be distinct principals")
    writer_client = writer_session.client("s3")
    verifier_client = verifier_session.client("s3")
    _validate_live_bucket(writer_client, config["bucketName"], config["region"], 7)
    return AWSS3EvidenceObjectStore(
        writer_client, verifier_client, config["bucketName"],
        writer_identity["Arn"], verifier_identity["Arn"],
    )


class _FakeS3State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.versions: dict[str, list[dict[str, Any]]] = {}


class _FakeS3Body(io.BytesIO):
    pass


class FakeS3Client:
    """Thread-safe S3 request double; it does not implement real Object Lock."""

    def __init__(self, state: _FakeS3State) -> None:
        self._state = state
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @staticmethod
    def _error(code: str, message: str = "synthetic S3 response") -> ClientError:
        return ClientError({"Error": {"Code": code, "Message": message},
                            "ResponseMetadata": {"HTTPStatusCode": 412 if code == "PreconditionFailed" else 403}},
                           "SyntheticS3")

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put_object", kwargs))
        if ("IfNoneMatch" not in kwargs and "IfMatch" not in kwargs) or kwargs.get("ObjectLockMode") != "COMPLIANCE":
            raise AssertionError("S3 writes must use If-None-Match or If-Match and request COMPLIANCE Object Lock")
        if kwargs.get("ChecksumSHA256") != base64.b64encode(hashlib.sha256(kwargs["Body"]).digest()).decode("ascii"):
            raise AssertionError("S3 write checksum does not match the exact request bytes")
        key = kwargs["Key"]
        with self._state.lock:
            versions = self._state.versions.setdefault(key, [])
            current = versions[-1] if versions and not versions[-1].get("delete_marker") else None
            if "IfNoneMatch" in kwargs and current is not None:
                raise self._error("PreconditionFailed")
            if "IfMatch" in kwargs and (current is None or current["ETag"] != kwargs["IfMatch"]):
                raise self._error("PreconditionFailed")
            version_id = "s3-version-" + uuid.uuid4().hex
            record = {
                "Key": key,
                "VersionId": version_id,
                "ETag": '"' + hashlib.md5(kwargs["Body"]).hexdigest() + '"',
                "Body": bytes(kwargs["Body"]),
                "Metadata": dict(kwargs["Metadata"]),
                "ObjectLockMode": kwargs["ObjectLockMode"],
                "ObjectLockRetainUntilDate": kwargs["ObjectLockRetainUntilDate"],
                "ContentLength": kwargs["ContentLength"],
                "delete_marker": False,
            }
            versions.append(record)
            return {"VersionId": version_id, "ChecksumSHA256": kwargs["ChecksumSHA256"]}

    def _find(self, key: str, version_id: str | None = None) -> dict[str, Any]:
        versions = self._state.versions.get(key, [])
        if version_id is None:
            if not versions or versions[-1].get("delete_marker"):
                raise self._error("NoSuchKey")
            return versions[-1]
        for item in versions:
            if item.get("VersionId") == version_id and not item.get("delete_marker"):
                return item
        raise self._error("NoSuchVersion")

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_object", kwargs))
        item = self._find(kwargs["Key"], kwargs.get("VersionId"))
        return {name: item[name] for name in (
            "VersionId", "ETag", "Metadata", "ObjectLockMode", "ObjectLockRetainUntilDate", "ContentLength"
        )}

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object", kwargs))
        item = self._find(kwargs["Key"], kwargs.get("VersionId"))
        return {"VersionId": item["VersionId"], "Body": _FakeS3Body(item["Body"])}

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_object_versions", kwargs))
        key = kwargs["Prefix"]
        versions = [dict(Key=item["Key"], VersionId=item["VersionId"])
                    for item in self._state.versions.get(key, []) if not item.get("delete_marker")]
        markers = [dict(Key=item["Key"], VersionId=item["VersionId"])
                   for item in self._state.versions.get(key, []) if item.get("delete_marker")]
        return {"Versions": versions, "DeleteMarkers": markers, "IsTruncated": False}

    def delete_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("delete_object", kwargs))
        if not kwargs.get("BypassGovernanceRetention"):
            raise AssertionError("deletion conformance probe must request governance bypass")
        item = self._find(kwargs["Key"], kwargs.get("VersionId"))
        if item["ObjectLockMode"] == "COMPLIANCE" and item["ObjectLockRetainUntilDate"] > datetime.now(timezone.utc):
            raise self._error("AccessDenied", "COMPLIANCE retention prevents version deletion")
        with self._state.lock:
            item["delete_marker"] = True
        return {"DeleteMarker": True}


def _approval_fixture() -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    report = {
        "result": "READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION",
        "qualificationRunId": "s3-qualification-001",
        "accountId": "123456789012",
        "region": "ap-south-2",
        "readOnlyInspection": True,
        "resourcePins": {"evidenceBucketName": "sky-high-evidence-qualification"},
        "resourceMutationsPerformed": False,
        "privilegedMutationAttemptsPerformed": False,
        "restoreOperationsPerformed": False,
        "productionApproval": False,
        "hostAdmissionEnabled": False,
    }
    expected = {
        "approvalId": "s3-approval-001",
        "runId": "s3-qualification-001",
        "accountId": "123456789012",
        "region": "ap-south-2",
        "bucketName": "sky-high-evidence-qualification",
        "bucketArn": "arn:aws:s3:::sky-high-evidence-qualification",
        "writerArn": "arn:aws:iam::123456789012:role/SkyHighEvidenceWriter",
        "verifierArn": "arn:aws:iam::123456789012:role/SkyHighEvidenceVerifier",
    }
    return {"report": report, "expected": expected, "now": now}


def _run_approval_self_test() -> None:
    import tempfile

    fixture = _approval_fixture()
    report_bytes = json.dumps(fixture["report"], sort_keys=True).encode("utf-8")
    expected = dict(fixture["expected"])
    now = fixture["now"]
    approval = {
        "profile": APPROVAL_PROFILE,
        "approvalId": expected["approvalId"],
        "runId": expected["runId"],
        "accountId": expected["accountId"],
        "region": expected["region"],
        "bucketName": expected["bucketName"],
        "bucketArn": expected["bucketArn"],
        "writerArn": expected["writerArn"],
        "verifierArn": expected["verifierArn"],
        "operation": APPROVAL_OPERATION,
        "preflightReportSha256": hashlib.sha256(report_bytes).hexdigest(),
        "approvedBy": "synthetic-bucket-owner",
        "issuedAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
    }
    with __import__("tempfile").TemporaryDirectory(prefix="fence-s3-approval-") as directory:
        report_path = Path(directory) / "preflight.json"
        approval_path = Path(directory) / "approval.json"
        report_path.write_bytes(report_bytes)
        approval_path.write_text(json.dumps(approval), encoding="utf-8")
        config = {**expected, "preflightReport": str(report_path), "approvalFile": str(approval_path)}
        _load_run_bound_approval(config)

        bad = dict(approval, bucketArn="arn:aws:s3:::substituted-bucket")
        approval_path.write_text(json.dumps(bad), encoding="utf-8")
        try:
            _load_run_bound_approval(config)
        except RuntimeError:
            pass
        else:
            raise AssertionError("S3 approval accepted bucket substitution")

        approval_path.write_text(json.dumps(approval), encoding="utf-8")
        report_path.write_text(json.dumps({**fixture["report"], "resourceMutationsPerformed": True}), encoding="utf-8")
        try:
            _load_run_bound_approval(config)
        except RuntimeError:
            pass
        else:
            raise AssertionError("S3 approval accepted modified/mutated preflight evidence")


def self_test() -> None:
    types = _contract_types()
    _run_approval_self_test()
    shared = _FakeS3State()
    writer = FakeS3Client(shared)
    verifier = FakeS3Client(shared)
    adapter_factory = lambda: AWSS3EvidenceObjectStore(
        writer, verifier, "sky-high-evidence-fixture",
        "collector-identity", "independent-verifier",
    )
    results = types.run_conformance(adapter_factory)
    failed = [item for item in results if not item.passed]
    for item in results:
        print(f"{'PASS' if item.passed else 'FAIL'} S3 evidence store {item.name}: {item.detail}")
    if failed:
        raise AssertionError(f"{len(failed)} S3 evidence object-store conformance cases failed")

    previous = os.environ.pop("FENCE_AWS_S3_ALLOW_LIVE", None)
    try:
        try:
            create_store()
        except RuntimeError as error:
            if "live S3 evidence writes are disabled" not in str(error):
                raise
        else:
            raise AssertionError("live S3 store factory opened without explicit opt-in")
    finally:
        if previous is not None:
            os.environ["FENCE_AWS_S3_ALLOW_LIVE"] = previous
    print("AWS S3 evidence object-store adapter self-test: PASS")
    print("Synthetic S3 API double only; no AWS credentials, sessions or provider calls were used.")
    print("Passing this test does not prove AWS Object Lock enforcement or privileged retention-bypass resistance.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    parser.error("use this module via FENCE_EVIDENCE_OBJECT_STORE_FACTORY=aws_s3_evidence_object_store:create_store")


if __name__ == "__main__":
    main()
