#!/usr/bin/env python3
"""Fail-closed S3 exact-version evidence object store for FENCE-001.

This adapter is dependency-injected: constructing it requires separately
configured writer and verifier S3 clients. It never creates buckets, changes
bucket policy, changes retention configuration, or discovers credentials.
The returned object_key is the physical, deterministic S3 key used for this
idempotency binding; manifests must store that key and the exact VersionId.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from typing import Any


SAFE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!_.*'()/:-]{0,199}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_OBJECT_LOCK_MODE = "COMPLIANCE"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc_datetime(epoch_seconds: int) -> datetime:
    if type(epoch_seconds) is not int or epoch_seconds <= 0:
        raise ValueError("retention_until must be a positive Unix timestamp")
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)


def _error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


class S3EvidenceObjectStore:
    """S3 adapter using conditional creation and exact version-addressed reads.

    A deterministic physical key is derived from the caller's logical key and
    idempotency key. If an acknowledgement is lost, retrying the same request
    targets the same key with IfNoneMatch='*'; the existing exact version is
    reconciled by HEAD and metadata comparison rather than creating a version.
    Different idempotency keys receive distinct physical keys, preserving each
    immutable artifact independently.
    """

    def __init__(
        self,
        writer_client: Any,
        verifier_client: Any,
        *,
        bucket_name: str,
        key_prefix: str,
        writer_identity: str,
    ) -> None:
        if not isinstance(bucket_name, str) or not bucket_name.strip():
            raise ValueError("bucket_name is required")
        if not isinstance(key_prefix, str) or not SAFE_PREFIX.fullmatch(key_prefix):
            raise ValueError("key_prefix must be a safe non-empty S3 prefix")
        if not isinstance(writer_identity, str) or not writer_identity.strip():
            raise ValueError("writer_identity is required")
        if writer_client is None or verifier_client is None:
            raise ValueError("separate writer and verifier S3 clients are required")
        if writer_client is verifier_client:
            raise ValueError("writer and verifier clients must be distinct instances")

        self._writer = writer_client
        self._verifier = verifier_client
        self._bucket = bucket_name
        self._prefix = key_prefix.rstrip("/")
        self._writer_identity = writer_identity
        self._verify_bucket_prerequisites()

    def _verify_bucket_prerequisites(self) -> None:
        versioning = self._writer.get_bucket_versioning(Bucket=self._bucket)
        if versioning.get("Status") != "Enabled":
            raise RuntimeError("evidence bucket versioning must be Enabled")
        lock = self._writer.get_object_lock_configuration(Bucket=self._bucket)
        configuration = lock.get("ObjectLockConfiguration", {})
        if configuration.get("ObjectLockEnabled") != "Enabled":
            raise RuntimeError("evidence bucket Object Lock must be enabled")

    def _physical_key(self, object_key: str, idempotency_key: str) -> str:
        if not isinstance(object_key, str) or not object_key.strip():
            raise ValueError("object_key must be non-empty")
        if len(object_key.encode("utf-8")) > 1024:
            raise ValueError("object_key exceeds 1024 UTF-8 bytes")
        if any(ord(char) < 32 or ord(char) == 127 for char in object_key):
            raise ValueError("object_key contains a control character")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("idempotency_key must be non-empty")
        if len(idempotency_key.encode("utf-8")) > 512:
            raise ValueError("idempotency_key exceeds 512 UTF-8 bytes")

        logical_hash = _sha256(object_key.encode("utf-8"))
        idempotency_hash = _sha256(idempotency_key.encode("utf-8"))
        return f"{self._prefix}/{logical_hash}/{idempotency_hash}"

    @staticmethod
    def _metadata(
        *,
        logical_key: str,
        content: bytes,
        idempotency_key: str,
        writer_identity: str,
    ) -> dict[str, str]:
        return {
            "fence-logical-key-sha256": _sha256(logical_key.encode("utf-8")),
            "fence-content-sha256": _sha256(content),
            "fence-byte-count": str(len(content)),
            "fence-idempotency-sha256": _sha256(idempotency_key.encode("utf-8")),
            "fence-writer-identity": writer_identity,
        }

    def _head_existing(
        self,
        physical_key: str,
        expected_metadata: dict[str, str],
        expected_retention: datetime,
    ) -> dict[str, Any]:
        head = self._writer.head_object(Bucket=self._bucket, Key=physical_key)
        actual_metadata = head.get("Metadata", {})
        for name, expected in expected_metadata.items():
            if actual_metadata.get(name) != expected:
                raise RuntimeError("existing S3 object does not match the exact idempotent request")
        if head.get("ObjectLockMode") != REQUIRED_OBJECT_LOCK_MODE:
            raise RuntimeError("existing S3 object is not protected by COMPLIANCE retention")
        actual_retention = head.get("ObjectLockRetainUntilDate")
        if not isinstance(actual_retention, datetime):
            raise RuntimeError("existing S3 object is missing its retention deadline")
        if actual_retention.tzinfo is None:
            actual_retention = actual_retention.replace(tzinfo=timezone.utc)
        if actual_retention < expected_retention:
            raise RuntimeError("existing S3 object retention is shorter than requested")
        version_id = head.get("VersionId")
        if not isinstance(version_id, str) or not version_id or version_id == "null":
            raise RuntimeError("S3 did not return an immutable VersionId")
        if head.get("ContentLength") != int(expected_metadata["fence-byte-count"]):
            raise RuntimeError("existing S3 object byte count differs from the requested content")
        return head

    def put_immutable(
        self,
        object_key: str,
        content: bytes,
        *,
        retention_until: int,
        idempotency_key: str,
        writer_identity: str,
    ) -> Any:
        # Imported lazily so synthetic contract tests do not need an AWS session.
        from validate_m0_fence_evidence_object_store import ObjectVersion

        if not isinstance(content, bytes) or not content:
            raise ValueError("evidence content must be non-empty bytes")
        if not isinstance(writer_identity, str) or writer_identity != self._writer_identity:
            raise PermissionError("writer identity does not match the configured writer principal")
        retention = _utc_datetime(retention_until)
        now = datetime.now(timezone.utc)
        if retention <= now:
            raise ValueError("retention_until must be in the future")

        physical_key = self._physical_key(object_key, idempotency_key)
        metadata = self._metadata(
            logical_key=object_key,
            content=content,
            idempotency_key=idempotency_key,
            writer_identity=writer_identity,
        )
        checksum = base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")

        try:
            response = self._writer.put_object(
                Bucket=self._bucket,
                Key=physical_key,
                Body=content,
                ContentLength=len(content),
                ContentType="application/octet-stream",
                ChecksumSHA256=checksum,
                Metadata=metadata,
                ObjectLockMode=REQUIRED_OBJECT_LOCK_MODE,
                ObjectLockRetainUntilDate=retention,
                IfNoneMatch="*",
            )
            version_id = response.get("VersionId")
            if not isinstance(version_id, str) or not version_id or version_id == "null":
                raise RuntimeError("S3 put did not return an immutable VersionId")
            head = self._head_existing(physical_key, metadata, retention)
            if head.get("VersionId") != version_id:
                raise RuntimeError("S3 HEAD version differs from the successful PUT VersionId")
        except Exception as error:
            # A conditional conflict or lost acknowledgement is recoverable
            # only if HEAD proves that the exact deterministic object exists.
            try:
                head = self._head_existing(physical_key, metadata, retention)
            except Exception:
                raise error
            version_id = head["VersionId"]

        return ObjectVersion(
            object_key=physical_key,
            version_id=version_id,
            sha256=_sha256(content),
            byte_count=len(content),
        )

    def get_exact_version(self, object_key: str, version_id: str, *, reader_identity: str) -> bytes:
        if not isinstance(reader_identity, str) or not reader_identity.strip():
            raise PermissionError("independent verifier identity is required")
        if reader_identity == self._writer_identity:
            raise PermissionError("readback must use a distinct independent verifier identity")
        if not isinstance(version_id, str) or not version_id or version_id == "latest" or version_id == "null":
            raise ValueError("an exact non-null S3 VersionId is required")
        response = self._verifier.get_object(
            Bucket=self._bucket,
            Key=object_key,
            VersionId=version_id,
        )
        body = response.get("Body")
        if body is None:
            raise RuntimeError("S3 exact-version read returned no body")
        content = body.read()
        if not isinstance(content, bytes):
            raise RuntimeError("S3 exact-version read did not return bytes")
        return content

    def head_exact_version(self, object_key: str, version_id: str) -> Any:
        from validate_m0_fence_evidence_object_store import ObjectMetadata

        if not isinstance(version_id, str) or not version_id or version_id in {"latest", "null"}:
            raise ValueError("an exact non-null S3 VersionId is required")
        response = self._verifier.head_object(
            Bucket=self._bucket,
            Key=object_key,
            VersionId=version_id,
        )
        metadata = response.get("Metadata", {})
        mode = response.get("ObjectLockMode")
        retention = response.get("ObjectLockRetainUntilDate")
        if mode != REQUIRED_OBJECT_LOCK_MODE or not isinstance(retention, datetime):
            raise RuntimeError("exact S3 version lacks compliance retention metadata")
        if retention.tzinfo is None:
            retention = retention.replace(tzinfo=timezone.utc)
        return ObjectMetadata(
            object_key=object_key,
            version_id=version_id,
            sha256=metadata.get("fence-content-sha256", ""),
            byte_count=int(metadata.get("fence-byte-count", "-1")),
            retention_until=int(retention.timestamp()),
            object_lock_mode=mode,
            writer_identity=metadata.get("fence-writer-identity", ""),
        )

    def delete_version(self, object_key: str, version_id: str) -> None:
        # Deliberately no DeleteObject call is exposed by this adapter.
        raise PermissionError("evidence deletion is not an adapter capability; retention bypass requires a separate governed test")
