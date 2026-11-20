#!/usr/bin/env python3
"""Synthetic-only tests for the FENCE-001 S3 exact-version adapter.

The fake implements only the S3 API calls used by the adapter. It does not
model AWS IAM, Object Lock enforcement, remote durability or provider behavior.
"""
from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone
from typing import Any

from aws_s3_evidence_object_store import S3EvidenceObjectStore
from validate_m0_fence_evidence_object_store import run_conformance


class FakeS3Error(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3Backend:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.current: dict[tuple[str, str], str] = {}


class FakeS3Client:
    def __init__(self, backend: FakeS3Backend) -> None:
        self.backend = backend

    def get_bucket_versioning(self, *, Bucket: str) -> dict[str, str]:
        return {"Status": "Enabled"}

    def get_object_lock_configuration(self, *, Bucket: str) -> dict[str, Any]:
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        bucket, key = kwargs["Bucket"], kwargs["Key"]
        current_key = (bucket, key)
        if kwargs.get("IfNoneMatch") == "*" and current_key in self.backend.current:
            raise FakeS3Error("PreconditionFailed")
        version_id = "fake-" + uuid.uuid4().hex
        body = kwargs["Body"]
        self.backend.objects[(bucket, key, version_id)] = {
            "Body": body,
            "Metadata": dict(kwargs["Metadata"]),
            "ObjectLockMode": kwargs["ObjectLockMode"],
            "ObjectLockRetainUntilDate": kwargs["ObjectLockRetainUntilDate"],
            "ContentLength": kwargs["ContentLength"],
        }
        self.backend.current[current_key] = version_id
        return {"VersionId": version_id}

    def head_object(self, *, Bucket: str, Key: str, VersionId: str | None = None) -> dict[str, Any]:
        version = VersionId or self.backend.current.get((Bucket, Key))
        if version is None:
            raise FakeS3Error("NoSuchKey")
        item = self.backend.objects.get((Bucket, Key, version))
        if item is None:
            raise FakeS3Error("NoSuchVersion")
        return {key: value for key, value in item.items() if key != "Body"} | {"VersionId": version}

    def get_object(self, *, Bucket: str, Key: str, VersionId: str) -> dict[str, Any]:
        item = self.backend.objects.get((Bucket, Key, VersionId))
        if item is None:
            raise FakeS3Error("NoSuchVersion")
        return {"Body": io.BytesIO(item["Body"])}


def adapter_factory() -> S3EvidenceObjectStore:
    backend = FakeS3Backend()
    return S3EvidenceObjectStore(
        FakeS3Client(backend),
        FakeS3Client(backend),
        bucket_name="synthetic-fence-evidence",
        key_prefix="qualification-test",
        writer_identity="synthetic-collector",
        verifier_identity="synthetic-verifier",
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_negative_tests() -> None:
    backend = FakeS3Backend()
    writer = FakeS3Client(backend)
    verifier = FakeS3Client(backend)
    store = S3EvidenceObjectStore(
        writer, verifier, bucket_name="synthetic-fence-evidence",
        key_prefix="qualification-test", writer_identity="synthetic-collector",
        verifier_identity="synthetic-verifier",
    )

    try:
        S3EvidenceObjectStore(
            writer, verifier, bucket_name="synthetic-fence-evidence",
            key_prefix="qualification-test", writer_identity="synthetic-collector",
            verifier_identity="synthetic-verifier",
        )
        # Construction is valid for enabled versioning and Object Lock.
    except Exception as error:
        raise AssertionError(f"valid synthetic bucket prerequisites were rejected: {error}")

    try:
        store.get_exact_version("key", "latest", reader_identity="synthetic-verifier")
    except ValueError:
        pass
    else:
        raise AssertionError("mutable latest alias was accepted as an exact version")

    try:
        store.get_exact_version("key", "v1", reader_identity="synthetic-collector")
    except PermissionError:
        pass
    else:
        raise AssertionError("writer identity was accepted as independent verifier")

    try:
        store.put_immutable(
            "logical/key", b"payload",
            retention_until=int(datetime.now(timezone.utc).timestamp()) - 60,
            idempotency_key="expired-retention",
            writer_identity="synthetic-collector",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("expired retention deadline was accepted")

    try:
        store.put_immutable(
            "logical/key", b"payload",
            retention_until=int(datetime.now(timezone.utc).timestamp()) + 3600,
            idempotency_key="wrong-writer",
            writer_identity="different-writer",
        )
    except PermissionError:
        pass
    else:
        raise AssertionError("unconfigured writer identity was accepted")

    print("PASS S3 adapter rejects mutable aliases, same-principal readback, expired retention and writer mismatch")


def main() -> None:
    results = run_conformance(adapter_factory)
    failures = [item for item in results if not item.passed]
    for item in results:
        print(f"{'PASS' if item.passed else 'FAIL'} {item.name}: {item.detail}")
    print(f"S3 evidence object-store contract cases: {len(results)}; passed: {len(results) - len(failures)}; failed: {len(failures)}")
    if failures:
        raise SystemExit(1)
    run_negative_tests()
    print("Synthetic S3 adapter tests passed; no AWS credentials or provider APIs were used.")


if __name__ == "__main__":
    main()
