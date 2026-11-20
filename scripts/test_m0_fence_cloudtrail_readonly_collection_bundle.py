#!/usr/bin/env python3
"""Synthetic-only integration tests for the read-only CloudTrail collection bundle."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Any
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from aws_cloudtrail_readonly_collection_bundle import AwsCloudTrailReadOnlyCollection


ACCOUNT = "123456789012"
REGION = "us-east-1"
BUCKET = "synthetic-evidence-bucket"
PREFIX = f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/"
LOG_PREFIX = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/"
DIGEST_KEY = (
    f"{PREFIX}2026/11/20/{ACCOUNT}_CloudTrail-Digest_{REGION}_"
    f"synthetic-trail_{REGION}_20261120T010000Z.json.gz"
)
LOG_KEY = f"{LOG_PREFIX}2026/11/20/synthetic-log.json.gz"
START = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 20, 2, 0, tzinfo=timezone.utc)
KEY_START = datetime(2026, 11, 19, tzinfo=timezone.utc)
KEY_END = datetime(2026, 11, 21, tzinfo=timezone.utc)
FINGERPRINT = "synthetic-fingerprint-001"


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signature(private_key: Any, document: dict[str, Any], uncompressed: bytes) -> str:
    data = (
        f"{document['digestEndTime']}\n{BUCKET}/{DIGEST_KEY}\n"
        f"{hashlib.sha256(uncompressed).hexdigest()}\nnull"
    ).encode("utf-8")
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256()).hex()


class FakeSts:
    def __init__(self, account: str, role: str, session: str, request_id: str) -> None:
        self.response = {
            "Account": account,
            "Arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session}",
            "UserId": f"AROA{role.upper()}IDENTITY:{session}",
            "ResponseMetadata": {"RequestId": request_id},
        }
        self.calls = 0

    def get_caller_identity(self) -> dict[str, Any]:
        self.calls += 1
        return self.response


class FakeCloudTrail:
    def __init__(self, der: bytes) -> None:
        self.meta = SimpleNamespace(region_name=REGION)
        self.der = der
        self.calls = 0

    def list_public_keys(self, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return {
            "PublicKeyList": [{
                "Fingerprint": FINGERPRINT,
                "Value": self.der,
                "ValidityStartTime": KEY_START,
                "ValidityEndTime": KEY_END,
            }],
            "ResponseMetadata": {"RequestId": "cloudtrail-listkeys-001"},
        }


class FakeS3:
    def __init__(self, objects: dict[str, tuple[bytes, str, dict[str, str]]]) -> None:
        self.objects = objects
        self.get_calls: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(kwargs)
        body, version, metadata = self.objects[kwargs["Key"]]
        if kwargs.get("VersionId") is not None and kwargs["VersionId"] != version:
            raise ValueError("wrong version")
        return {
            "Body": io.BytesIO(body),
            "VersionId": version,
            "ContentLength": len(body),
            "Metadata": metadata,
            "ResponseMetadata": {"RequestId": f"s3-get-{len(self.get_calls):03d}"},
        }

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
        self.list_calls.append(kwargs)
        return {
            "Name": BUCKET,
            "Prefix": PREFIX,
            "IsTruncated": False,
            "Versions": [{
                "Key": DIGEST_KEY,
                "VersionId": "digest-version-001",
                "IsLatest": True,
                "LastModified": datetime(2026, 11, 20, 1, 1, tzinfo=timezone.utc),
                "Size": len(self.objects[DIGEST_KEY][0]),
                "ETag": '"synthetic-etag"',
                "StorageClass": "STANDARD",
            }],
            "DeleteMarkers": [],
            "ResponseMetadata": {"RequestId": "s3-listversions-001"},
        }


def make_collection() -> tuple[AwsCloudTrailReadOnlyCollection, FakeSts, FakeSts, FakeCloudTrail, FakeS3]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    log_content = b'{"Records":[{"eventName":"SyntheticEvent","eventSource":"fixture.amazonaws.com"}]}'
    log_gzip = gzip.compress(log_content, mtime=0)
    document = {
        "awsAccountId": ACCOUNT,
        "digestStartTime": "2026-11-20T00:00:00Z",
        "digestEndTime": "2026-11-20T01:00:00Z",
        "digestS3Bucket": BUCKET,
        "digestS3Object": DIGEST_KEY,
        "digestPublicKeyFingerprint": FINGERPRINT,
        "digestSignatureAlgorithm": "SHA256withRSA",
        "previousDigestS3Bucket": None,
        "previousDigestS3Object": None,
        "previousDigestHashValue": None,
        "previousDigestHashAlgorithm": None,
        "previousDigestSignature": None,
        "logFiles": [{
            "s3Bucket": BUCKET,
            "s3Object": LOG_KEY,
            "hashValue": hashlib.sha256(log_content).hexdigest(),
            "hashAlgorithm": "SHA-256",
        }],
    }
    raw_digest = json_bytes(document)
    digest_signature = signature(private_key, document, raw_digest)
    digest_gzip = gzip.compress(raw_digest, mtime=0)
    s3 = FakeS3({
        DIGEST_KEY: (digest_gzip, "digest-version-001", {"signature": digest_signature}),
        LOG_KEY: (log_gzip, "log-version-001", {}),
    })
    collector_sts = FakeSts(ACCOUNT, "evidence-collector", "collector-session", "sts-collector-001")
    verifier_sts = FakeSts(ACCOUNT, "evidence-verifier", "verifier-session", "sts-verifier-001")
    cloudtrail = FakeCloudTrail(der)
    collection = AwsCloudTrailReadOnlyCollection(
        sts_collector_client=collector_sts,
        sts_verifier_client=verifier_sts,
        cloudtrail_client=cloudtrail,
        s3_client=s3,
        account_id=ACCOUNT,
        region=REGION,
        bucket=BUCKET,
        digest_prefix=PREFIX,
        collector_role_arn=f"arn:aws:iam::{ACCOUNT}:role/skyhigh/evidence-collector",
        verifier_role_arn=f"arn:aws:iam::{ACCOUNT}:role/skyhigh/evidence-verifier",
        log_prefixes=(LOG_PREFIX,),
    )
    return collection, collector_sts, verifier_sts, cloudtrail, s3


def rejected(action, label: str) -> None:
    try:
        action()
    except (ValueError, TypeError):
        return
    raise AssertionError(f"expected fail-closed rejection: {label}")


def main() -> None:
    collection, collector_sts, verifier_sts, cloudtrail, s3 = make_collection()
    bundle = collection.collect(
        standard_latest=(BUCKET, DIGEST_KEY, "digest-version-001"),
        backfill_latest=None,
        requested_start_time=START,
        requested_end_time=END,
        test_only=True,
        collection_started_at=datetime(2026, 11, 20, 2, 5, tzinfo=timezone.utc),
        collection_completed_at=datetime(2026, 11, 20, 2, 6, tzinfo=timezone.utc),
    )
    summary = bundle.summary()
    assert summary["productionQualificationReady"] is False
    assert summary["manifestSigningStatus"] == "NOT_SIGNED"
    assert summary["completeWithinCapturedInventory"] is True
    assert bundle.verification_report["digestCount"] == 1
    assert bundle.verification_report["logCount"] == 1
    assert bundle.collector_identity["identityRole"] == "COLLECTOR"
    assert bundle.verifier_identity["identityRole"] == "INDEPENDENT_VERIFIER"
    assert collector_sts.calls == verifier_sts.calls == 1
    assert cloudtrail.calls == 1
    assert len(s3.list_calls) == 1
    assert any(name.startswith("cloudtrail-digest-") for name in bundle.artifacts)
    assert any(name.startswith("cloudtrail-log-") for name in bundle.artifacts)
    assert any(name.endswith(".der") for name in bundle.artifacts)
    assert "collection-bundle-index.json" in bundle.artifacts
    print("PASS read-only collection bundle binds STS identities, exact S3 versions, digest/log bytes and inventory")

    rejected(
        lambda: AwsCloudTrailReadOnlyCollection(
            sts_collector_client=collector_sts,
            sts_verifier_client=verifier_sts,
            cloudtrail_client=cloudtrail,
            s3_client=s3,
            account_id=ACCOUNT,
            region=REGION,
            bucket=BUCKET,
            digest_prefix=PREFIX,
            collector_role_arn=f"arn:aws:iam::{ACCOUNT}:role/shared",
            verifier_role_arn=f"arn:aws:iam::{ACCOUNT}:role/shared",
            log_prefixes=(LOG_PREFIX,),
        ),
        "same configured IAM role",
    )
    rejected(
        lambda: collection.collect(
            standard_latest=(BUCKET, DIGEST_KEY, "null"),
            backfill_latest=None,
            requested_start_time=START,
            requested_end_time=END,
            test_only=True,
        ),
        "null exact digest VersionId",
    )
    print("PASS shared role and null-version requests fail closed")
    print("Collection bundle tests passed; all AWS clients were synthetic and injected.")


if __name__ == "__main__":
    main()
