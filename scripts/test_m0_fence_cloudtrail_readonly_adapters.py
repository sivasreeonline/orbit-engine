#!/usr/bin/env python3
"""Synthetic tests for read-only AWS CloudTrail/S3 adapters."""
from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from aws_cloudtrail_readonly_adapters import (
    AwsCloudTrailPublicKeyProvider,
    S3ListObjectVersionsInventoryCollector,
    S3VersionedEvidenceReader,
)
from validate_m0_fence_cloudtrail_digest_inventory import reconcile_inventory


ACCOUNT = "123456789012"
REGION = "us-east-1"
BUCKET = "synthetic-cloudtrail-bucket"
PREFIX = f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/"
DIGEST_KEY = f"{PREFIX}2026/11/20/{ACCOUNT}_CloudTrail-Digest_{REGION}_fixture_{REGION}_20261120T010000Z.json.gz"
START = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 20, 2, 0, tzinfo=timezone.utc)


class FakeCloudTrailClient:
    def __init__(self, region: str, der: bytes) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self.der = der
        self.calls: list[dict[str, Any]] = []

    def list_public_keys(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if kwargs.get("NextToken") is None:
            return {
                "PublicKeyList": [{
                    "Fingerprint": "a" * 32,
                    "Value": base64.b64encode(self.der).decode("ascii"),
                    "ValidityStartTime": datetime(2026, 11, 19, tzinfo=timezone.utc),
                    "ValidityEndTime": datetime(2026, 11, 21, tzinfo=timezone.utc),
                }],
                "NextToken": "page-two",
                "ResponseMetadata": {"RequestId": "cloudtrail-request-001"},
            }
        return {
            "PublicKeyList": [{
                "Fingerprint": "b" * 32,
                "Value": self.der,
                "ValidityStartTime": datetime(2026, 11, 19, tzinfo=timezone.utc),
                "ValidityEndTime": datetime(2026, 11, 21, tzinfo=timezone.utc),
            }],
            "ResponseMetadata": {"RequestId": "cloudtrail-request-002"},
        }


class FakeS3Client:
    def __init__(self) -> None:
        self.get_calls: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(kwargs)
        return {
            "Body": io.BytesIO(b"synthetic-object-bytes"),
            "VersionId": kwargs.get("VersionId", "latest-version-001"),
            "ContentLength": len(b"synthetic-object-bytes"),
            "Metadata": {
                "Signature": "ab" * 128,
                "Backfill-Generation-Timestamp": "2026-11-20T03:00:00Z",
            },
            "ResponseMetadata": {"RequestId": "s3-get-request-001"},
        }

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
        self.list_calls.append(kwargs)
        if kwargs.get("KeyMarker") is None:
            return {
                "Name": BUCKET,
                "Prefix": PREFIX,
                "IsTruncated": True,
                "NextKeyMarker": DIGEST_KEY,
                "NextVersionIdMarker": "latest-version-001",
                "Versions": [{
                    "Key": DIGEST_KEY,
                    "VersionId": "latest-version-001",
                    "IsLatest": True,
                    "LastModified": datetime(2026, 11, 20, 1, 1, tzinfo=timezone.utc),
                    "Size": 123,
                    "ETag": '"fixture-etag"',
                    "StorageClass": "STANDARD",
                }],
                "DeleteMarkers": [],
                "ResponseMetadata": {"RequestId": "s3-list-request-001"},
            }
        return {
            "Name": BUCKET,
            "Prefix": PREFIX,
            "IsTruncated": False,
            "Versions": [{
                "Key": DIGEST_KEY,
                "VersionId": "older-version-000",
                "IsLatest": False,
                "LastModified": datetime(2026, 11, 20, 0, 59, tzinfo=timezone.utc),
                "Size": 100,
                "ETag": '"older-etag"',
                "StorageClass": "STANDARD",
            }],
            "DeleteMarkers": [],
            "ResponseMetadata": {"RequestId": "s3-list-request-002"},
        }


def rejected(action, label: str) -> None:
    try:
        action()
    except (ValueError, TypeError):
        return
    raise AssertionError(f"expected fail-closed rejection: {label}")


def main() -> None:
    fake_der = b"synthetic-public-key-der"
    cloudtrail_client = FakeCloudTrailClient(REGION, fake_der)
    public_keys = AwsCloudTrailPublicKeyProvider(cloudtrail_client, expected_region=REGION)
    records = public_keys.list_public_keys(REGION, START, END)
    assert len(records) == 2
    assert records[0]["Value"] == fake_der
    assert public_keys.last_request_ids == ("cloudtrail-request-001", "cloudtrail-request-002")
    assert len(cloudtrail_client.calls) == 2
    assert cloudtrail_client.calls[0]["StartTime"] == START
    assert cloudtrail_client.calls[1]["NextToken"] == "page-two"
    public_keys.list_public_keys(REGION, START, END)
    assert public_keys.last_request_ids == (
        "cloudtrail-request-001", "cloudtrail-request-002",
        "cloudtrail-request-001", "cloudtrail-request-002",
    )
    rejected(
        lambda: public_keys.list_public_keys("us-west-2", START, END),
        "wrong CloudTrail Region",
    )
    rejected(
        lambda: AwsCloudTrailPublicKeyProvider(
            FakeCloudTrailClient("us-west-2", fake_der), expected_region=REGION
        ),
        "mismatched injected CloudTrail client Region",
    )
    print("PASS regional ListPublicKeys pagination and Region pinning")

    s3 = FakeS3Client()
    reader = S3VersionedEvidenceReader(
        s3, expected_bucket=BUCKET, allowed_prefixes=(PREFIX, f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/")
    )
    read = reader.read_object(BUCKET, DIGEST_KEY, version_id="latest-version-001")
    assert read.version_id == "latest-version-001"
    assert read.body == b"synthetic-object-bytes"
    assert read.metadata["signature"] == "ab" * 128
    assert read.metadata["backfill-generation-timestamp"] == "2026-11-20T03:00:00Z"
    assert s3.get_calls[0]["VersionId"] == "latest-version-001"
    rejected(lambda: reader.read_object(BUCKET, DIGEST_KEY, version_id="null"), "null requested S3 version")
    rejected(lambda: reader.read_object("other-bucket", DIGEST_KEY), "wrong S3 bucket")
    rejected(lambda: reader.read_object(BUCKET, "outside/prefix/key"), "wrong S3 prefix")
    print("PASS exact-version S3 GetObject readback and metadata normalization")

    s3 = FakeS3Client()
    collector = S3ListObjectVersionsInventoryCollector(
        s3, expected_bucket=BUCKET, expected_prefix=PREFIX
    )
    collected = collector.collect(
        account_id=ACCOUNT,
        region=REGION,
        requested_start_time=START,
        requested_end_time=END,
        test_only=True,
        collection_started_at=datetime(2026, 11, 20, 2, 5, tzinfo=timezone.utc),
        collection_completed_at=datetime(2026, 11, 20, 2, 6, tzinfo=timezone.utc),
    )
    assert collected.index["paginationComplete"] is True
    assert collected.index["pageCount"] == 2
    assert collected.index["requestIds"] == ["s3-list-request-001", "s3-list-request-002"]
    assert len(collected.page_artifacts) == 2
    page_docs = [json.loads(value) for value in collected.page_artifacts.values()]
    report = {
        "testOnly": True,
        "accountId": ACCOUNT,
        "region": REGION,
        "digests": [{
            "chainType": "STANDARD",
            "bucket": BUCKET,
            "key": DIGEST_KEY,
            "versionId": "latest-version-001",
            "digestEndTime": "2026-11-20T01:00:00Z",
        }],
    }
    result = reconcile_inventory(report, collected.index, page_docs)
    assert result["completeWithinCapturedStandardInventory"] is True
    assert result["paginationPageCount"] == 2
    assert len(s3.list_calls) == 2
    assert s3.list_calls[1]["KeyMarker"] == DIGEST_KEY
    assert s3.list_calls[1]["VersionIdMarker"] == "latest-version-001"
    print("PASS ListObjectVersions collector emits validator-compatible complete pagination evidence")

    print("Read-only AWS adapter tests passed; all clients were synthetic and injected.")


if __name__ == "__main__":
    main()
