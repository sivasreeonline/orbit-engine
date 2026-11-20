#!/usr/bin/env python3
"""Synthetic-only CloudTrail digest-chain verifier tests."""
from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from verify_m0_fence_cloudtrail_digest_chain import (
    CloudTrailDigestChainVerifier,
    DigestVerificationError,
    ReadObject,
)


ACCOUNT = "123456789012"
REGION = "us-east-1"
BUCKET = "synthetic-cloudtrail-evidence"
FINGERPRINT = "synthetic-fingerprint-001"
KEY_VALID_FROM = datetime(2026, 11, 19, tzinfo=timezone.utc)
KEY_VALID_TO = datetime(2026, 11, 21, tzinfo=timezone.utc)


class FakeReader:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], ReadObject] = {}

    def add(
        self, bucket: str, key: str, body: bytes, version_id: str,
        signature: str | None = None, metadata: dict[str, str] | None = None,
    ) -> None:
        stored_metadata = dict(metadata or {})
        if signature is not None:
            stored_metadata["signature"] = signature
        self.objects[(bucket, key)] = ReadObject(body, version_id, stored_metadata)

    def read_object(self, bucket: str, key: str, *, version_id: str | None = None) -> ReadObject:
        item = self.objects.get((bucket, key))
        if item is None:
            raise DigestVerificationError("synthetic object not found")
        if version_id is not None and item.version_id != version_id:
            raise DigestVerificationError("synthetic exact version mismatch")
        return item


class FakePublicKeys:
    def __init__(self, der: bytes) -> None:
        self.der = der
        self.calls: list[tuple[str, datetime, datetime]] = []

    def list_public_keys(self, region: str, start_time: datetime, end_time: datetime) -> list[dict[str, Any]]:
        self.calls.append((region, start_time, end_time))
        return [{
            "Fingerprint": FINGERPRINT,
            "Value": self.der,
            "ValidityStartTime": KEY_VALID_FROM,
            "ValidityEndTime": KEY_VALID_TO,
        }]


def canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def gzip_bytes(value: bytes) -> bytes:
    return gzip.compress(value, mtime=0)


def sign_digest(private_key: Any, document: dict[str, Any], bucket: str, key: str, uncompressed: bytes) -> str:
    previous_signature = document.get("previousDigestSignature")
    if previous_signature is None:
        previous_signature = "null"
    data_to_sign = (
        f"{document['digestEndTime']}\n"
        f"{bucket}/{key}\n"
        f"{hashlib.sha256(uncompressed).hexdigest()}\n"
        f"{previous_signature}"
    ).encode("utf-8")
    return private_key.sign(data_to_sign, padding.PKCS1v15(), hashes.SHA256()).hex()


def build_fixture() -> tuple[FakeReader, FakePublicKeys, Any, str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    reader = FakeReader()
    keys = FakePublicKeys(public_der)

    log_one = b'{"Records":[{"eventName":"CreateTrail","eventSource":"cloudtrail.amazonaws.com"}]}'
    log_two = b'{"Records":[{"eventName":"PutObject","eventSource":"s3.amazonaws.com"}]}'
    log_one_key = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/2026/11/20/log-one.json.gz"
    log_two_key = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/2026/11/20/log-two.json.gz"
    reader.add(BUCKET, log_one_key, gzip_bytes(log_one), "log-version-001")
    reader.add(BUCKET, log_two_key, gzip_bytes(log_two), "log-version-002")

    genesis_key = f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/2026/11/20/genesis.json.gz"
    genesis = {
        "awsAccountId": ACCOUNT,
        "digestStartTime": "2026-11-20T00:00:00Z",
        "digestEndTime": "2026-11-20T01:00:00Z",
        "digestS3Bucket": BUCKET,
        "digestS3Object": genesis_key,
        "digestPublicKeyFingerprint": FINGERPRINT,
        "digestSignatureAlgorithm": "SHA256withRSA",
        "previousDigestS3Bucket": None,
        "previousDigestS3Object": None,
        "previousDigestHashValue": None,
        "previousDigestHashAlgorithm": None,
        "previousDigestSignature": None,
        "logFiles": [{
            "s3Bucket": BUCKET,
            "s3Object": log_one_key,
            "hashValue": hashlib.sha256(log_one).hexdigest(),
            "hashAlgorithm": "SHA-256",
        }],
    }
    genesis_bytes = canonical_json(genesis)
    genesis_signature = sign_digest(private_key, genesis, BUCKET, genesis_key, genesis_bytes)
    reader.add(BUCKET, genesis_key, gzip_bytes(genesis_bytes), "digest-version-001", genesis_signature)

    latest_key = f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/2026/11/20/latest.json.gz"
    latest = {
        "awsAccountId": ACCOUNT,
        "digestStartTime": "2026-11-20T01:00:00Z",
        "digestEndTime": "2026-11-20T02:00:00Z",
        "digestS3Bucket": BUCKET,
        "digestS3Object": latest_key,
        "digestPublicKeyFingerprint": FINGERPRINT,
        "digestSignatureAlgorithm": "SHA256withRSA",
        "previousDigestS3Bucket": BUCKET,
        "previousDigestS3Object": genesis_key,
        "previousDigestHashValue": hashlib.sha256(genesis_bytes).hexdigest(),
        "previousDigestHashAlgorithm": "SHA-256",
        "previousDigestSignature": genesis_signature,
        "logFiles": [{
            "s3Bucket": BUCKET,
            "s3Object": log_two_key,
            "hashValue": hashlib.sha256(log_two).hexdigest(),
            "hashAlgorithm": "SHA-256",
        }],
    }
    latest_bytes = canonical_json(latest)
    latest_signature = sign_digest(private_key, latest, BUCKET, latest_key, latest_bytes)
    reader.add(BUCKET, latest_key, gzip_bytes(latest_bytes), "digest-version-002", latest_signature)
    return reader, keys, latest_key, latest_signature, genesis_key


def build_backfill_fixture() -> tuple[FakeReader, FakePublicKeys, str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    reader = FakeReader()
    keys = FakePublicKeys(public_der)
    log_content = b'{"Records":[{"eventName":"BackfilledEvent","eventSource":"fixture.amazonaws.com"}]}'
    log_key = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/2026/11/20/backfill-log.json.gz"
    reader.add(BUCKET, log_key, gzip_bytes(log_content), "backfill-log-version-001")
    digest_key = (
        f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/2026/11/20/"
        f"{ACCOUNT}_CloudTrail-Digest_{REGION}_fixture-trail_{REGION}_"
        "20261120T020000Z_backfill.json.gz"
    )
    generation_time = "2026-11-20T03:00:00Z"
    document = {
        "awsAccountId": ACCOUNT,
        "digestStartTime": "2026-11-20T01:00:00Z",
        "digestEndTime": "2026-11-20T02:00:00Z",
        "digestS3Bucket": BUCKET,
        "digestS3Object": digest_key,
        "digestPublicKeyFingerprint": FINGERPRINT,
        "digestSignatureAlgorithm": "SHA256withRSA",
        "previousDigestS3Bucket": None,
        "previousDigestS3Object": None,
        "previousDigestHashValue": None,
        "previousDigestHashAlgorithm": None,
        "previousDigestSignature": None,
        "logFiles": [{
            "s3Bucket": BUCKET,
            "s3Object": log_key,
            "hashValue": hashlib.sha256(log_content).hexdigest(),
            "hashAlgorithm": "SHA-256",
        }],
    }
    uncompressed = canonical_json(document)
    signature = sign_digest(private_key, document, BUCKET, digest_key, uncompressed)
    reader.add(
        BUCKET, digest_key, gzip_bytes(uncompressed), "backfill-digest-version-001",
        signature,
        metadata={"backfill-generation-timestamp": generation_time},
    )
    keys.der = public_der
    return reader, keys, digest_key, generation_time


def rejected(action, label: str) -> None:
    try:
        action()
    except DigestVerificationError:
        return
    raise AssertionError(f"expected fail-closed rejection: {label}")


def main() -> None:
    reader, keys, latest_key, latest_signature, genesis_key = build_fixture()
    verifier = CloudTrailDigestChainVerifier(
        reader, keys,
        expected_account_id=ACCOUNT,
        expected_region=REGION,
        expected_digest_bucket=BUCKET,
    )
    report = verifier.verify_chain(BUCKET, latest_key, latest_version_id="digest-version-002")
    assert report.digest_count == 2, "expected two verified digest files"
    assert report.log_count == 2, "expected two verified CloudTrail log files"
    assert report.digests[0].version_id == "digest-version-002"
    assert report.digests[1].version_id == "digest-version-001"
    custody = report.to_dict(test_only=True)
    latest_read = reader.objects[(BUCKET, latest_key)]
    assert custody["digests"][0]["rawSha256"] == hashlib.sha256(latest_read.body).hexdigest()
    assert custody["digests"][0]["rawByteCount"] == len(latest_read.body)
    assert custody["digests"][0]["uncompressedSha256"] == report.digests[0].uncompressed_sha256
    assert custody["digests"][0]["publicKey"]["derSha256"] == hashlib.sha256(keys.der).hexdigest()
    assert custody["digests"][0]["publicKey"]["derBase64"]
    assert custody["digests"][0]["logs"][0]["rawByteCount"] > 0
    assert custody["digests"][0]["logs"][0]["uncompressedByteCount"] > 0
    assert {call[0] for call in keys.calls} == {REGION}, "public keys must be retrieved from the digest Region"
    print("PASS two-link CloudTrail digest signature chain and exact-version evidence readback")

    bad_reader, bad_keys, bad_latest_key, _, _ = build_fixture()
    bad_log_key = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/2026/11/20/log-two.json.gz"
    bad_reader.objects[(BUCKET, bad_log_key)] = ReadObject(
        gzip_bytes(b'{"Records":[{"eventName":"tampered"}]}'),
        "log-version-tampered",
        {},
    )
    rejected(
        lambda: CloudTrailDigestChainVerifier(
            bad_reader, bad_keys,
            expected_account_id=ACCOUNT, expected_region=REGION,
            expected_digest_bucket=BUCKET,
        ).verify_chain(BUCKET, bad_latest_key, latest_version_id="digest-version-002"),
        "tampered referenced log bytes",
    )
    print("PASS tampered CloudTrail log bytes are rejected")

    moved_reader, moved_keys, moved_latest_key, _, _ = build_fixture()
    moved = moved_reader.objects[(BUCKET, moved_latest_key)]
    moved_doc = json.loads(gzip.decompress(moved.body))
    moved_doc["digestS3Object"] = "moved/elsewhere.json.gz"
    moved_bytes = canonical_json(moved_doc)
    moved_reader.objects[(BUCKET, moved_latest_key)] = ReadObject(
        gzip_bytes(moved_bytes), moved.version_id, moved.metadata
    )
    rejected(
        lambda: CloudTrailDigestChainVerifier(
            moved_reader, moved_keys,
            expected_account_id=ACCOUNT, expected_region=REGION,
            expected_digest_bucket=BUCKET,
        ).verify_chain(BUCKET, moved_latest_key, latest_version_id="digest-version-002"),
        "digest moved from original bucket/key",
    )
    print("PASS moved digest object is rejected")

    missing_version_reader, missing_keys, missing_key, _, _ = build_fixture()
    original = missing_version_reader.objects[(BUCKET, missing_key)]
    missing_version_reader.objects[(BUCKET, missing_key)] = ReadObject(
        original.body, "null", original.metadata
    )
    rejected(
        lambda: CloudTrailDigestChainVerifier(
            missing_version_reader, missing_keys,
            expected_account_id=ACCOUNT, expected_region=REGION,
            expected_digest_bucket=BUCKET,
        ).verify_chain(BUCKET, missing_key, latest_version_id="digest-version-002"),
        "null S3 version",
    )
    print("PASS null S3 versions are rejected")

    backfill_reader, backfill_keys, backfill_key, generation_time = build_backfill_fixture()
    backfill_verifier = CloudTrailDigestChainVerifier(
        backfill_reader, backfill_keys,
        expected_account_id=ACCOUNT, expected_region=REGION,
        expected_digest_bucket=BUCKET,
    )
    backfill_report = backfill_verifier.verify_chain(
        BUCKET, backfill_key, latest_version_id="backfill-digest-version-001",
        is_backfill=True,
    )
    backfill_data = backfill_report.to_dict(test_only=True)
    assert backfill_data["backfillDigestCount"] == 1
    assert backfill_data["digests"][0]["chainType"] == "BACKFILL"
    assert backfill_data["digests"][0]["backfillGenerationTimestamp"] == generation_time
    start_call = backfill_keys.calls[-1]
    assert start_call[1].isoformat().startswith("2026-11-20T02:00:00")
    assert start_call[2].isoformat().startswith("2026-11-20T04:00:00")
    print("PASS separate backfill chain uses generation-time regional key lookup")

    rejected(
        lambda: backfill_verifier.verify_chain(
            BUCKET, backfill_key, latest_version_id="backfill-digest-version-001",
            is_backfill=False,
        ),
        "backfill key in standard chain",
    )
    missing_metadata_reader, missing_metadata_keys, missing_metadata_key, _ = build_backfill_fixture()
    missing_object = missing_metadata_reader.objects[(BUCKET, missing_metadata_key)]
    missing_metadata_reader.objects[(BUCKET, missing_metadata_key)] = ReadObject(
        missing_object.body, missing_object.version_id, {"signature": missing_object.metadata["signature"]}
    )
    rejected(
        lambda: CloudTrailDigestChainVerifier(
            missing_metadata_reader, missing_metadata_keys,
            expected_account_id=ACCOUNT, expected_region=REGION,
            expected_digest_bucket=BUCKET,
        ).verify_chain(
            BUCKET, missing_metadata_key, latest_version_id="backfill-digest-version-001",
            is_backfill=True,
        ),
        "missing backfill generation timestamp",
    )
    print("PASS standard/backfill classification and missing generation metadata are rejected")

    print("Synthetic CloudTrail digest verifier tests passed; no AWS account, credentials or provider APIs were used.")


if __name__ == "__main__":
    main()
