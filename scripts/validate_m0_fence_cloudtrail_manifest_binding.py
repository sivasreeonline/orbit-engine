#!/usr/bin/env python3
"""Bind CloudTrail digest-chain results and raw provider bytes to a dual-signed FENCE-001 manifest."""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import tempfile
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from validate_m0_fence_evidence_manifest import (
    ROOT,
    SIGNATURE_PREFIX,
    load_json,
    validate_manifest,
)
from verify_m0_fence_evidence_artifact_bytes import verify_artifact_files


HEX = set("0123456789abcdef")
CLOUDTRAIL_TYPES = {
    "CLOUDTRAIL_DIGEST",
    "CLOUDTRAIL_LOG",
    "CLOUDTRAIL_PUBLIC_KEY",
    "CLOUDTRAIL_VERIFICATION_REPORT",
}
REQUIRED_TEST_IDS = {
    "CLOUDTRAIL_DIGEST": {"CT-001", "CT-002", "CT-004", "CT-006"},
    "CLOUDTRAIL_LOG": {"CT-003", "CT-004", "CT-006"},
    "CLOUDTRAIL_PUBLIC_KEY": {"CT-001", "CT-006"},
    "CLOUDTRAIL_VERIFICATION_REPORT": {"CT-006"},
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in HEX for ch in value)


def safe_version(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value != "null"


def object_ref(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


def _bounded_uncompress(raw: bytes, *, maximum: int, label: str) -> bytes:
    if len(raw) > maximum:
        raise ValueError(f"{label} compressed bytes exceed the configured limit")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            content = stream.read(maximum + 1)
    except (OSError, EOFError) as error:
        raise ValueError(f"{label} is not a valid gzip stream") from error
    if len(content) > maximum:
        raise ValueError(f"{label} decompressed bytes exceed the configured limit")
    return content


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON field: {key}")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return value


def _verify_materialized_digest(
    digest: dict[str, Any], raw_digest: bytes, raw_public_key: bytes,
    account_id: str, region: str,
) -> dict[str, Any]:
    uncompressed = _bounded_uncompress(raw_digest, maximum=16 * 1024 * 1024, label="CloudTrail digest")
    if sha(uncompressed) != digest["uncompressedSha256"] or len(uncompressed) != digest["uncompressedByteCount"]:
        raise ValueError("CloudTrail digest uncompressed measurements do not match preserved raw bytes")
    document = _strict_json(uncompressed, "CloudTrail digest")
    for field, expected in (
        ("awsAccountId", account_id),
        ("digestS3Bucket", digest["bucket"]),
        ("digestS3Object", digest["key"]),
        ("digestStartTime", digest["digestStartTime"]),
        ("digestEndTime", digest["digestEndTime"]),
        ("digestPublicKeyFingerprint", digest["signatureFingerprint"]),
        ("digestSignatureAlgorithm", digest["signatureAlgorithm"]),
    ):
        if document.get(field) != expected:
            raise ValueError(f"CloudTrail digest source field {field} differs from the verification report")
    public_key = serialization.load_der_public_key(raw_public_key)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("CloudTrail public-key artifact is not an RSA public key")
    previous_signature = document.get("previousDigestSignature")
    if previous_signature is None:
        previous_signature = ""
    if not isinstance(previous_signature, str):
        raise ValueError("CloudTrail previousDigestSignature is malformed")
    data_to_sign = (
        f"{document['digestEndTime']}\\n"
        f"{digest['bucket']}/{digest['key']}\\n"
        f"{sha(uncompressed)}\\n"
        f"{previous_signature}"
    ).encode("utf-8")
    try:
        public_key.verify(
            bytes.fromhex(digest["signatureHex"]),
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as error:
        raise ValueError("CloudTrail digest signature does not verify against the manifested public key") from error
    return document


def _verify_materialized_log(log: dict[str, Any], raw_log: bytes) -> None:
    uncompressed = _bounded_uncompress(raw_log, maximum=64 * 1024 * 1024, label="CloudTrail log")
    if sha(uncompressed) != log["uncompressedSha256"] or len(uncompressed) != log["uncompressedByteCount"]:
        raise ValueError("CloudTrail log uncompressed measurements do not match preserved raw bytes")


def _read_artifact(root: Path, artifact_id: str) -> bytes:
    if not isinstance(artifact_id, str) or not artifact_id or artifact_id in {".", ".."}:
        raise ValueError("unsafe manifest artifact ID")
    if any(ch in artifact_id for ch in ("/", "\\", "\x00")):
        raise ValueError("manifest artifact ID must be a flat local filename")
    candidate = root / artifact_id
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"manifest artifact is missing or is not a regular file: {artifact_id}")
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents:
        raise ValueError("manifest artifact path escapes the artifact root")
    return resolved.read_bytes()


def validate_report(report: dict[str, Any], manifest_body: dict[str, Any]) -> None:
    if report.get("profile") != "sky-high-cloudtrail-digest-verification-v1":
        raise ValueError("unsupported CloudTrail verification report profile")
    if report.get("schemaVersion") != 1:
        raise ValueError("unsupported CloudTrail verification report schema version")
    if report.get("testOnly") is not manifest_body["testOnly"]:
        raise ValueError("CloudTrail report testOnly flag differs from signed manifest")
    provider = manifest_body["providerScope"]
    if provider["name"].lower() not in {"aws", "amazon-web-services"} or provider["service"].lower() != "cloudtrail":
        raise ValueError("manifest provider scope must identify AWS CloudTrail")
    if report.get("accountId") != provider["account"] or report.get("region") != provider["region"]:
        raise ValueError("CloudTrail report account/Region differs from signed manifest scope")
    if report.get("verificationStatus") != "CHAIN_AND_REFERENCED_OBJECTS_VERIFIED":
        raise ValueError("CloudTrail report does not record successful chain and referenced-object verification")
    if report.get("completenessStatus") != "NOT_ESTABLISHED_BY_CHAIN_WALK":
        raise ValueError("CloudTrail report must not overstate digest-chain completeness")
    digests = report.get("digests")
    if not isinstance(digests, list) or not digests:
        raise ValueError("CloudTrail report must contain at least one verified digest")
    if report.get("digestCount") != len(digests):
        raise ValueError("CloudTrail report digestCount mismatch")
    log_count = sum(len(item.get("logs", [])) for item in digests if isinstance(item, dict))
    if report.get("logCount") != log_count:
        raise ValueError("CloudTrail report logCount mismatch")

    previous_end = None
    seen_digests: set[tuple[str, str, str]] = set()
    seen_logs: set[tuple[str, str, str]] = set()
    for digest in digests:
        if not isinstance(digest, dict):
            raise ValueError("CloudTrail digest report entry must be an object")
        bucket, key, version = digest.get("bucket"), digest.get("key"), digest.get("versionId")
        if not all(isinstance(value, str) and value for value in (bucket, key)) or not safe_version(version):
            raise ValueError("CloudTrail digest report must pin bucket, key and exact non-null VersionId")
        identity = (bucket, key, version)
        if identity in seen_digests:
            raise ValueError("duplicate digest object/version in CloudTrail report")
        seen_digests.add(identity)
        for field in ("rawSha256", "uncompressedSha256"):
            if not is_sha(digest.get(field)):
                raise ValueError(f"CloudTrail digest {field} is malformed")
        for field in ("rawByteCount", "uncompressedByteCount"):
            if type(digest.get(field)) is not int or digest[field] < 1:
                raise ValueError(f"CloudTrail digest {field} must be a positive integer")
        if digest.get("signatureAlgorithm") != "SHA256withRSA":
            raise ValueError("unsupported CloudTrail digest signature algorithm in report")
        signature = digest.get("signatureHex")
        if not isinstance(signature, str) or not signature or len(signature) % 2 or any(ch not in HEX for ch in signature):
            raise ValueError("CloudTrail digest signature evidence is malformed")
        start, end = digest.get("digestStartTime"), digest.get("digestEndTime")
        if not isinstance(start, str) or not isinstance(end, str) or not start or not end:
            raise ValueError("CloudTrail digest time interval is missing")
        if previous_end is not None and end >= previous_end:
            raise ValueError("CloudTrail digest report is not ordered latest-to-oldest")
        previous_end = end

        public_key = digest.get("publicKey")
        if not isinstance(public_key, dict) or public_key.get("region") != provider["region"]:
            raise ValueError("CloudTrail regional public-key evidence is missing or scoped incorrectly")
        if public_key.get("fingerprint") != digest.get("signatureFingerprint"):
            raise ValueError("CloudTrail public-key fingerprint differs from digest signer fingerprint")
        if not is_sha(public_key.get("derSha256")):
            raise ValueError("CloudTrail public-key DER SHA-256 is malformed")
        if type(public_key.get("derByteCount")) is not int or public_key["derByteCount"] < 1:
            raise ValueError("CloudTrail public-key DER byte count is invalid")
        if not isinstance(public_key.get("validityStartTime"), str) or not isinstance(public_key.get("validityEndTime"), str):
            raise ValueError("CloudTrail public-key validity interval is missing")

        logs = digest.get("logs")
        if not isinstance(logs, list):
            raise ValueError("CloudTrail digest logs must be an array")
        for log in logs:
            if not isinstance(log, dict):
                raise ValueError("CloudTrail log report entry must be an object")
            log_bucket, log_key, log_version = log.get("bucket"), log.get("key"), log.get("versionId")
            if not all(isinstance(value, str) and value for value in (log_bucket, log_key)) or not safe_version(log_version):
                raise ValueError("CloudTrail log report must pin bucket, key and exact non-null VersionId")
            log_identity = (log_bucket, log_key, log_version)
            if log_identity in seen_logs:
                raise ValueError("duplicate CloudTrail log object/version in report")
            seen_logs.add(log_identity)
            for field in ("rawSha256", "uncompressedSha256"):
                if not is_sha(log.get(field)):
                    raise ValueError(f"CloudTrail log {field} is malformed")
            for field in ("rawByteCount", "uncompressedByteCount"):
                if type(log.get(field)) is not int or log[field] < 1:
                    raise ValueError(f"CloudTrail log {field} must be a positive integer")


def validate_cloudtrail_manifest(
    envelope: dict[str, Any],
    trusted_keys: list[dict[str, str]],
    artifact_root: Path,
    *,
    allow_test_only: bool = False,
) -> dict[str, Any]:
    manifest_digest = validate_manifest(envelope, trusted_keys, allow_test_only=allow_test_only)
    body = envelope["manifestBody"]
    root = artifact_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("artifact root must be a directory")
    verify_artifact_files(body, root)

    artifacts = body["artifacts"]
    cloudtrail_artifacts = [item for item in artifacts if item["artifactType"] in CLOUDTRAIL_TYPES]
    by_type: dict[str, list[dict[str, Any]]] = {
        artifact_type: [item for item in cloudtrail_artifacts if item["artifactType"] == artifact_type]
        for artifact_type in CLOUDTRAIL_TYPES
    }
    reports = by_type["CLOUDTRAIL_VERIFICATION_REPORT"]
    if len(reports) != 1:
        raise ValueError("manifest must contain exactly one CloudTrail verification report artifact")
    report_artifact = reports[0]
    report_bytes = _read_artifact(root, report_artifact["artifactId"])
    report = json.loads(report_bytes.decode("utf-8", errors="strict"))
    if not isinstance(report, dict):
        raise ValueError("CloudTrail verification report root must be an object")
    validate_report(report, body)

    expected: dict[tuple[str, str, str, str], tuple[str, int]] = {}
    for digest in report["digests"]:
        expected[(
            "CLOUDTRAIL_DIGEST",
            object_ref(digest["bucket"], digest["key"]),
            digest["versionId"],
            digest["rawSha256"],
        )] = (digest["rawByteCount"], digest["rawByteCount"])
        public_key = digest["publicKey"]
        key_ref = f"cloudtrail-public-key://{public_key['region']}/{public_key['fingerprint']}"
        key_version = f"{public_key['validityStartTime']}/{public_key['validityEndTime']}"
        expected[(
            "CLOUDTRAIL_PUBLIC_KEY", key_ref, key_version, public_key["derSha256"]
        )] = (public_key["derByteCount"], public_key["derByteCount"])
        for log in digest["logs"]:
            expected[(
                "CLOUDTRAIL_LOG",
                object_ref(log["bucket"], log["key"]),
                log["versionId"],
                log["rawSha256"],
            )] = (log["rawByteCount"], log["rawByteCount"])

    if len(expected) != len(by_type["CLOUDTRAIL_DIGEST"]) + len(by_type["CLOUDTRAIL_LOG"]) + len(by_type["CLOUDTRAIL_PUBLIC_KEY"]):
        raise ValueError("manifest contains duplicate or unreferenced CloudTrail source artifacts")
    for artifact_type in CLOUDTRAIL_TYPES:
        for artifact in by_type[artifact_type]:
            if not REQUIRED_TEST_IDS[artifact_type].issubset(set(artifact["testIds"])):
                raise ValueError(f"{artifact_type} artifact lacks its required CloudTrail test IDs")

    actual: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for artifact in cloudtrail_artifacts:
        if artifact["artifactType"] == "CLOUDTRAIL_VERIFICATION_REPORT":
            continue
        identity = (
            artifact["artifactType"],
            artifact["objectRef"],
            artifact["objectVersion"],
            artifact["sha256"],
        )
        if identity in actual:
            raise ValueError("duplicate CloudTrail evidence artifact mapping")
        actual[identity] = artifact
    if set(actual) != set(expected):
        raise ValueError("CloudTrail report evidence inventory does not exactly match signed manifest artifacts")

    for identity, (expected_count, _) in expected.items():
        artifact = actual[identity]
        if artifact["byteCount"] != expected_count:
            raise ValueError("CloudTrail manifest artifact byte count differs from verification report")

    for digest in report["digests"]:
        digest_identity = (
            "CLOUDTRAIL_DIGEST", object_ref(digest["bucket"], digest["key"]),
            digest["versionId"], digest["rawSha256"],
        )
        key = digest["publicKey"]
        key_identity = (
            "CLOUDTRAIL_PUBLIC_KEY",
            f"cloudtrail-public-key://{key['region']}/{key['fingerprint']}",
            f"{key['validityStartTime']}/{key['validityEndTime']}",
            key["derSha256"],
        )
        digest_bytes = _read_artifact(root, actual[digest_identity]["artifactId"])
        key_bytes = _read_artifact(root, actual[key_identity]["artifactId"])
        document = _verify_materialized_digest(
            digest, digest_bytes, key_bytes, body["providerScope"]["account"],
            body["providerScope"]["region"],
        )
        for log in digest["logs"]:
            log_identity = (
                "CLOUDTRAIL_LOG", object_ref(log["bucket"], log["key"]),
                log["versionId"], log["rawSha256"],
            )
            _verify_materialized_log(log, _read_artifact(root, actual[log_identity]["artifactId"]))

    for index, digest in enumerate(report["digests"]):
        document = _strict_json(
            _bounded_uncompress(
                _read_artifact(root, actual[(
                    "CLOUDTRAIL_DIGEST", object_ref(digest["bucket"], digest["key"]),
                    digest["versionId"], digest["rawSha256"],
                )]["artifactId"]),
                maximum=16 * 1024 * 1024,
                label="CloudTrail digest",
            ),
            "CloudTrail digest",
        )
        previous = document.get("previousDigestS3Object")
        previous_bucket = document.get("previousDigestS3Bucket")
        previous_hash = document.get("previousDigestHashValue")
        previous_signature = document.get("previousDigestSignature")
        if index + 1 < len(report["digests"]):
            predecessor = report["digests"][index + 1]
            if previous_bucket != predecessor["bucket"] or previous != predecessor["key"]:
                raise ValueError("CloudTrail report order does not match previous digest bucket/key linkage")
            if previous_hash != predecessor["uncompressedSha256"]:
                raise ValueError("CloudTrail previousDigestHashValue does not match predecessor evidence")
            if previous_signature != predecessor["signatureHex"]:
                raise ValueError("CloudTrail previousDigestSignature does not match predecessor signature evidence")
        elif any(value is not None for value in (
            previous_bucket, previous, previous_hash,
            document.get("previousDigestHashAlgorithm"), previous_signature,
        )):
            raise ValueError("CloudTrail report does not terminate at a complete starting digest")

    if not REQUIRED_TEST_IDS["CLOUDTRAIL_VERIFICATION_REPORT"].issubset(set(report_artifact["testIds"])):
        raise ValueError("CloudTrail verification report artifact lacks CT-006")
    if report_artifact["objectVersion"] != "report-v1":
        raise ValueError("CloudTrail verification report objectVersion must be report-v1")
    if report_artifact["sha256"] != sha(report_bytes) or report_artifact["byteCount"] != len(report_bytes):
        raise ValueError("CloudTrail verification report bytes differ from signed manifest")

    return {
        "manifestDigest": manifest_digest,
        "reportSha256": sha(report_bytes),
        "digestCount": report["digestCount"],
        "logCount": report["logCount"],
        "sourceArtifactCount": len(expected),
        "reportArtifactId": report_artifact["artifactId"],
        "testOnly": report["testOnly"],
    }


def _signed_manifest(body: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    import base64

    signer_material: list[tuple[str, str, Ed25519PrivateKey, bytes, str]] = []
    trusted: list[dict[str, str]] = []
    for role, identity in (("COLLECTOR", "collector-test"), ("INDEPENDENT_VERIFIER", "verifier-test")):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        key_id = sha(public)
        signer_material.append((role, identity, private, public, key_id))
        trusted.append({
            "keyId": key_id,
            "identity": identity,
            "role": role,
            "publicKeyBase64Url": base64.urlsafe_b64encode(public).decode("ascii").rstrip("="),
        })

    key_ids = {role: key_id for role, _, _, _, key_id in signer_material}
    for artifact in body["artifacts"]:
        artifact["collectorIdentity"] = "collector-test"
        artifact["collectorKeyId"] = key_ids["COLLECTOR"]
        artifact["independentVerifierIdentity"] = "verifier-test"
        artifact["verifierKeyId"] = key_ids["INDEPENDENT_VERIFIER"]

    digest = sha(rfc8785.dumps(body))
    attestations = []
    for role, identity, private, _public, key_id in signer_material:
        payload = {
            "manifestDigest": digest,
            "role": role,
            "signerIdentity": identity,
            "keyId": key_id,
        }
        signature = private.sign(SIGNATURE_PREFIX + rfc8785.dumps(payload))
        attestations.append({
            "role": role,
            "signerIdentity": identity,
            "keyId": key_id,
            "signatureBase64Url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        })
    return {
        "manifestBody": body,
        "manifestDigest": digest,
        "attestations": attestations,
    }, trusted

def _artifact(
    artifact_id: str, artifact_type: str, object_ref_value: str, object_version: str,
    data: bytes, test_ids: list[str],
) -> dict[str, Any]:
    return {
        "artifactId": artifact_id,
        "testIds": test_ids,
        "artifactType": artifact_type,
        "objectRef": object_ref_value,
        "objectVersion": object_version,
        "sha256": sha(data),
        "byteCount": len(data),
        "acquiredAt": "2026-11-20T00:00:00Z",
        "collectorIdentity": "collector-test",
        "collectorKeyId": "1" * 64,
        "independentVerifierIdentity": "verifier-test",
        "verifierKeyId": "2" * 64,
        "providerRequestIds": [],
        "redaction": "NONE",
    }


def _fixture(root: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    import base64
    import gzip

    account, region, bucket = "123456789012", "us-east-1", "fixture-cloudtrail-bucket"
    digest_key = f"AWSLogs/{account}/CloudTrail-Digest/{region}/2026/11/20/digest.json.gz"
    log_key = f"AWSLogs/{account}/CloudTrail/{region}/2026/11/20/log.json.gz"
    log_content = b'{"Records":[{"eventName":"SyntheticFixtureEvent","eventSource":"fixture.amazonaws.com"}]}'
    log_raw = gzip.compress(log_content, mtime=0)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1
    )
    start, end = "2026-11-20T00:00:00Z", "2026-11-20T01:00:00Z"
    fingerprint = "fixture-cloudtrail-key"
    document = {
        "awsAccountId": account,
        "digestStartTime": start,
        "digestEndTime": end,
        "digestS3Bucket": bucket,
        "digestS3Object": digest_key,
        "digestPublicKeyFingerprint": fingerprint,
        "digestSignatureAlgorithm": "SHA256withRSA",
        "previousDigestS3Bucket": None,
        "previousDigestS3Object": None,
        "previousDigestHashValue": None,
        "previousDigestHashAlgorithm": None,
        "previousDigestSignature": None,
        "logFiles": [{
            "s3Bucket": bucket,
            "s3Object": log_key,
            "hashValue": sha(log_content),
            "hashAlgorithm": "SHA-256",
        }],
    }
    digest_content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest_raw = gzip.compress(digest_content, mtime=0)
    data_to_sign = f"{end}\\n{bucket}/{digest_key}\\n{sha(digest_content)}\\n".encode("utf-8")
    signature_hex = private_key.sign(data_to_sign, padding.PKCS1v15(), hashes.SHA256()).hex()
    report = {
        "profile": "sky-high-cloudtrail-digest-verification-v1",
        "schemaVersion": 1,
        "testOnly": True,
        "accountId": account,
        "region": region,
        "verificationStatus": "CHAIN_AND_REFERENCED_OBJECTS_VERIFIED",
        "completenessStatus": "NOT_ESTABLISHED_BY_CHAIN_WALK",
        "digestCount": 1,
        "logCount": 1,
        "digests": [{
            "bucket": bucket, "key": digest_key, "versionId": "digest-version-001",
            "rawSha256": sha(digest_raw), "rawByteCount": len(digest_raw),
            "uncompressedSha256": sha(digest_content), "uncompressedByteCount": len(digest_content),
            "signatureHex": signature_hex, "signatureAlgorithm": "SHA256withRSA",
            "signatureFingerprint": fingerprint,
            "digestStartTime": start, "digestEndTime": end,
            "publicKey": {
                "region": region, "fingerprint": fingerprint,
                "derSha256": sha(key_der), "derByteCount": len(key_der),
                "validityStartTime": "2026-11-19T00:00:00Z",
                "validityEndTime": "2026-11-21T00:00:00Z",
            },
            "logs": [{
                "bucket": bucket, "key": log_key, "versionId": "log-version-001",
                "rawSha256": sha(log_raw), "rawByteCount": len(log_raw),
                "uncompressedSha256": sha(log_content), "uncompressedByteCount": len(log_content),
            }],
        }],
    }
    report_bytes = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    files = {
        "digest-001": digest_raw,
        "log-001": log_raw,
        "public-key-001": key_der,
        "report-001": report_bytes,
    }
    for name, data in files.items():
        (root / name).write_bytes(data)

    artifacts = [
        _artifact("digest-001", "CLOUDTRAIL_DIGEST", object_ref(bucket, digest_key), "digest-version-001", digest_raw, sorted(REQUIRED_TEST_IDS["CLOUDTRAIL_DIGEST"])),
        _artifact("log-001", "CLOUDTRAIL_LOG", object_ref(bucket, log_key), "log-version-001", log_raw, sorted(REQUIRED_TEST_IDS["CLOUDTRAIL_LOG"])),
        _artifact("public-key-001", "CLOUDTRAIL_PUBLIC_KEY", f"cloudtrail-public-key://{region}/{fingerprint}", f"{report['digests'][0]['publicKey']['validityStartTime']}/{report['digests'][0]['publicKey']['validityEndTime']}", key_der, sorted(REQUIRED_TEST_IDS["CLOUDTRAIL_PUBLIC_KEY"])),
        _artifact("report-001", "CLOUDTRAIL_VERIFICATION_REPORT", f"cloudtrail-verification-report://{account}/{region}", "report-v1", report_bytes, sorted(REQUIRED_TEST_IDS["CLOUDTRAIL_VERIFICATION_REPORT"])),
    ]
    body = {
        "profile": "sky-high-fence-evidence-manifest-v1",
        "schemaVersion": 1,
        "manifestId": "cloudtrail-fixture-manifest",
        "createdAt": "2026-11-20T00:00:00Z",
        "testOnly": True,
        "providerScope": {"name": "aws", "account": account, "region": region, "service": "cloudtrail"},
        "adapter": {
            "repository": "https://example.invalid/cloudtrail-verifier",
            "commit": "1" * 40,
            "version": "fixture-1",
            "configurationDigest": "2" * 64,
        },
        "artifacts": artifacts,
    }
    envelope, trust = _signed_manifest(body)
    return envelope, trust

def run_fixture_tests() -> int:
    cases = 0
    with tempfile.TemporaryDirectory(prefix="fence-cloudtrail-manifest-") as directory:
        root = Path(directory)
        envelope, trusted = _fixture(root)
        validate_cloudtrail_manifest(envelope, trusted, root, allow_test_only=True)
        cases += 1

        (root / "log-001").write_bytes(b"tampered raw log")
        try:
            validate_cloudtrail_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "SHA-256 mismatch" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("tampered raw CloudTrail log artifact was accepted")

        envelope, trusted = _fixture(root)
        report_path = root / "report-001"
        report = json.loads(report_path.read_text())
        report["digests"][0]["versionId"] = "null"
        report_bytes = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        report_path.write_bytes(report_bytes)
        report_artifact = next(item for item in envelope["manifestBody"]["artifacts"] if item["artifactType"] == "CLOUDTRAIL_VERIFICATION_REPORT")
        report_artifact["sha256"] = sha(report_bytes)
        report_artifact["byteCount"] = len(report_bytes)
        envelope, trusted = _signed_manifest(envelope["manifestBody"])
        try:
            validate_cloudtrail_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "exact non-null VersionId" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("null S3 VersionId in signed report was accepted")

        envelope, trusted = _fixture(root)
        body = envelope["manifestBody"]
        body["providerScope"]["region"] = "us-west-2"
        envelope, trusted = _signed_manifest(body)
        try:
            validate_cloudtrail_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "account/Region differs" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("report/manifest Region mismatch was accepted")
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--trusted-keys", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()
    supplied = (args.manifest, args.trusted_keys, args.artifact_root)
    if any(supplied) and not all(supplied):
        parser.error("--manifest, --trusted-keys and --artifact-root must be supplied together")
    if all(supplied):
        envelope = load_json(args.manifest)
        trust = load_json(args.trusted_keys)
        result = validate_cloudtrail_manifest(envelope, trust["keys"], args.artifact_root)
        print(f"CloudTrail evidence manifest binding: PASS ({result['manifestDigest']})")
        print(f"Digests: {result['digestCount']}; logs: {result['logCount']}; source artifacts: {result['sourceArtifactCount']}")
        print(f"Verification report artifact: {result['reportArtifactId']}")
        print("A valid cryptographic chain does not by itself prove complete delivery or production qualification.")
        return
    cases = run_fixture_tests()
    print("FENCE-001 CloudTrail report-to-manifest binding: PASS")
    print(f"Synthetic negative cases rejected: {cases}")
    print("Scope: ephemeral signing keys and synthetic artifacts only; no AWS account or provider API calls.")


if __name__ == "__main__":
    main()
