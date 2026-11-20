#!/usr/bin/env python3
"""Synthetic-only tests for dual-signed CloudTrail evidence manifest generation."""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from build_m0_fence_cloudtrail_evidence_manifest import build_manifest
from validate_m0_fence_cloudtrail_manifest_binding import (
    _fixture,
    validate_cloudtrail_manifest,
)


ACCOUNT = "123456789012"
REGION = "us-east-1"
BUCKET = "fixture-cloudtrail-bucket"
DIGEST_KEY = f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/2026/11/20/{ACCOUNT}_CloudTrail-Digest_{REGION}_fixture-trail_{REGION}_20261120T010000Z.json.gz"
LOG_KEY = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/2026/11/20/log.json.gz"


def object_artifact_id(kind: str, bucket: str, key: str, version: str) -> str:
    digest = hashlib.sha256(f"{bucket}\0{key}\0{version}".encode()).hexdigest()[:24]
    return f"cloudtrail-{kind}-{digest}.bin"


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        _fixture(root)
        report_bytes = (root / "report-001").read_bytes()
        report = json.loads(report_bytes)
        digest = report["digests"][0]
        digest_id = object_artifact_id("digest", BUCKET, DIGEST_KEY, "digest-version-001")
        log_id = object_artifact_id("log", BUCKET, LOG_KEY, "log-version-001")
        public_key_id = f"cloudtrail-public-key-{digest['publicKey']['derSha256'][:24]}.der"
        (root / digest_id).write_bytes((root / "digest-001").read_bytes())
        (root / log_id).write_bytes((root / "log-001").read_bytes())
        (root / public_key_id).write_bytes((root / "public-key-001").read_bytes())
        (root / "cloudtrail-verification-report.json").write_bytes(report_bytes)

        collector_arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/evidence-collector/fixture"
        verifier_arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/evidence-verifier/fixture"
        (root / "aws-sts-collector-identity.json").write_text(json.dumps({
            "identityRole": "COLLECTOR", "callerArn": collector_arn,
        }))
        (root / "aws-sts-independent-verifier-identity.json").write_text(json.dumps({
            "identityRole": "INDEPENDENT_VERIFIER", "callerArn": verifier_arn,
        }))
        (root / "cloudtrail-provider-exchange.json").write_text(json.dumps({
            "cloudTrailListPublicKeysRequestIds": ["cloudtrail-listkeys-001"],
            "inventoryListObjectVersionsRequestIds": ["s3-listversions-001"],
            "s3ObjectReads": [
                {"bucket": BUCKET, "key": DIGEST_KEY, "versionId": "digest-version-001", "artifactId": digest_id},
                {"bucket": BUCKET, "key": LOG_KEY, "versionId": "log-version-001", "artifactId": log_id},
            ],
            "regionalPublicKeys": [{
                "fingerprint": digest["publicKey"]["fingerprint"],
                "artifactId": public_key_id,
            }],
            "testOnly": True,
        }))
        artifacts = [
            digest_id, log_id, public_key_id, "cloudtrail-verification-report.json",
            "aws-sts-collector-identity.json", "aws-sts-independent-verifier-identity.json",
            "cloudtrail-provider-exchange.json",
        ]
        (root / "collection-bundle-index.json").write_text(json.dumps({
            "testOnly": True, "accountId": ACCOUNT, "region": REGION,
            "collectionEndTime": "2026-11-20T02:06:00Z", "artifacts": artifacts,
        }))

        collector_key = Ed25519PrivateKey.generate()
        verifier_key = Ed25519PrivateKey.generate()
        envelope, trust = build_manifest(
            root, collector_key, verifier_key,
            adapter_commit="a" * 40,
            configuration_digest="b" * 64,
            manifest_id="synthetic-cloudtrail-manifest",
        )
        result = validate_cloudtrail_manifest(envelope, trust, root, allow_test_only=True)
        assert result["digestCount"] == 1
        assert result["logCount"] == 1
        assert len(envelope["manifestBody"]["artifacts"]) == 4
        assert {x["role"] for x in envelope["attestations"]} == {"COLLECTOR", "INDEPENDENT_VERIFIER"}
        assert len({x["keyId"] for x in envelope["attestations"]}) == 2
        assert envelope["manifestBody"]["testOnly"] is True
        print("PASS generated manifest verifies against the existing FENCE-001 dual-signature and CloudTrail custody validators")

        try:
            build_manifest(
                root, collector_key, collector_key,
                adapter_commit="a" * 40,
                configuration_digest="b" * 64,
                manifest_id="same-key-must-fail",
            )
        except ValueError as error:
            assert "keys must differ" in str(error)
        else:
            raise AssertionError("same signing key was accepted for both roles")

        (root / digest_id).write_bytes(b"tampered source")
        try:
            validate_cloudtrail_manifest(envelope, trust, root, allow_test_only=True)
        except ValueError as error:
            assert "SHA-256 mismatch" in str(error)
        else:
            raise AssertionError("tampered raw digest artifact was accepted")
        print("PASS same-key reuse and post-signing source tampering are rejected")
        print("Manifest builder tests passed; all signing keys and provider data were synthetic.")


if __name__ == "__main__":
    main()
