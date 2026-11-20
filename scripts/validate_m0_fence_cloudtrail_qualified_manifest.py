#!/usr/bin/env python3
"""Run the combined CloudTrail custody, inventory and dual-principal STS gate."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from validate_m0_fence_cloudtrail_manifest_binding import (
    _artifact,
    _identity_report if False else _artifact,
)
from validate_m0_fence_cloudtrail_manifest_binding import _signed_manifest
from validate_m0_fence_cloudtrail_digest_inventory import _inventory_fixture, validate_inventory_manifest
from validate_m0_fence_cloudtrail_manifest_binding import validate_cloudtrail_manifest
from validate_m0_fence_aws_identity_manifest import (
    IDENTITY_TYPE,
    _identity_report,
    validate_identity_manifest,
)


def validate_qualified_manifest(
    envelope: dict[str, Any],
    trusted_keys: list[dict[str, str]],
    artifact_root: Path,
    *,
    allow_test_only: bool = False,
) -> dict[str, Any]:
    cloudtrail = validate_cloudtrail_manifest(
        envelope, trusted_keys, artifact_root, allow_test_only=allow_test_only
    )
    identity = validate_identity_manifest(
        envelope, trusted_keys, artifact_root, allow_test_only=allow_test_only
    )
    inventory = validate_inventory_manifest(
        envelope, trusted_keys, artifact_root, allow_test_only=allow_test_only
    )
    body = envelope["manifestBody"]
    return {
        "profile": "sky-high-fence-cloudtrail-qualified-manifest-v1",
        "schemaVersion": 1,
        "testOnly": body["testOnly"],
        "evidenceGateStatus": "CUSTODY_IDENTITY_AND_INVENTORY_RECONCILED",
        "productionQualificationReady": False,
        "externalQualificationStatus": "REQUIRED",
        "accountId": body["providerScope"]["account"],
        "region": body["providerScope"]["region"],
        "manifestDigest": cloudtrail["manifestDigest"],
        "cloudtrailReportArtifactId": cloudtrail["reportArtifactId"],
        "collectorCallerArn": identity["collectorCallerArn"],
        "verifierCallerArn": identity["verifierCallerArn"],
        "inventoryStatus": inventory["status"],
        "completeWithinCapturedInventory": inventory["completeWithinCapturedInventory"],
        "absoluteSnapshotCompleteness": inventory["absoluteSnapshotCompleteness"],
        "externalQualificationRequirements": [
            "Compare digest bytes and signatures with AWS CLI cloudtrail validate-logs using an independently acquired real digest fixture.",
            "Run the read-only adapters with separately governed collector and verifier AWS roles and preserve their STS evidence.",
            "Qualify the actual S3 bucket versioning, Object Lock mode, retention, IAM policy and delete-marker behavior.",
            "Obtain a repeat or independently governed point-in-time S3 inventory to address non-atomic ListObjectVersions pagination.",
            "Verify all required backfill chains and define the expected CloudTrail delivery time window.",
            "Keep host admission and student-code execution disabled until the separate runtime qualification gates pass.",
        ],
    }


def _qualified_fixture(root: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    envelope, trusted = _inventory_fixture(root)
    body = envelope["manifestBody"]
    account = body["providerScope"]["account"]
    identities = [
        ("COLLECTOR", "evidence-collector", "collector-session", "sts-collector-001"),
        ("INDEPENDENT_VERIFIER", "evidence-verifier", "verifier-session", "sts-verifier-001"),
    ]
    for index, (role, role_name, session, request_id) in enumerate(identities, start=1):
        report = _identity_report(role, account, role_name, session, request_id)
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        artifact_id = f"qualified-sts-identity-{index:03d}"
        (root / artifact_id).write_bytes(raw)
        body["artifacts"].append(_artifact(
            artifact_id,
            IDENTITY_TYPE,
            f"aws-sts-caller-identity://{account}/{role}",
            session,
            raw,
            ["CT-009"],
        ))
    return _signed_manifest(body)


def run_fixture_tests() -> int:
    cases = 0
    with tempfile.TemporaryDirectory(prefix="fence-cloudtrail-qualified-") as directory:
        root = Path(directory)
        envelope, trusted = _qualified_fixture(root)
        result = validate_qualified_manifest(envelope, trusted, root, allow_test_only=True)
        if result["productionQualificationReady"] or result["evidenceGateStatus"] != "CUSTODY_IDENTITY_AND_INVENTORY_RECONCILED":
            raise AssertionError("synthetic combined gate claimed production readiness or failed reconciliation")
        cases += 1

        envelope, trusted = _qualified_fixture(root)
        verifier_path = root / "qualified-sts-identity-002"
        report = json.loads(verifier_path.read_text(encoding="utf-8"))
        report["expectedRoleArn"] = report["expectedRoleArn"].replace("evidence-verifier", "evidence-collector")
        report["callerArn"] = report["callerArn"].replace("evidence-verifier", "evidence-collector")
        report["roleName"] = "evidence-collector"
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        verifier_path.write_bytes(raw)
        artifact = next(item for item in envelope["manifestBody"]["artifacts"] if item["artifactId"] == "qualified-sts-identity-002")
        artifact["sha256"] = __import__("hashlib").sha256(raw).hexdigest()
        artifact["byteCount"] = len(raw)
        envelope, trusted = _signed_manifest(envelope["manifestBody"])
        try:
            validate_qualified_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "distinct IAM roles" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("combined gate accepted one role for collector and verifier")

        envelope, trusted = _qualified_fixture(root)
        envelope["manifestBody"]["artifacts"] = [
            item for item in envelope["manifestBody"]["artifacts"]
            if item["artifactType"] != IDENTITY_TYPE or item["artifactId"] != "qualified-sts-identity-002"
        ]
        envelope, trusted = _signed_manifest(envelope["manifestBody"])
        try:
            validate_qualified_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "exactly two AWS STS caller identity artifacts" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("combined gate accepted a manifest missing verifier identity")

        envelope, trusted = _qualified_fixture(root)
        (root / "qualified-sts-identity-001").write_bytes(b"tampered")
        try:
            validate_qualified_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "SHA-256 mismatch" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("combined gate accepted tampered STS identity bytes")
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
        envelope = json.loads(args.manifest.read_text(encoding="utf-8"))
        trust = json.loads(args.trusted_keys.read_text(encoding="utf-8"))
        result = validate_qualified_manifest(envelope, trust["keys"], args.artifact_root)
        print(f"CloudTrail FENCE-001 combined evidence gate: {result['evidenceGateStatus']}")
        print(f"External qualification: {result['externalQualificationStatus']}")
        print(f"Production qualification ready: {result['productionQualificationReady']}")
        return
    cases = run_fixture_tests()
    print("FENCE-001 combined CloudTrail qualification gate: PASS")
    print(f"Synthetic negative cases rejected: {cases}")
    print("Production qualification remains false; external AWS evidence is still required.")


if __name__ == "__main__":
    main()
