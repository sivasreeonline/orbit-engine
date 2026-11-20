#!/usr/bin/env python3
"""Bind distinct collector/verifier AWS STS caller identities into a dual-signed FENCE-001 manifest."""
from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from validate_m0_fence_evidence_manifest import load_json, validate_manifest
from verify_m0_fence_evidence_artifact_bytes import verify_artifact_files
from validate_m0_fence_cloudtrail_manifest_binding import (
    _artifact,
    _read_artifact,
    _signed_manifest,
    _strict_json,
    sha,
)

IDENTITY_TYPE = "AWS_STS_CALLER_IDENTITY"
ROLE_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/(.+)$")
ASSUMED_ROLE_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sts::([0-9]{12}):assumed-role/([^/]+)/([^/]+)$"
)


def _validate_identity_report(
    report: dict[str, Any],
    *,
    expected_role: str,
    account_id: str,
    test_only: bool,
) -> dict[str, str]:
    if report.get("profile") != "sky-high-aws-sts-caller-identity-v1" or report.get("schemaVersion") != 1:
        raise ValueError("unsupported AWS STS caller identity report profile/version")
    if report.get("testOnly") is not test_only or report.get("verified") is not True:
        raise ValueError("AWS STS identity report testOnly/verified status differs from signed manifest")
    if report.get("identityRole") != expected_role:
        raise ValueError("AWS STS identity report role differs from its manifest artifact role")
    if report.get("expectedAccountId") != account_id or report.get("callerAccountId") != account_id:
        raise ValueError("AWS STS caller account differs from the signed manifest account")
    expected_arn = report.get("expectedRoleArn")
    expected = ROLE_ARN.fullmatch(expected_arn) if isinstance(expected_arn, str) else None
    if expected is None:
        raise ValueError("AWS STS expectedRoleArn is not a supported IAM role ARN")
    expected_partition, expected_account, expected_path = expected.groups()
    expected_name = expected_path.rsplit("/", 1)[-1]
    if expected_account != account_id:
        raise ValueError("AWS STS expectedRoleArn account differs from signed manifest account")

    caller_arn = report.get("callerArn")
    caller = ASSUMED_ROLE_ARN.fullmatch(caller_arn) if isinstance(caller_arn, str) else None
    if caller is None:
        raise ValueError("AWS STS caller ARN must be an assumed-role principal")
    partition, caller_account, role_name, session_name = caller.groups()
    if partition != expected_partition or caller_account != account_id or role_name != expected_name:
        raise ValueError("AWS STS caller ARN does not match the expected IAM role")
    if report.get("partition") != partition or report.get("roleName") != role_name or report.get("sessionName") != session_name:
        raise ValueError("AWS STS report parsed identity fields differ from caller ARN")
    user_id = report.get("callerUserId")
    if not isinstance(user_id, str) or not user_id or user_id.rsplit(":", 1)[-1] != session_name:
        raise ValueError("AWS STS UserId session suffix differs from caller ARN")
    request_id = report.get("requestId")
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("AWS STS RequestId is required for identity evidence")
    return {
        "expectedRoleArn": expected_arn,
        "callerArn": caller_arn,
        "roleName": role_name,
        "sessionName": session_name,
        "requestId": request_id,
    }


def validate_identity_manifest(
    envelope: dict[str, Any],
    trusted_keys: list[dict[str, str]],
    artifact_root: Path,
    *,
    allow_test_only: bool = False,
) -> dict[str, Any]:
    manifest_digest = validate_manifest(envelope, trusted_keys, allow_test_only=allow_test_only)
    body = envelope["manifestBody"]
    if body["providerScope"]["name"].lower() not in {"aws", "amazon-web-services"}:
        raise ValueError("AWS STS identity evidence requires an AWS provider scope")
    account_id = body["providerScope"]["account"]
    root = artifact_root.resolve(strict=True)
    verify_artifact_files(body, root)
    artifacts = [item for item in body["artifacts"] if item["artifactType"] == IDENTITY_TYPE]
    if len(artifacts) != 2:
        raise ValueError("manifest must contain exactly two AWS STS caller identity artifacts")
    by_role: dict[str, dict[str, str]] = {}
    for artifact in artifacts:
        if "CT-009" not in artifact["testIds"]:
            raise ValueError("AWS STS identity artifact lacks CT-009")
        raw = _read_artifact(root, artifact["artifactId"])
        report = _strict_json(raw, "AWS STS caller identity report")
        identity_role = report.get("identityRole")
        if identity_role not in {"COLLECTOR", "INDEPENDENT_VERIFIER"}:
            raise ValueError("AWS STS identity role must be COLLECTOR or INDEPENDENT_VERIFIER")
        if identity_role in by_role:
            raise ValueError("duplicate AWS STS identity role in manifest")
        identity = _validate_identity_report(
            report,
            expected_role=identity_role,
            account_id=account_id,
            test_only=body["testOnly"],
        )
        expected_ref = f"aws-sts-caller-identity://{account_id}/{identity_role}"
        if artifact["objectRef"] != expected_ref or artifact["objectVersion"] != identity["sessionName"]:
            raise ValueError("AWS STS identity artifact object reference/version differs from report")
        by_role[identity_role] = identity

    if set(by_role) != {"COLLECTOR", "INDEPENDENT_VERIFIER"}:
        raise ValueError("manifest must contain collector and independent verifier STS identities")
    collector = by_role["COLLECTOR"]
    verifier = by_role["INDEPENDENT_VERIFIER"]
    if collector["expectedRoleArn"] == verifier["expectedRoleArn"] or collector["roleName"] == verifier["roleName"]:
        raise ValueError("collector and independent verifier must use distinct IAM roles")
    if collector["callerArn"] == verifier["callerArn"]:
        raise ValueError("collector and independent verifier caller ARNs must be distinct")
    if collector["requestId"] == verifier["requestId"]:
        raise ValueError("collector and independent verifier STS request IDs must be distinct")
    return {
        "manifestDigest": manifest_digest,
        "accountId": account_id,
        "collectorCallerArn": collector["callerArn"],
        "verifierCallerArn": verifier["callerArn"],
        "collectorRoleArn": collector["expectedRoleArn"],
        "verifierRoleArn": verifier["expectedRoleArn"],
        "testOnly": body["testOnly"],
    }


def _identity_report(role: str, account: str, role_name: str, session: str, request_id: str) -> dict[str, Any]:
    return {
        "profile": "sky-high-aws-sts-caller-identity-v1",
        "schemaVersion": 1,
        "testOnly": True,
        "identityRole": role,
        "verified": True,
        "expectedAccountId": account,
        "expectedRoleArn": f"arn:aws:iam::{account}:role/skyhigh/{role_name}",
        "callerAccountId": account,
        "callerArn": f"arn:aws:sts::{account}:assumed-role/{role_name}/{session}",
        "callerUserId": f"AROA{role_name.upper()}ID:{session}",
        "partition": "aws",
        "roleName": role_name,
        "sessionName": session,
        "requestId": request_id,
    }


def _fixture(root: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    account = "123456789012"
    reports = [
        ("COLLECTOR", "evidence-collector", "collector-session", "sts-collector-001"),
        ("INDEPENDENT_VERIFIER", "evidence-verifier", "verifier-session", "sts-verifier-001"),
    ]
    artifacts = []
    for index, (role, role_name, session, request_id) in enumerate(reports, start=1):
        report = _identity_report(role, account, role_name, session, request_id)
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        artifact_id = f"sts-identity-{index:03d}"
        (root / artifact_id).write_bytes(raw)
        artifacts.append(_artifact(
            artifact_id,
            IDENTITY_TYPE,
            f"aws-sts-caller-identity://{account}/{role}",
            session,
            raw,
            ["CT-009"],
        ))
    body = {
        "profile": "sky-high-fence-evidence-manifest-v1",
        "schemaVersion": 1,
        "manifestId": "sts-identity-fixture",
        "createdAt": "2026-11-20T00:00:00Z",
        "testOnly": True,
        "providerScope": {"name": "aws", "account": account, "region": "us-east-1", "service": "cloudtrail"},
        "adapter": {
            "repository": "https://example.invalid/sts-identity",
            "commit": "1" * 40,
            "version": "fixture-1",
            "configurationDigest": "2" * 64,
        },
        "artifacts": artifacts,
    }
    return _signed_manifest(body)


def run_fixture_tests() -> int:
    cases = 0
    with tempfile.TemporaryDirectory(prefix="fence-sts-identity-") as directory:
        root = Path(directory)
        envelope, trusted = _fixture(root)
        result = validate_identity_manifest(envelope, trusted, root, allow_test_only=True)
        if result["collectorCallerArn"] == result["verifierCallerArn"]:
            raise AssertionError("collector and verifier identities unexpectedly match")
        cases += 1

        envelope, trusted = _fixture(root)
        verifier_path = root / "sts-identity-002"
        report = _strict_json(verifier_path.read_bytes(), "fixture identity")
        report["expectedRoleArn"] = "arn:aws:iam::123456789012:role/skyhigh/evidence-collector"
        report["callerArn"] = "arn:aws:sts::123456789012:assumed-role/evidence-collector/verifier-session"
        report["roleName"] = "evidence-collector"
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        verifier_path.write_bytes(raw)
        artifact = next(item for item in envelope["manifestBody"]["artifacts"] if item["artifactId"] == "sts-identity-002")
        artifact["sha256"] = sha(raw)
        artifact["byteCount"] = len(raw)
        envelope, trusted = _signed_manifest(envelope["manifestBody"])
        try:
            validate_identity_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "distinct IAM roles" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("same collector/verifier IAM role was accepted")

        envelope, trusted = _fixture(root)
        (root / "sts-identity-001").write_bytes(b"tampered identity")
        try:
            validate_identity_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "SHA-256 mismatch" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("tampered STS identity evidence was accepted")
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
        result = validate_identity_manifest(envelope, trust["keys"], args.artifact_root)
        print(f"AWS STS dual-principal identity binding: PASS ({result['manifestDigest']})")
        print(f"Collector: {result['collectorCallerArn']}")
        print(f"Independent verifier: {result['verifierCallerArn']}")
        return
    cases = run_fixture_tests()
    print("FENCE-001 AWS STS identity manifest binding: PASS")
    print(f"Synthetic negative cases rejected: {cases}")
    print("Scope: two synthetic STS responses and a dual-signed test-only manifest; no AWS credentials or API calls.")


if __name__ == "__main__":
    main()
