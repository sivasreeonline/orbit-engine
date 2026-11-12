#!/usr/bin/env python3
"""Validate the FENCE-001 external witness qualification record template and gate rules.

This checks repository-owned record structure only. It does not qualify a provider,
verify external evidence, or authorize production use.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import tempfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from validate_m0_fence_evidence_manifest import validate_manifest as validate_evidence_manifest
from verify_m0_fence_evidence_artifact_bytes import verify_artifact_files

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "docs/schemas/m0-fence-witness-qualification-record.schema.json"
TEMPLATE = ROOT / "docs/templates/m0-fence-witness-qualification-record.json"
EXPECTED_IDS = tuple(f"WIT-{number:03d}" for number in range(1, 15))


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def semantic_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    tests = record.get("tests", [])
    ids = [item.get("id") for item in tests]
    if len(ids) != len(set(ids)):
        errors.append("duplicate qualification test ID")
    if tuple(sorted(ids)) != tuple(sorted(EXPECTED_IDS)):
        errors.append("qualification test inventory must contain WIT-001 through WIT-014 exactly")

    for item in tests:
        test_id = item.get("id", "<missing>")
        evidence = item.get("evidence", [])
        if item.get("status") == "PASS" and not evidence:
            errors.append(f"{test_id}: PASS requires immutable evidence")
        if item.get("status") == "NOT_RUN" and evidence:
            errors.append(f"{test_id}: NOT_RUN must not carry evidence")
        if item.get("status") == "PASS" and (
            record.get("provider") is None or record.get("adapter") is None
        ):
            errors.append(f"{test_id}: PASS requires an explicitly pinned provider and adapter")
        provider = record.get("provider")
        adapter = record.get("adapter")
        expected_scope = None
        if provider is not None and adapter is not None:
            expected_scope = "|".join((
                provider["name"], provider["account"], provider["region"],
                provider["service"], adapter["commit"],
            ))
        for entry in evidence:
            if entry.get("collectorIdentity") == entry.get("independentVerifierIdentity"):
                errors.append(f"{test_id}: evidence collector and independent verifier must differ")
            if expected_scope is not None and entry.get("providerScope") != expected_scope:
                errors.append(f"{test_id}: evidence providerScope does not match the pinned provider/adapter")

    monitor_ids = [item.get("monitorId") for item in record.get("monitors", {}).get("identities", [])]
    if len(monitor_ids) != len(set(monitor_ids)):
        errors.append("monitor identities must be unique")
    if record.get("qualificationStatus") == "NOT_STARTED" and any(
        item.get("status") != "NOT_RUN" for item in tests
    ):
        errors.append("NOT_STARTED requires every mandatory test to remain NOT_RUN")
    if record.get("qualificationStatus") == "READY_FOR_INDEPENDENT_REVIEW":
        if any(item.get("status") != "PASS" for item in tests):
            errors.append("READY_FOR_INDEPENDENT_REVIEW requires every mandatory test to PASS")
        if record.get("provider") is None or record.get("adapter") is None:
            errors.append("READY_FOR_INDEPENDENT_REVIEW requires a pinned provider and adapter")
        monitors = record.get("monitors", {}).get("identities", [])
        if (
            len(monitors) < 2
            or len({item.get("operator") for item in monitors}) < 2
            or len({item.get("account") for item in monitors}) < 2
            or len({item.get("failureDomain") for item in monitors}) < 2
        ):
            errors.append("READY_FOR_INDEPENDENT_REVIEW requires two monitors with distinct operators, accounts and failure domains")
        if not record.get("monitors", {}).get("independenceEvidence"):
            errors.append("READY_FOR_INDEPENDENT_REVIEW requires monitor-independence evidence")
        reviewer = record.get("independentSecurityReviewer")
        if reviewer is None:
            errors.append("READY_FOR_INDEPENDENT_REVIEW requires a named independent security reviewer")
        if record.get("evidenceManifest") is None:
            errors.append("READY_FOR_INDEPENDENT_REVIEW requires a signed evidence manifest reference")
    if record.get("productionApproval") is not False:
        errors.append("productionApproval must remain false in this qualification record")
    return errors


def expect_rejected(label: str, record: dict[str, Any], schema_validator: Draft202012Validator) -> None:
    schema_errors = list(schema_validator.iter_errors(record))
    semantic = semantic_errors(record)
    if not schema_errors and not semantic:
        raise AssertionError(f"negative qualification case unexpectedly passed: {label}")


def validate_record_manifest_binding(
    record: dict[str, Any],
    manifest_envelope: dict[str, Any],
    trusted_keys: list[dict[str, str]],
    *,
    allow_test_only: bool = False,
    artifact_root: Path | None = None,
) -> None:
    digest = validate_evidence_manifest(manifest_envelope, trusted_keys, allow_test_only=allow_test_only)
    if artifact_root is None:
        raise ValueError("materialized artifact root is required for evidence qualification")
    verify_artifact_files(manifest_envelope["manifestBody"], artifact_root)
    reference = record.get("evidenceManifest")
    if reference is None:
        raise ValueError("qualification record does not reference a signed evidence manifest")
    body = manifest_envelope["manifestBody"]
    if reference["manifestId"] != body["manifestId"] or reference["sha256"] != digest:
        raise ValueError("qualification record manifest identity/digest does not match verified manifest")
    if record.get("provider") is None or record.get("adapter") is None:
        raise ValueError("manifest binding requires pinned provider and adapter in qualification record")
    provider = record["provider"]
    scope = body["providerScope"]
    if any(provider[field] != scope[field] for field in ("name", "account", "region", "service")):
        raise ValueError("qualification provider scope differs from signed evidence manifest")
    adapter = record["adapter"]
    manifest_adapter = body["adapter"]
    if any(adapter[field] != manifest_adapter[field] for field in ("repository", "commit", "version", "configurationDigest")):
        raise ValueError("qualification adapter pin differs from signed evidence manifest")

    artifact_index = {
        (item["objectRef"], item["objectVersion"], item["sha256"], item["byteCount"]): item
        for item in body["artifacts"]
    }
    for test in record.get("tests", []):
        if test.get("status") != "PASS":
            continue
        for evidence in test.get("evidence", []):
            key = (evidence["objectRef"], evidence["objectVersion"], evidence["sha256"], evidence["byteCount"])
            artifact = artifact_index.get(key)
            if artifact is None:
                raise ValueError(f"{test['id']}: PASS evidence is absent from signed manifest")
            if test["id"] not in artifact["testIds"]:
                raise ValueError(f"{test['id']}: manifest artifact is not bound to this qualification control")
            if evidence["collectorIdentity"] != artifact["collectorIdentity"]:
                raise ValueError(f"{test['id']}: evidence collector differs from manifest")
            if evidence["independentVerifierIdentity"] != artifact["independentVerifierIdentity"]:
                raise ValueError(f"{test['id']}: independent verifier differs from manifest")


def run_manifest_binding_fixture_tests() -> int:
    vector = load_json(ROOT / "docs/test-vectors/fence-evidence-manifest-v1.json")
    envelope = {key: vector[key] for key in ("manifestBody", "manifestDigest", "attestations")}
    body = envelope["manifestBody"]
    artifact = body["artifacts"][0]
    record = load_json(TEMPLATE)
    record["provider"] = {
        **body["providerScope"],
        "contractReference": "fixture-only",
    }
    record["adapter"] = body["adapter"]
    record["evidenceManifest"] = {
        "manifestId": body["manifestId"],
        "objectRef": "fixture://manifests/001",
        "objectVersion": "immutable-v1",
        "sha256": envelope["manifestDigest"],
    }
    record["tests"][0]["status"] = "PASS"
    record["tests"][0]["evidence"] = [{
        "objectRef": artifact["objectRef"],
        "objectVersion": artifact["objectVersion"],
        "sha256": artifact["sha256"],
        "byteCount": artifact["byteCount"],
        "acquiredAt": artifact["acquiredAt"],
        "acquisitionMethod": "synthetic signed-vector fixture",
        "collectorIdentity": artifact["collectorIdentity"],
        "independentVerifierIdentity": artifact["independentVerifierIdentity"],
        "providerScope": "|".join((
            body["providerScope"]["name"], body["providerScope"]["account"],
            body["providerScope"]["region"], body["providerScope"]["service"],
            body["adapter"]["commit"],
        )),
        "redaction": artifact["redaction"],
    }]
    with tempfile.TemporaryDirectory(prefix="fence-qualification-fixture-") as directory:
        artifact_root = Path(directory)
        (artifact_root / artifact["artifactId"]).write_bytes(b"synthetic provider evidence fixture only\n")
        validate_record_manifest_binding(
            record, envelope, vector["trustedKeys"],
            allow_test_only=True, artifact_root=artifact_root,
        )
    rejected = 0

    wrong_provider = copy.deepcopy(record)
    wrong_provider["provider"]["account"] = "different-account"
    try:
        validate_record_manifest_binding(wrong_provider, envelope, vector["trustedKeys"], allow_test_only=True)
    except ValueError:
        rejected += 1
    else:
        raise AssertionError("provider substitution in qualification record was accepted")

    wrong_manifest_digest = copy.deepcopy(record)
    wrong_manifest_digest["evidenceManifest"]["sha256"] = "f" * 64
    try:
        validate_record_manifest_binding(wrong_manifest_digest, envelope, vector["trustedKeys"], allow_test_only=True)
    except ValueError:
        rejected += 1
    else:
        raise AssertionError("manifest digest substitution in qualification record was accepted")

    unmanifested_artifact = copy.deepcopy(record)
    unmanifested_artifact["tests"][0]["evidence"][0]["objectRef"] = "fixture://evidence/not-in-manifest"
    try:
        validate_record_manifest_binding(unmanifested_artifact, envelope, vector["trustedKeys"], allow_test_only=True)
    except ValueError:
        rejected += 1
    else:
        raise AssertionError("PASS evidence absent from signed manifest was accepted")

    return rejected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, default=TEMPLATE, help="qualification record JSON (defaults to blank repository template)")
    parser.add_argument("--evidence-manifest", type=Path, help="dual-signed evidence manifest envelope JSON")
    parser.add_argument("--trusted-keys", type=Path, help="independently provisioned trusted-key configuration JSON")
    parser.add_argument("--artifact-root", type=Path, help="directory containing independently materialized evidence files")
    args = parser.parse_args()
    if len([value for value in (args.evidence_manifest, args.trusted_keys, args.artifact_root) if value]) not in (0, 3):
        parser.error("--evidence-manifest, --trusted-keys and --artifact-root must be supplied together")

    schema = load_json(SCHEMA)
    record = load_json(args.record)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    schema_errors = list(validator.iter_errors(record))
    if schema_errors:
        raise SystemExit(f"blank qualification template failed schema: {schema_errors[0].message}")
    semantic = semantic_errors(record)
    if semantic:
        raise SystemExit("blank qualification template failed semantic checks: " + "; ".join(semantic))
    needs_manifest_verification = (
        record.get("evidenceManifest") is not None
        or record.get("qualificationStatus") == "READY_FOR_INDEPENDENT_REVIEW"
        or any(item.get("status") == "PASS" for item in record.get("tests", []))
    )
    if needs_manifest_verification and not args.evidence_manifest:
        raise SystemExit("PASS evidence or review readiness requires --evidence-manifest and --trusted-keys")

    if args.record.resolve() == TEMPLATE.resolve():
        if record["qualificationStatus"] != "NOT_STARTED":
            raise SystemExit("template must start NOT_STARTED")
        if record["provider"] is not None or record["adapter"] is not None:
            raise SystemExit("template must not select a provider or adapter")
        if any(item["status"] != "NOT_RUN" or item["evidence"] for item in record["tests"]):
            raise SystemExit("template must contain only NOT_RUN tests and no evidence")
        if record["productionApproval"] is not False:
            raise SystemExit("template must keep production approval false")

    if args.record.resolve() == TEMPLATE.resolve():
        # Exercise important fail-closed semantic boundaries using mutations of the blank template.
        missing_test = copy.deepcopy(record)
        missing_test["tests"].pop()
        expect_rejected("missing mandatory test", missing_test, validator)

        duplicate_test = copy.deepcopy(record)
        duplicate_test["tests"][-1]["id"] = duplicate_test["tests"][0]["id"]
        expect_rejected("duplicate test ID", duplicate_test, validator)

        pass_without_evidence = copy.deepcopy(record)
        pass_without_evidence["tests"][0]["status"] = "PASS"
        expect_rejected("PASS without evidence", pass_without_evidence, validator)

        approval_attempt = copy.deepcopy(record)
        approval_attempt["productionApproval"] = True
        expect_rejected("production approval flag", approval_attempt, validator)

        same_reviewer = copy.deepcopy(record)
        same_reviewer["provider"] = {
            "name": "synthetic-provider", "account": "fixture-account",
            "region": "fixture-region", "service": "fixture-witness",
            "contractReference": "fixture-only"
        }
        same_reviewer["adapter"] = {
            "repository": "https://example.invalid/adapter", "commit": "1" * 40,
            "version": "fixture-only", "configurationDigest": "2" * 64
        }
        same_reviewer["tests"][0]["status"] = "PASS"
        same_reviewer["tests"][0]["evidence"] = [{
            "objectRef": "evidence://synthetic/1", "objectVersion": "v1",
            "sha256": "a" * 64, "byteCount": 1, "acquiredAt": "2026-01-01T00:00:00Z",
            "acquisitionMethod": "synthetic negative fixture", "collectorIdentity": "reviewer-1",
            "independentVerifierIdentity": "reviewer-1",
            "providerScope": "synthetic-provider|fixture-account|fixture-region|fixture-witness|" + "1" * 40,
            "redaction": "NONE"
        }]
        reviewer_errors = semantic_errors(same_reviewer)
        if not any("collector and independent verifier must differ" in error for error in reviewer_errors):
            raise AssertionError("same collector/verifier identity was not specifically rejected")


    binding_negative_cases = run_manifest_binding_fixture_tests()
    if args.evidence_manifest:
        manifest_envelope = load_json(args.evidence_manifest)
        trust_document = load_json(args.trusted_keys)
        if not isinstance(trust_document.get("keys"), list):
            raise SystemExit("trusted-key document must contain a keys array")
        validate_record_manifest_binding(
            record, manifest_envelope, trust_document["keys"],
            artifact_root=args.artifact_root,
        )
        print("Signed evidence manifest binding: PASS")

    print("FENCE-001 external witness qualification record: PASS")
    print(f"Mandatory test inventory: {len(EXPECTED_IDS)} unique controls")
    if record.get("qualificationStatus") == "NOT_STARTED":
        print("Record: NOT_STARTED; no provider qualification claimed")
    else:
        print(f"Record status: {record['qualificationStatus']}")
    print("Negative gate cases: missing/duplicate test, PASS without evidence, same reviewer, production approval")
    print(f"Manifest-binding negative cases rejected: {binding_negative_cases}")
    print("Scope: manifest binding and record validation only; no provider qualification or production authorization")


if __name__ == "__main__":
    main()
