#!/usr/bin/env python3
"""Validate the FENCE-001 external witness qualification record template and gate rules.

This checks repository-owned record structure only. It does not qualify a provider,
verify external evidence, or authorize production use.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

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
    if record.get("productionApproval") is not False:
        errors.append("productionApproval must remain false in this qualification record")
    return errors


def expect_rejected(label: str, record: dict[str, Any], schema_validator: Draft202012Validator) -> None:
    schema_errors = list(schema_validator.iter_errors(record))
    semantic = semantic_errors(record)
    if not schema_errors and not semantic:
        raise AssertionError(f"negative qualification case unexpectedly passed: {label}")


def main() -> None:
    schema = load_json(SCHEMA)
    record = load_json(TEMPLATE)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    schema_errors = list(validator.iter_errors(record))
    if schema_errors:
        raise SystemExit(f"blank qualification template failed schema: {schema_errors[0].message}")
    semantic = semantic_errors(record)
    if semantic:
        raise SystemExit("blank qualification template failed semantic checks: " + "; ".join(semantic))
    if record["qualificationStatus"] != "NOT_STARTED":
        raise SystemExit("template must start NOT_STARTED")
    if record["provider"] is not None or record["adapter"] is not None:
        raise SystemExit("template must not select a provider or adapter")
    if any(item["status"] != "NOT_RUN" or item["evidence"] for item in record["tests"]):
        raise SystemExit("template must contain only NOT_RUN tests and no evidence")
    if record["productionApproval"] is not False:
        raise SystemExit("template must keep production approval false")

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

    print("FENCE-001 external witness qualification record: PASS")
    print(f"Mandatory test inventory: {len(EXPECTED_IDS)} unique controls")
    print("Blank record: NOT_STARTED; provider/adapter unselected; all tests NOT_RUN")
    print("Negative gate cases: missing/duplicate test, PASS without evidence, same reviewer, production approval")
    print("Scope: record/schema validation only; no provider qualification or production authorization")


if __name__ == "__main__":
    main()
