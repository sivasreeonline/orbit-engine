#!/usr/bin/env python3
"""Validate M0 evidence schema invariants using synthetic, non-sensitive data."""

import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-proof-evidence.schema.json"
FIXTURE_CONTRACT_PATH = ROOT / "docs/specifications/m0-adversarial-fixture-contract.md"
REQUIRED_FIXTURE_IDS = (
    "M0-RUN-JAVA-001",
    "M0-RUN-PY-001",
    "M0-RUN-JAVA-002",
    "M0-RUN-003",
    "M0-RUN-004",
    "M0-ID-001",
    "M0-ID-002",
    "M0-HOST-001",
    "M0-HOST-002",
    "M0-HOST-003",
    "M0-HOST-004",
    "M0-HOST-005",
    "M0-NET-001",
    "M0-NET-002",
    "M0-NET-003",
    "M0-NET-004",
    "M0-NET-005",
    "M0-NET-006",
    "M0-RES-CPU-001",
    "M0-RES-MEM-001",
    "M0-RES-PID-001",
    "M0-RES-TIME-001",
    "M0-RES-FS-001",
    "M0-RES-FS-002",
    "M0-RES-FS-003",
    "M0-RES-OUT-001",
    "M0-RES-OUT-002",
    "M0-LIFE-CLEAN-001",
    "M0-LIFE-CLEAN-002",
    "M0-LIFE-CANCEL-001",
    "M0-LIFE-DUP-001",
    "M0-LIFE-RESTART-RUNNER-001",
    "M0-LIFE-RESTART-SUPERVISOR-001",
    "M0-LIFE-RESTART-CONTAINERD-001",
    "M0-LIFE-REPEAT-001",
)


def fixture_ids_from_contract():
    pattern = re.compile(r"^\|\s*`(M0-[A-Z0-9-]+)`\s*\|")
    return {
        match.group(1)
        for line in FIXTURE_CONTRACT_PATH.read_text(encoding="utf-8").splitlines()
        if (match := pattern.match(line))
    }


def validate_fixture_contract_alignment(schema):
    contract_ids = fixture_ids_from_contract()
    if contract_ids != set(REQUIRED_FIXTURE_IDS):
        missing = sorted(set(REQUIRED_FIXTURE_IDS) - contract_ids)
        unexpected = sorted(contract_ids - set(REQUIRED_FIXTURE_IDS))
        raise AssertionError(
            "fixture contract/validator mismatch; missing="
            + ",".join(missing) + "; unexpected=" + ",".join(unexpected)
        )

    passed_tests = schema["allOf"][0]["then"]["properties"]["tests"]
    schema_ids = {
        rule["contains"]["properties"]["test_id"]["const"].upper()
        for rule in passed_tests["allOf"]
    }
    if schema_ids != contract_ids:
        raise AssertionError("fixture contract and JSON Schema contains rules differ")
    if passed_tests.get("minItems") != len(contract_ids):
        raise AssertionError("passed-result schema minItems does not match fixture contract")
    if passed_tests.get("maxItems") != len(contract_ids):
        raise AssertionError("passed-result schema maxItems does not match fixture contract")


def valid_manifest():
    return {
        "schema_version": "1.0.0",
        "proof_run_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "generated_at": "2026-11-10T00:00:00Z",
        "baseline": {
            "os": "Ubuntu Server 24.04 LTS",
            "architecture": "x86_64",
            "containerd_major_minor": "2.3",
            "containerd_config_version": 3,
            "runtime_handler": "io.containerd.runsc.v1",
            "required_platform": "systrap",
        },
        "host": {
            "image_identifier": "synthetic-proof-image",
            "kernel_release": "6.8.0-synthetic",
            "cgroup_mode": "v2",
            "provider": "synthetic-provider",
            "region": "synthetic-region",
        },
        "runtime": {
            "containerd_version": "2.3.1",
            "runsc_version": "runsc-synthetic",
            "shim_version": "shim-synthetic",
            "runtime_handler": "io.containerd.runsc.v1",
            "platform": "systrap",
            "oci_image_digest": "sha256:" + "a" * 64,
        },
        "resource_profile": {
            "profile_id": "m0-proof-small-v1",
            "revision": "1",
            "cpu_quota_millis": 1000,
            "memory_bytes": 1073741824,
            "wall_time_millis": 60000,
            "process_limit": 128,
            "output_bytes_total": 1048576,
            "stdout_bytes_max": 1048576,
            "stderr_bytes_max": 1048576,
            "scratch_bytes": 268435456,
            "scratch_inodes": 4096,
        },
        "fixture": {
            "repository_revision": "b" * 40,
            "image_digest": "sha256:" + "c" * 64,
        },
        "tests": [
            {
                "test_id": fixture_id.lower(),
                "phase": "runtime",
                "status": "passed",
                "expected_outcome": "Synthetic fixture completes",
                "observed_outcome": "Synthetic fixture completes",
                "exit_code": 0,
                "duration_ms": 1,
                "evidence": [{
                    "relative_path": "synthetic/evidence.txt",
                    "sha256": "d" * 64,
                    "bytes": 0,
                    "redacted": True,
                }],
            }
            for fixture_id in REQUIRED_FIXTURE_IDS
        ],
        "overall_result": "passed",
        "security_review": {
            "decision": "approved",
            "reviewed_at": "2026-11-10T00:00:00Z",
            "reviewer_reference": "synthetic-independent-review",
        },
    }


def expect_valid(validator, manifest, label):
    errors = list(validator.iter_errors(manifest))
    if errors:
        raise AssertionError(
            f"{label} should be valid: " + "; ".join(str(error) for error in errors)
        )


def expect_invalid(manifest_validator, manifest, label):
    errors = list(manifest_validator.iter_errors(manifest))
    if not errors:
        raise AssertionError(f"{label} should be rejected")


def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validate_fixture_contract_alignment(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def validate_manifest(manifest):
        errors = list(validator.iter_errors(manifest))
        if errors:
            return errors
        if manifest["overall_result"] == "passed":
            recorded_ids = [item["test_id"].upper() for item in manifest["tests"]]
            recorded = set(recorded_ids)
            duplicates = sorted({
                fixture_id for fixture_id in recorded_ids
                if recorded_ids.count(fixture_id) > 1
            })
            missing = sorted(set(REQUIRED_FIXTURE_IDS) - recorded)
            unexpected = sorted(recorded - set(REQUIRED_FIXTURE_IDS))
            if missing or duplicates or unexpected:
                problems = []
                if missing:
                    problems.append("missing: " + ", ".join(missing))
                if duplicates:
                    problems.append("duplicate: " + ", ".join(duplicates))
                if unexpected:
                    problems.append("unexpected: " + ", ".join(unexpected))
                return [ValueError("fixture coverage mismatch (" + "; ".join(problems) + ")")]
        return []

    class ManifestValidator:
        def iter_errors(self, manifest):
            return validate_manifest(manifest)

    manifest_validator = ManifestValidator()
    expect_valid(manifest_validator, valid_manifest(), "complete passed synthetic manifest")

    cases = []

    failed_fixture = valid_manifest()
    failed_fixture["tests"][0]["status"] = "failed"
    cases.append(("passed result with failed fixture", failed_fixture))

    missing_evidence = valid_manifest()
    missing_evidence["tests"][0]["evidence"] = []
    cases.append(("passed result without evidence", missing_evidence))

    missing_exit_code = valid_manifest()
    missing_exit_code["tests"][0]["exit_code"] = None
    cases.append(("passed result without an exit code", missing_exit_code))

    missing_duration = valid_manifest()
    missing_duration["tests"][0]["duration_ms"] = None
    cases.append(("passed result without measured duration", missing_duration))

    missing_fixture = valid_manifest()
    missing_fixture["tests"].pop()
    cases.append(("passed result missing a required fixture", missing_fixture))

    duplicate_fixture = valid_manifest()
    duplicate_fixture["tests"][-1]["test_id"] = duplicate_fixture["tests"][0]["test_id"]
    cases.append(("passed result with duplicate fixture ID", duplicate_fixture))

    unexpected_fixture = valid_manifest()
    unexpected_fixture["tests"][-1]["test_id"] = "m0-unapproved-fixture"
    cases.append(("passed result with unapproved fixture ID", unexpected_fixture))

    wrong_profile = valid_manifest()
    wrong_profile["resource_profile"]["output_bytes_total"] = 2097152
    cases.append(("passed result with unapproved resource profile", wrong_profile))

    wrong_platform = valid_manifest()
    wrong_platform["runtime"]["platform"] = "ptrace"
    cases.append(("passed result with non-systrap platform", wrong_platform))

    missing_host_location = valid_manifest()
    missing_host_location["host"]["provider"] = None
    cases.append(("passed result without provider", missing_host_location))

    pending_review = valid_manifest()
    pending_review["security_review"]["decision"] = "pending"
    pending_review["security_review"]["reviewed_at"] = None
    pending_review["security_review"]["reviewer_reference"] = None
    cases.append(("passed result with pending security review", pending_review))

    incomplete_reviewer = valid_manifest()
    incomplete_reviewer["security_review"]["reviewer_reference"] = None
    cases.append(("approved review without reviewer reference", incomplete_reviewer))

    not_run_fixture = valid_manifest()
    not_run_fixture["tests"][0]["status"] = "not_run"
    cases.append(("passed result with not-run fixture", not_run_fixture))

    for label, manifest in cases:
        expect_invalid(manifest_validator, manifest, label)

    # The JSON Schema alone must enforce exact fixture coverage. The custom
    # Python guard above remains an independent second layer.
    for label, manifest in (
        ("missing fixture", missing_fixture),
        ("duplicate fixture", duplicate_fixture),
        ("unapproved fixture", unexpected_fixture),
    ):
        expect_invalid(validator, manifest, "schema-only " + label)

    incomplete = valid_manifest()
    incomplete["overall_result"] = "incomplete"
    incomplete["tests"][0]["status"] = "blocked"
    incomplete["security_review"]["decision"] = "pending"
    incomplete["security_review"]["reviewed_at"] = None
    incomplete["security_review"]["reviewer_reference"] = None
    expect_valid(manifest_validator, incomplete, "incomplete synthetic manifest")

    print("PASS  JSON Schema Draft 2020-12 meta-schema validation")
    print("PASS  fixture contract, JSON Schema and Python validator are synchronized")
    print(f"PASS  valid fully-passed manifest with all {len(REQUIRED_FIXTURE_IDS)} required fixtures")
    for label, _ in cases:
        print(f"PASS  rejects {label}")
    print("PASS  accepts incomplete manifest with blocked fixture and pending review")
    print(f"PASS  schema-only exact, unique coverage of all {len(REQUIRED_FIXTURE_IDS)} contract fixtures")
    print("PASS  Python invariant layer independently rejects missing, duplicate and unapproved fixture IDs")
    print(f"RESULT: {len(cases) + 5} evidence-schema checks passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # Fail CI with a concise diagnostic.
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
