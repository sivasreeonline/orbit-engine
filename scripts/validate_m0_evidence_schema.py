#!/usr/bin/env python3
"""Validate M0 evidence schema invariants using synthetic, non-sensitive data."""

import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-proof-evidence.schema.json"
REQUIRED_FIXTURE_IDS = ["M0-RUN-JAVA-001","M0-RUN-PY-001","M0-RUN-JAVA-002","M0-RUN-003","M0-RUN-004","M0-ID-001","M0-ID-002","M0-HOST-001","M0-HOST-002","M0-HOST-003","M0-HOST-004","M0-HOST-005","M0-NET-001","M0-NET-002","M0-NET-003","M0-NET-004","M0-NET-005","M0-NET-006","M0-RES-CPU-001","M0-RES-MEM-001","M0-RES-PID-001","M0-RES-TIME-001","M0-RES-FS-001","M0-RES-FS-002","M0-RES-FS-003","M0-RES-OUT-001","M0-RES-OUT-002","M0-LIFE-CLEAN-001","M0-LIFE-CLEAN-002","M0-LIFE-CANCEL-001","M0-LIFE-DUP-001","M0-LIFE-RESTART-001","M0-LIFE-REPEAT-001"]


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
            f"{label} should be valid: " + "; ".join(error.message for error in errors)
        )


def expect_invalid(manifest_validator, manifest, label):
    errors = list(validator.iter_errors(manifest))
    if not errors:
        raise AssertionError(f"{label} should be rejected")


def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def validate_manifest(manifest):
        errors = list(validator.iter_errors(manifest))
        if errors:
            return errors
        if manifest["overall_result"] == "passed":
            recorded = {item["test_id"].upper() for item in manifest["tests"]}
            missing = sorted(set(REQUIRED_FIXTURE_IDS) - recorded)
            if missing:
                return [ValueError("missing required fixtures: " + ", ".join(missing))]
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

    missing_fixture = valid_manifest()
    missing_fixture["tests"].pop()
    cases.append(("passed result missing a required fixture", missing_fixture))

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
        expect_invalid(validator, manifest, label)

    incomplete = valid_manifest()
    incomplete["overall_result"] = "incomplete"
    incomplete["tests"][0]["status"] = "blocked"
    incomplete["security_review"]["decision"] = "pending"
    incomplete["security_review"]["reviewed_at"] = None
    incomplete["security_review"]["reviewer_reference"] = None
    expect_valid(manifest_validator, incomplete, "incomplete synthetic manifest")

    print("PASS  JSON Schema Draft 2020-12 meta-schema validation")
    print(f"PASS  valid fully-passed manifest with all {len(REQUIRED_FIXTURE_IDS)} required fixtures")
    for label, _ in cases:
        print(f"PASS  rejects {label}")
    print("PASS  accepts incomplete manifest with blocked fixture and pending review")
    print(f"PASS  requires complete coverage of all {len(REQUIRED_FIXTURE_IDS)} contract fixtures")
    print(f"RESULT: {len(cases) + 4} evidence-schema checks passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # Fail CI with a concise diagnostic.
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
