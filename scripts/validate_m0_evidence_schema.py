#!/usr/bin/env python3
"""Validate M0 evidence schema invariants using synthetic, non-sensitive data."""

import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-proof-evidence.schema.json"


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
        "tests": [{
            "test_id": "m0-synthetic-001",
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
        }],
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


def expect_invalid(validator, manifest, label):
    errors = list(validator.iter_errors(manifest))
    if not errors:
        raise AssertionError(f"{label} should be rejected")


def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    expect_valid(validator, valid_manifest(), "fully passed synthetic manifest")

    cases = []

    failed_fixture = valid_manifest()
    failed_fixture["tests"][0]["status"] = "failed"
    cases.append(("passed result with failed fixture", failed_fixture))

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
    expect_valid(validator, incomplete, "incomplete synthetic manifest")

    print("PASS  JSON Schema Draft 2020-12 meta-schema validation")
    print("PASS  valid fully-passed manifest")
    for label, _ in cases:
        print(f"PASS  rejects {label}")
    print("PASS  accepts incomplete manifest with blocked fixture and pending review")
    print(f"RESULT: {len(cases) + 3} evidence-schema checks passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # Fail CI with a concise diagnostic.
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
