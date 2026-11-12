#!/usr/bin/env python3
"""Run the FENCE-001 audit custody and final qualification gates as one fail-closed command.

This orchestrates existing independent validators. It does not collect provider
evidence, establish provider truth, approve production, or authorize host admission.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def validate_review_ready_record(record: dict[str, Any]) -> None:
    if record.get("qualificationStatus") != "READY_FOR_INDEPENDENT_REVIEW":
        raise ValueError("final custody gate requires qualificationStatus READY_FOR_INDEPENDENT_REVIEW")
    if record.get("productionApproval") is not False:
        raise ValueError("productionApproval must remain false")
    tests = record.get("tests")
    expected = {f"WIT-{number:03d}" for number in range(1, 15)}
    if not isinstance(tests, list) or {item.get("id") for item in tests} != expected:
        raise ValueError("qualification record must contain WIT-001 through WIT-014 exactly")
    if any(item.get("status") != "PASS" for item in tests):
        raise ValueError("all 14 mandatory qualification controls must be PASS before review readiness")


def run(command: list[str], label: str) -> None:
    print(f"\n== {label} ==")
    subprocess.run(command, cwd=ROOT, check=True)


def self_test() -> None:
    template_path = ROOT / "docs/templates/m0-fence-witness-qualification-record.json"
    template = load_object(template_path)
    try:
        validate_review_ready_record(template)
    except ValueError:
        pass
    else:
        raise AssertionError("NOT_STARTED template unexpectedly passed final review-ready gate")

    ready = json.loads(json.dumps(template))
    ready["qualificationStatus"] = "READY_FOR_INDEPENDENT_REVIEW"
    for item in ready["tests"]:
        item["status"] = "PASS"
    validate_review_ready_record(ready)

    production = json.loads(json.dumps(ready))
    production["productionApproval"] = True
    try:
        validate_review_ready_record(production)
    except ValueError:
        pass
    else:
        raise AssertionError("production approval was accepted by the final custody gate")

    run([sys.executable, str(SCRIPTS / "validate_m0_fence_audit_provenance_manifest_binding.py"), "--self-test"],
        "Audit provenance signature, mapping and byte-binding self-test")
    run([sys.executable, str(SCRIPTS / "validate_m0_fence_witness_qualification.py")],
        "Qualification record schema and fail-closed fixture tests")
    print("\nFENCE-001 end-to-end custody gate self-test: PASS (synthetic fixtures only)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--record", type=Path, help="final qualification record")
    parser.add_argument("--manifest", type=Path, help="dual-signed evidence manifest")
    parser.add_argument("--manifest-trusted-keys", type=Path, help="independently provisioned manifest trust keys")
    parser.add_argument("--audit-report", type=Path, help="provider audit provenance report")
    parser.add_argument("--audit-binding", type=Path, help="dual-attested audit provenance binding")
    parser.add_argument("--binding-trusted-keys", type=Path, help="independently provisioned binding trust keys")
    parser.add_argument("--artifact-root", type=Path, help="directory of materialized files named by manifest artifactId")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    required = (
        args.record, args.manifest, args.manifest_trusted_keys, args.audit_report,
        args.audit_binding, args.binding_trusted_keys, args.artifact_root,
    )
    if any(value is None for value in required):
        parser.error("external mode requires --record, --manifest, --manifest-trusted-keys, --audit-report, --audit-binding, --binding-trusted-keys and --artifact-root")

    record = load_object(args.record)
    validate_review_ready_record(record)

    common = [
        "--manifest", str(args.manifest),
        "--manifest-trusted-keys", str(args.manifest_trusted_keys),
        "--audit-report", str(args.audit_report),
        "--binding-trusted-keys", str(args.binding_trusted_keys),
        "--artifact-root", str(args.artifact_root),
    ]
    run([
        sys.executable, str(SCRIPTS / "validate_m0_fence_audit_provenance_manifest_binding.py"),
        *common, "--binding", str(args.audit_binding),
    ], "Dual-signature audit provenance, manifest mapping and materialized-byte verification")

    run([
        sys.executable, str(SCRIPTS / "validate_m0_fence_witness_qualification.py"),
        "--record", str(args.record),
        "--evidence-manifest", str(args.manifest),
        "--trusted-keys", str(args.manifest_trusted_keys),
        "--artifact-root", str(args.artifact_root),
    ], "Final WIT-001–WIT-014 qualification-record and evidence-manifest reconciliation")

    print("\nFENCE-001 end-to-end evidence custody: PASS")
    print("Meaning: supplied signed artifacts, audit provenance binding, materialized bytes and review-ready record are internally consistent.")
    print("Not established: provider truth/completeness, remote immutability, trust-root governance, monitor independence or independent security approval.")
    print("productionApproval remains false; this command does not authorize host admission or execution.")


if __name__ == "__main__":
    main()
