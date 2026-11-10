#!/usr/bin/env python3
"""Check that M0 cleanup calibration and full-proof gates stay aligned.

This is a static documentation consistency check only. It does not inspect a
host, verify isolation, authorize calibration, or approve execution.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = {
    "resource profile": "docs/specifications/m0-proof-resource-profile-v1.md",
    "host runbook": "docs/specifications/m0-host-preflight-and-proof-runbook.md",
    "runtime harness": "docs/specifications/m0-runtime-proof-harness-design.md",
    "host launch ADR": "docs/adr/ADR-0019-m0-host-launch-boundary.md",
    "security review packet": "docs/security/m0-sandbox-security-review-packet.md",
}
REQUIRED = {
    "resource profile": [
        "Authorization phases", "Phase A", "Phase B",
        "outer safety boundary", "CAL-CLEAN", "35-fixture",
        "evidence-finalization reserve", "student execution",
    ],
    "host runbook": [
        "Phase A — Cleanup deadline calibration", "Phase A.1",
        "Phase B.1", "CAL-CLEAN-001", "35-fixture",
        "external VM safety cutoff", "journal backend proof gate",
    ],
    "runtime harness": [
        "Cleanup deadline calibration mode (Phase A)",
        "CAL-CLEAN-001", "same supervisor cleanup controller",
        "Phase B remains blocked", "general execution endpoint",
    ],
    "host launch ADR": [
        "Cleanup calibration authorization boundary",
        "Phase A", "Phase B", "35-fixture",
        "outer VM safety cutoff",
    ],
    "security review packet": [
        "Phase A calibration review requirements",
        "Phase B approval", "35-fixture",
        "outer VM", "independent reviewer",
    ],
}
FORBIDDEN_CIRCULAR_WORDING = [
    "No stress fixture or host proof may start until the cleanup deadline and its clock/restart semantics are explicitly approved",
    "Before any stress fixture or host proof, follow the measurement and approval protocol",
]

def main() -> int:
    failures = []
    contents = {}
    for label, relative_path in DOCUMENTS.items():
        path = ROOT / relative_path
        if not path.is_file():
            failures.append(f"{label}: missing {relative_path}")
            continue
        content = path.read_text(encoding="utf-8")
        contents[label] = content
        for phrase in REQUIRED[label]:
            if phrase.casefold() not in content.casefold():
                failures.append(f"{label}: missing required gate text: {phrase}")
        for phrase in FORBIDDEN_CIRCULAR_WORDING:
            if phrase.casefold() in content.casefold():
                failures.append(f"{label}: obsolete circular gate wording remains")

    if "host runbook" in contents:
        runbook = contents["host runbook"]
        if runbook.index("Phase A — Cleanup deadline calibration") > runbook.index("Phase A.1"):
            failures.append("host runbook: Phase A authorization must precede Phase A.1 smoke checks")
        if runbook.index("Phase B.1") > runbook.index("Phase A measurement evidence and Phase B release gate"):
            failures.append("host runbook: Phase B full proof must follow the calibration/release gate")

    if "resource profile" in contents:
        profile = contents["resource profile"]
        if "Phase A samples never count toward the 35-fixture manifest" not in profile:
            failures.append("resource profile: Phase A evidence must be excluded from the full-proof manifest")
        if "Phase B approval gate" not in profile:
            failures.append("resource profile: explicit Phase B approval gate missing")

    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1

    for label in DOCUMENTS:
        print(f"PASS  {label}: calibration/full-proof gates aligned")
    print("PASS  obsolete circular cleanup-deadline gate wording absent")
    print("PASS  Phase A evidence is distinct from the 35-fixture Phase B manifest")
    print("NOTE  static documentation check only; it is not host proof or execution authorization")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
