#!/usr/bin/env python3
"""Static consistency checks for the M0 supervisor/journal design contract.

This does not compile or authorize privileged code, inspect a host, prove
clock behavior, or approve a journal backend.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "contract": "docs/specifications/m0-supervisor-journal-implementation-contract.md",
    "runtime harness": "docs/specifications/m0-runtime-proof-harness-design.md",
    "journal evaluation": "docs/specifications/m0-journal-backend-evaluation.md",
    "runner README": "services/execution-runner/README.md",
    "host launch ADR": "docs/adr/ADR-0019-m0-host-launch-boundary.md",
}
REQUIRED = {
    "contract": [
        "Per-attempt deadline and cleanup controller",
        "Supervisor liveness and recovery watchdog",
        "Outer VM safety watchdog",
        "supervisor_generation", "attempt_generation",
        "operation_sequence", "state_version", "branch_generation",
        "Immediate termination exception", "CLOCK_BOOTTIME",
        "No exactly-once claim", "UnconfiguredExecutor",
        "`acquired_by_id` principal", "independent verifier ID",
        "Supervisor socket authentication and authorization",
        "kernel-supplied peer credentials",
        "socket inode", "unexpected ancillary data/file descriptors",
        "Stable kernel lock-file contract",
        "Never unlink, rename, or recreate the lock file",
        "close-on-exec", "exact service instance",
        "Candidate A requires a root-owned directory",
        "Candidate B must prove an equivalent protected publication mechanism",
        "Candidate B requires a lock file owned by its dedicated non-root supervisor identity",
    ],
    "runtime harness": [
        "m0-supervisor-journal-implementation-contract.md",
        "Neither candidate is selected",
        "exclusive host-wide kernel process lock",
        "journal compare-and-set rejects stale state mutations",
        "requests workload termination immediately",
        "journal read alone cannot rule out a trigger",
        "host-owned trigger arbiter accepts it while the attempt is still active",
        "current `supervisor_generation` and `attempt_generation`",
        "`branch_state_version`",
        "Every branch mutation must compare all four ownership/version values atomically",
        "Candidate A requires the root-owned socket boundary",
        "Candidate B must prove the protected non-root socket-publication boundary",
        "exactly two candidates",
        "not a third ADR candidate",
    ],
    "journal evaluation": [
        "m0-supervisor-journal-implementation-contract.md",
        "supervisor_generation",
        "attempt_generation",
        "operation_sequence",
        "trigger_sequence",
        "branch_generation",
        "candidate-specific supervisor journal only",
        "Candidate B requires ownership by its dedicated non-root supervisor identity",
        "current `supervisor_generation`",
        "current `attempt_generation`",
        "branch_state_version",
        "Every finalization-branch mutation must compare supervisor_generation, attempt_generation, branch_generation, and branch_state_version together in one conditional update",
        "Candidate A requires root ownership; Candidate B requires ownership by its dedicated non-root supervisor identity",
    ],
    "runner README": [
        "m0-supervisor-journal-implementation-contract.md",
        "ADR-0019 has not selected an implementation",
        "UnconfiguredExecutor",
    ],
    "host launch ADR": [
        "m0-supervisor-journal-implementation-contract.md",
        "No launch-boundary candidate is selected",
        "Candidates under evaluation",
        "Candidate A", "Candidate B",
        "Candidate A — rootful host supervisor requirements",
        "Candidate B — rootless containerd experiment",
        "persist the trigger and `TERMINATING` transition concurrently",
        "supervisor_generation",
        "attempt_generation",
        "branch_generation",
        "current `supervisor_generation`, `attempt_generation`, `branch_generation`, and expected branch state version",
        "database lease or generation integer alone cannot fence a paused process",
    ],
}
FORBIDDEN_ADR_SELECTION_PHRASES = [
    "recommended for disposable M0 proof only",
    "For the initial M0 proof, use a dedicated",
    "Before the proposed rootful supervisor is accepted",
    "Recommended candidate, not yet approved",
    "An architecture recommendation does not authorize privileged implementation",
]
FORBIDDEN_AUTHORIZATION_PHRASES = [
    "Implementation authorized: true",
    "student execution enabled by this contract",
]
FORBIDDEN_RUNTIME_HARNESS_PHRASES = [
    "preferred design candidate",
    "supervisor lease/fencing generation",
    "journal/lease authority",
    "durable transition wins while the attempt is still active",
]

def main() -> int:
    failures = []
    contents = {}
    for label, relative in TARGETS.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{label}: missing {relative}")
            continue
        value = path.read_text(encoding="utf-8")
        contents[label] = value
        for phrase in REQUIRED[label]:
            if phrase.casefold() not in value.casefold():
                failures.append(f"{label}: missing required contract reference/text: {phrase}")
    for phrase in FORBIDDEN_ADR_SELECTION_PHRASES:
        if phrase.casefold() in contents.get("host launch ADR", "").casefold():
            failures.append(f"host launch ADR contains stale candidate-selection language: {phrase}")
    for phrase in FORBIDDEN_AUTHORIZATION_PHRASES:
        if phrase.casefold() in contents.get("contract", "").casefold():
            failures.append("contract contains an explicitly prohibited authorization marker")
    for phrase in FORBIDDEN_RUNTIME_HARNESS_PHRASES:
        if phrase.casefold() in contents.get("runtime harness", "").casefold():
            failures.append(f"runtime harness contains stale/unsafe fencing or candidate language: {phrase}")

    if "contract" in contents:
        contract = contents["contract"]
        if contract.count("Outer VM safety watchdog") < 2:
            failures.append("contract must define and cross-reference the outer VM watchdog")
        if "Termination is the deliberate exception" not in contract:
            failures.append("termination/journal ordering exception must remain explicit")
        if "No numeric cleanup timeout" not in contract:
            failures.append("contract must not introduce an unapproved cleanup timeout")
        authority_sentence = "The controller may request only the five typed supervisor operations in the runtime harness design;"
        if contract.count(authority_sentence) != 1:
            failures.append("contract must contain exactly one typed supervisor-operation authority statement")

    if failures:
        for item in failures:
            print(f"FAIL  {item}", file=sys.stderr)
        return 1

    for label in TARGETS:
        print(f"PASS  {label}: supervisor/journal contract aligned")
    print("PASS  distinct watchdog roles and generation values are documented")
    print("PASS  termination exception and no-exactly-once boundary are explicit")
    print("PASS  design-only and fail-closed implementation boundary retained")
    print("NOTE  static document check only; not host proof or implementation approval")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
