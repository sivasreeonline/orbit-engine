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
        "only one preconfigured supervisor systemd unit",
        "StopUnit`/`StartUnit",
        "unit-file/drop-in digests",
        "complete supervisor cgroup",
        "implicit automatic restart must not race",
        "no generic root command or containerd authority",
        "WD-001", "WD-002", "WD-003", "WD-004", "WD-005", "WD-006", "WD-007",
        "Watchdog SIGSTOP/deadlock",
        "Watchdog service-manager authorization denied",
        "Supervisor unit/drop-in or executable digest substitution",
        "Supervisor cgroup path or membership mismatch",
        "systemd automatic-restart race",
        "Service manager reports stop complete but process/lock remains",
        "Watchdog unit unavailable or watchdog process exits",
        "Candidate A requires a root-owned directory",
        "Candidate B must prove an equivalent protected publication mechanism",
        "Candidate B requires a lock file owned by its dedicated non-root supervisor identity",
        "Containerd operation reconciliation",
        "DISPATCH_POSSIBLE",
        "terminalization_trigger_watermark",
        "trigger_stream_sealed",
        "insert exactly one `terminal_results` row",
        "append-only: no update, upsert, replacement, or delete is permitted",
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
        "verify the trigger stream is sealed and every trigger through the watermark is durable",
        "one immutable terminal row and attempt transition in one transaction",
        "Candidate A requires the root-owned socket boundary",
        "Candidate B must prove the protected non-root socket-publication boundary",
        "exactly two candidates",
        "not a third ADR candidate",
        "WD-001", "WD-002", "WD-003", "WD-004", "WD-005", "WD-006", "WD-007",
        "Watchdog process pause/deadlock",
        "Watchdog service-manager authorization denial",
        "Supervisor unit-file, drop-in, executable-digest",
        "Service-manager stop acknowledgement before actual process exit",
        "systemd automatic-restart racing",
        "Watchdog service outage or crash",
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
        "current `supervisor_generation` and current `attempt_generation`",
        "branch_state_version",
        "Every finalization-branch mutation must compare supervisor_generation, attempt_generation, branch_generation, and branch_state_version together in one conditional update",
        "a unique terminal_results.attempt_id",
        "Install database-level guards",
        "sealed trigger watermark",
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
        "For Candidate A, this covers all rootful containerd access; for Candidate B, it covers the dedicated non-root supervisor",
        "persist the trigger and `TERMINATING` transition concurrently",
        "supervisor_generation",
        "attempt_generation",
        "branch_generation",
        "current `supervisor_generation`, `attempt_generation`, `branch_generation`, and expected branch state version",
        "database lease or generation integer alone cannot fence a paused process",
        "full lifetime of the selected supervisor",
        "seals a trigger watermark after final output-drain/quiescence",
        "Database constraints/guards must reject a second terminal insert",
        "preconfigured supervisor unit through narrowly scoped service-manager authorization",
        "Prohibit shell/systemctl command execution",
        "preconfigured supervisor unit through narrowly scoped service-manager authorization",
        "Prohibit shell/systemctl command execution",
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
    # Stable watchdog IDs must be present in both design matrices so a test
    # cannot silently disappear from one side of the contract.
    watchdog_ids = [f"WD-{number:03d}" for number in range(1, 8)]
    for scenario_id in watchdog_ids:
        for label in ("contract", "runtime harness"):
            if scenario_id not in contents.get(label, ""):
                failures.append(f"{label}: missing watchdog fault-injection scenario {scenario_id}")

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
