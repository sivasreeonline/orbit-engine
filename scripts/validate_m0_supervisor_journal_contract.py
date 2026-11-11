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
        "The cleanup deadline anchor is the earliest accepted host-observed trigger timestamp",
        "Repeated and secondary triggers never reset the original cleanup clock",
        "For an attempt in `CREATING`, `STARTING`, or `RUNNING`",
        "pre-create cancellation/deadline must resolve through the existing `REJECTED` or `EXPIRED` admission outcome",
        "If create dispatch may already have occurred, the attempt is in `CREATING`",
        "after natural exit has been observed or after finalization begins is late",
        "Cleanup and evidence branches execute independently",
        "both branch dispositions are durable and current",
        "Any failed, timed-out, stale, or uncertain branch is incomplete/infrastructure-failed and quarantined",
        "terminal CAS verifies every trigger sequence through it is present exactly once",
        "Terminal CAS requires that finalized snapshot",
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
        "winning trigger ID/cause",
        "cleanup/evidence branch generations and state versions plus durable dispositions",
        "Insert exactly once; append-only; no update, upsert, replacement, or delete",
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
        "trigger sequence",
        "Globally unique `attempt_id`",
        "unique `(attempt_id, trigger_sequence)`",
        "unique immutable `reference_id`",
        "unique `quarantine_record_id`",
        "append-only disposition event",
        "attempt identity, owner, profile and request digest are immutable after acceptance",
        "phase advances only through declared forward transitions",
        "append-only immutable trigger record",
        "state and disposition advance only through expected-version and generation-fenced compare-and-set",
        "append-only immutable attempt-scoped object reference/version",
        "trigger records required to verify sealed watermarks",
        "evidence references and their immutable objects while referenced",
        "object deletion requires a reviewed reference scan and retention authorization",
        "branch_generation",
        "candidate-specific supervisor journal only",
        "Candidate B requires ownership by its dedicated non-root supervisor identity",
        "current `supervisor_generation`",
        "current `attempt_generation`",
        "current `supervisor_generation` and `attempt_generation`",
        "branch_state_version",
        "Every finalization-branch mutation must compare supervisor_generation, attempt_generation, branch_generation, and branch_state_version together in one conditional update",
        "a unique terminal_results.attempt_id",
        "Install database-level guards",
        "sealed trigger watermark",
        "winning trigger ID/cause",
        "cleanup/evidence branch generations and state versions plus durable dispositions",
        "Insert exactly once; append-only; no update, upsert, replacement, or delete",
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
LOGICAL_RECORD_NAMES = {
    "host_meta", "attempts", "idempotency_keys", "operations", "triggers",
    "finalization_branches", "terminal_results", "evidence_references", "quarantine_records",
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

    logical_sections = {
        "contract": "## 6. Journal logical schema contract",
        "journal evaluation": "## 4. Minimum logical data model",
    }
    for label, heading in logical_sections.items():
        document = contents.get(label, "")
        start = document.find(heading)
        if start < 0:
            failures.append(f"{label}: missing logical data model section {heading}")
            continue
        end = document.find("\n## ", start + len(heading))
        section = document[start:] if end < 0 else document[start:end]
        rows = [line for line in section.splitlines() if line.startswith("| `")]
        names = [line.split("`", 2)[1] for line in rows]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        missing = sorted(LOGICAL_RECORD_NAMES - set(names))
        extra = sorted(set(names) - LOGICAL_RECORD_NAMES)
        if duplicates or missing or extra:
            failures.append(f"{label}: logical record inventory mismatch; duplicates={duplicates}, missing={missing}, extra={extra}")

    terminal_rows_by_label = {}
    for label in ("contract", "journal evaluation"):
        terminal_rows = [line for line in contents.get(label, "").splitlines() if line.startswith("| `terminal_results` |")]
        if len(terminal_rows) != 1:
            failures.append(f"{label}: exactly one canonical terminal_results logical record must be defined")
        else:
            terminal_rows_by_label[label] = terminal_rows[0]
            if not all(phrase.casefold() in terminal_rows[0].casefold() for phrase in (
                "winning trigger ID/cause",
                "sealed trigger watermark",
                "cleanup/evidence branch generations and state versions",
                "append-only",
            )):
                failures.append(f"{label}: terminal_results row is missing required recovery/immutability fields")
    if len(terminal_rows_by_label) == 2 and terminal_rows_by_label["contract"] != terminal_rows_by_label["journal evaluation"]:
        failures.append("contract and journal evaluation must use the exact same canonical terminal_results row")

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
        cross_document_requirements = {
            "journal evaluation": [
                "The trigger seal and final output snapshot are committed durably before terminal CAS",
                "post-seal triggers are recorded as late incidents and cannot alter the watermark or output snapshot",
                "Every finalization-branch mutation must compare supervisor_generation, attempt_generation, branch_generation, and branch_state_version together in one conditional update",
                "Terminal commit must additionally compare the sealed trigger watermark",
                "verify contiguous durable trigger records through that watermark",
                "Output counters must be monotonic before finalization",
                "terminal commit requires that finalized snapshot",
            ],
            "runtime harness": [
                "capture the earliest host-observed termination trigger's monotonic timestamp and boot identity",
                "Secondary triggers do not reset the interval",
                "A cancellation arriving after natural exit has been observed by that same arbiter is late",
                "Cleanup and evidence finalization remain independent branches",
                "The terminal compare-and-set may run only after both branch dispositions are durably recorded",
                "Cleanup requests are idempotent and fenced by the exclusive host lock",
                "read back the exact immutable manifest version and independently verify its full byte count, SHA-256, and every referenced object/version",
                "the manifest must not self-reference",
                "No terminal result without a durable, verified final manifest",
                "Terminal journal state with missing/unverified manifest or evidence",
                "Evidence collection and evidence-store access must not be on the critical path for process termination",
            ],
            "host launch ADR": [
                "seals a trigger watermark after final output-drain/quiescence",
                "current `supervisor_generation`, `attempt_generation`, `branch_generation`, and expected branch state version",
            ],
        }
        for label, phrases in cross_document_requirements.items():
            document = contents.get(label, "")
            for phrase in phrases:
                if phrase.casefold() not in document.casefold():
                    failures.append(f"{label}: missing terminalization/cleanup invariant: {phrase}")
        for phrase in (
            "The fence must be effective before the new epoch is issued or accepted",
            "Responses are authenticated and replay-detectable",
            "nonce reuse with changed request content is a conflict",
            "provider mechanism must prove hard stop or equivalent enforced isolation of compute, storage writes, and privileged control paths",
            "durably records the accepted epoch and evidence reference before allocating a supervisor generation or enabling any listener/admission path",
            "Epoch issuance/revocation and provider fencing must be serialized per enrolled host",
            "startup/restore fails closed",
        ):
            if phrase.casefold() not in contract.casefold():
                failures.append(f"contract: external host-incarnation trust boundary missing: {phrase}")
        contract_epoch_phrases = [
            "The fence must be effective before the new epoch is issued or accepted",
            "Responses are authenticated and replay-detectable",
            "nonce reuse with changed request content is a conflict",
            "provider mechanism must prove hard stop or equivalent enforced isolation of compute, storage writes, and privileged control paths",
            "durably records the accepted epoch and evidence reference before allocating a supervisor generation or enabling any listener/admission path",
            "Epoch issuance/revocation and provider fencing must be serialized per enrolled host",
            "startup/restore fails closed",
        ]
        for phrase in contract_epoch_phrases:
            if phrase.casefold() not in contract.casefold():
                failures.append(f"contract: external host-incarnation trust boundary missing: {phrase}")
        runtime_document = contents.get("runtime harness", "")
        evidence_publication_order = [
            "Apply redaction before publication",
            "compute SHA-256 and byte count from the exact final bytes",
            "Publish to an immutable, content-addressed object identity",
            "Re-open/read back the published object",
            "Persist the verified evidence reference",
            "Generate and validate the final manifest",
            "read back the exact immutable manifest version",
            "Persist the terminal result with compare-and-set only after all artifact references",
        ]
        evidence_section_start = runtime_document.casefold().find("### 7.1 evidence publication, integrity, and crash ordering")
        evidence_section = runtime_document[evidence_section_start:] if evidence_section_start >= 0 else ""
        positions = [evidence_section.casefold().find(phrase.casefold()) for phrase in evidence_publication_order]
        if any(position < 0 for position in positions) or positions != sorted(positions):
            failures.append("runtime harness: evidence publication steps must remain complete and strictly ordered before terminal commit")
        for phrase in (
            "Crash after evidence staging is durable but before immutable publication",
            "Crash after immutable evidence publication but before readback verification",
            "Crash after verified object readback but before journal reference commit",
            "Crash after evidence-reference commit but before final manifest publication",
            "Crash after manifest publication but before manifest readback/verification",
        ):
            if phrase.casefold() not in runtime_document.casefold():
                failures.append(f"runtime harness: evidence publication crash case missing: {phrase}")
        for phrase in (
            "REQUESTED", "VALIDATING", "QUEUED", "CREATING", "STARTING",
            "RUNNING", "TERMINATING", "FINALIZING", "QUARANTINED",
        ):
            if phrase not in contract:
                failures.append(f"contract: lifecycle transition model missing state {phrase}")
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
