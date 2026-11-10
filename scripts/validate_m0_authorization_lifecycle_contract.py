#!/usr/bin/env python3
"""Static/synthetic linkage checks for the M0 authorization lifecycle contract.

This validator does not implement or contact an external authority/provider,
verify cryptographic signatures, exercise a transactional store, inspect a host,
or authorize privileged work.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs/specifications/m0-authorization-lifecycle-and-recovery-contract.md"
PROTOCOL = ROOT / "docs/specifications/m0-host-and-journal-qualification-protocol.md"
SECURITY_PACKET = ROOT / "docs/security/m0-sandbox-security-review-packet.md"
SUPERVISOR = ROOT / "docs/specifications/m0-supervisor-journal-implementation-contract.md"
CALIBRATION_VALIDATOR = ROOT / "scripts/validate_m0_cleanup_calibration_authorization.py"
M0_WORKFLOW = ROOT / ".github/workflows/m0-preflight-ci.yml"

def require(text: str, fragment: str, label: str) -> None:
    if fragment not in text:
        raise AssertionError(f"missing {label}: {fragment}")

def main() -> int:
    contract = CONTRACT.read_text(encoding="utf-8")
    protocol = PROTOCOL.read_text(encoding="utf-8")
    packet = SECURITY_PACKET.read_text(encoding="utf-8")
    supervisor = SUPERVISOR.read_text(encoding="utf-8")
    calibration = CALIBRATION_VALIDATOR.read_text(encoding="utf-8")
    workflow = M0_WORKFLOW.read_text(encoding="utf-8")

    required_contract_terms = [
        "Single-writer per enrolled host", "Monotonic epoch", "Nonce/request binding",
        "Authenticated response", "Fence before issue", "Durable accept before privilege",
        "One active incarnation", "Revocation is terminal", "Fail-closed recovery",
        "ENROLLED", "FENCING", "FENCED", "ISSUED", "ACCEPTED", "REVOKED", "QUARANTINED",
        "Same nonce + same request digest", "changed request digest", "non-reusable digest tombstone",
        "atomic compare-and-swap", "max_total_runs", "crash after claim never silently refunds budget",
        "RECOVERY_ONLY", "signature", "provider instance identity",
    ]
    for term in required_contract_terms:
        require(contract, term, "authorization lifecycle security property")

    cases = [f"C-{n:02d}" for n in range(1, 11)]
    for case in cases:
        require(contract, case, "deterministic concurrency/recovery case")
    if len(re.findall(r"\| C-\d{2} \|", contract)) != 10:
        raise AssertionError("the concurrency matrix must contain exactly ten uniquely identified cases")

    for term in [
        "m0-authorization-lifecycle-and-recovery-contract.md",
        "terminal revocation",
        "replay tombstones",
        "durable guest readback before readiness",
    ]:
        require(protocol, term, "host qualification protocol linkage")
    for term in [
        "m0-authorization-lifecycle-and-recovery-contract.md",
        "nonce/request replay",
        "provider-fence-before-issue chronology",
        "atomic run-budget claims",
    ]:
        require(packet, term, "independent security review packet linkage")
    for term in [
        "Epoch issuance/revocation and provider fencing must be serialized per enrolled host",
        "durably records the accepted epoch and evidence reference before allocating a supervisor generation",
    ]:
        require(supervisor, term, "external host-incarnation authority contract")
    for term in [
        "does not create an authorization",
        "does not verify a real signature",
        "synthetic contract tests only",
        "full_m0_proof_authorized",
        "student_execution_authorized",
        "production_execution_authorized",
    ]:
        require(calibration, term, "Phase A validator safety boundary")
    for term in [
        "docs/specifications/m0-authorization-lifecycle-and-recovery-contract.md",
        "scripts/validate_m0_authorization_lifecycle_contract.py",
        "Validate authorization lifecycle contract linkage",
    ]:
        require(workflow, term, "M0 workflow dependency and execution step")

    if "Phase A remains unauthorized" not in protocol:
        raise AssertionError("protocol must retain explicit Phase A unauthorized boundary")
    print("PASS  authorization lifecycle security properties and state inventory")
    print("PASS  ten deterministic concurrency/recovery cases C-01 through C-10")
    print("PASS  protocol, independent review and supervisor contract cross-linkage")
    print("PASS  Phase A synthetic-only and no-execution safety boundary")
    print("NOTE  static contract checks only; no authority, provider, crypto, ledger or host proof")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
