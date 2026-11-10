#!/usr/bin/env python3
"""Validate the M0 Phase A calibration authorization schema contract.

This exercises only synthetic manifests. It does not create an authorization,
verify a real signature, inspect a host, or enable sandbox execution.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-cleanup-calibration-authorization.schema.json"
PACKET_PATH = ROOT / "docs/security/m0-sandbox-security-review-packet.md"
REQUIRED_SCENARIOS = [
    "CAL-CLEAN-001", "CAL-CLEAN-002", "CAL-CLEAN-003",
    "CAL-CLEAN-004", "CAL-CLEAN-005", "CAL-CLEAN-006",
    "CAL-CLEAN-007", "CAL-CLEAN-008", "CAL-CLEAN-009",
]

def digest(char: str = "a") -> str:
    return char * 64

def synthetic_manifest() -> dict:
    now = datetime.now(timezone.utc)
    issued_at = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    expires_at = (now + timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schema_version": "1.1.0",
        "authorization_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "phase": "cleanup-calibration-only",
        "status": "authorized",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "host": {
            "provider": "synthetic-provider",
            "host_instance_id": "synthetic-host-instance-001",
            "host_incarnation_epoch": "synthetic-monotonic-epoch-42",
            "host_incarnation_authority_id": "synthetic-authority",
            "host_incarnation_authority_key_version": "key-v3",
            "host_incarnation_epoch_evidence_ref": "immutable://synthetic/epoch/v42",
            "host_incarnation_epoch_evidence_digest": digest("9"),
            "host_incarnation_issuance_nonce_digest": digest("a"),
            "predecessor_incarnation_set_digest": digest("b"),
            "prior_incarnation_fence_evidence_ref": "immutable://synthetic/fence/predecessors-41",
            "provider_fence_method": "provider-hard-stop-and-storage-write-fence",
            "provider_fence_verified_at": "2026-11-10T00:00:00Z",
            "provider_fence_evidence_digest": digest("c"),
            "host_qualification_record_ref": "immutable://synthetic/qualification/host-record",
            "host_qualification_record_digest": digest("d"),
            "region": "synthetic-region",
            "vm_image_digest": digest("a"),
            "os_release": "Ubuntu Server 24.04 LTS",
            "kernel_release": "6.8.0-synthetic",
            "architecture": "x86_64",
            "filesystem_type": "ext4",
            "mount_options_digest": digest("b"),
            "containerd_version": "2.3.1",
            "containerd_config_version": 3,
            "runsc_version": "runsc-synthetic",
            "shim_version": "shim-synthetic",
            "runtime_handler": "io.containerd.runsc.v1",
            "platform": "systrap",
            "supervisor_build_sha256": digest("c"),
            "watchdog_build_sha256": digest("d"),
        },
        "outer_safety": {
            "cpu_millis": 2000,
            "memory_bytes": 2147483648,
            "pid_limit": 512,
            "disk_bytes": 1073741824,
            "wall_cutoff_seconds": 900,
            "watchdog_control_plane": "synthetic-control-plane",
            "vm_hard_stop_control": "synthetic-vm-stop-action",
            "independence_attested": True,
            "verification_evidence_sha256": digest("e"),
        },
        "network_containment": {
            "default_deny_ipv4": True,
            "default_deny_ipv6": True,
            "enforced_outside_sandbox": True,
            "metadata_link_local_denied_before_host_uplink": True,
            "packet_drop_evidence_sha256": digest("f"),
        },
        "journal_qualification": {
            "backend": "SQLite DELETE journal / EXTRA",
            "library_version": "synthetic-sqlite-build",
            "configuration_digest_sha256": digest("1"),
            "durability_report_sha256": digest("2"),
            "power_loss_report_sha256": digest("3"),
            "corruption_restore_report_sha256": digest("4"),
            "lock_fencing_report_sha256": digest("5"),
            "independent_gate_passed": True,
        },
        "calibration": {
            "profile_id": "m0-cleanup-calibration-v1",
            "profile_revision": "1",
            "image_digest": "sha256:" + digest("6"),
            "scenario_bundle_digest": "sha256:" + digest("7"),
            "scenario_ids": REQUIRED_SCENARIOS.copy(),
            "max_total_runs": 90,
            "max_attempts_per_scenario": 10,
            "control_path": "host-local-only",
            "student_source_allowed": False,
            "hidden_test_data_allowed": False,
            "network_callbacks_allowed": False,
            "arbitrary_commands_allowed": False,
            "arbitrary_oci_allowed": False,
            "general_execution_endpoint_enabled": False,
            "queue_consumer_enabled": False,
            "uses_target_cleanup_controller": True,
            "uses_target_journal_path": True,
        },
        "stop_conditions": {
            "stop_on_outer_cutoff_fired": True,
            "stop_on_network_boundary_uncertain": True,
            "stop_on_unowned_resource_detected": True,
            "stop_on_cleanup_unverified": True,
            "stop_on_clock_ambiguous": True,
            "stop_on_evidence_leak_detected": True,
            "stop_on_unexplained_host_mutation": True,
            "stop_on_independent_reviewer_stop": True,
        },
        "evidence": {
            "destination": "synthetic-evidence-store",
            "redaction_policy_id": "synthetic-redaction-policy-v1",
            "immutable_storage_required": True,
            "sanitized_only": True,
            "host_fencing_verifier_id": "independent-fence-verifier",
            "host_fencing_evidence_acquired_at": "2026-11-10T00:00:00Z",
            "host_fencing_verification_completed_at": "2026-11-10T00:00:00Z",
            "host_fencing_verification_report_ref": "immutable://synthetic/fence-verification/report",
            "host_fencing_verification_report_digest": digest("e"),
            "host_fencing_acquired_by_id": "evidence-acquirer",
        },
        "signoff": {
            "host_owner_id": "host-owner-synthetic",
            "independent_reviewer_id": "reviewer-synthetic",
            "reviewer_role": "independent-security-reviewer",
            "independence_attested": True,
            "reviewed_at": "2026-11-10T00:00:00Z",
            "independent_security_review_record_ref": "immutable://synthetic/security-review/record",
            "independent_security_review_record_digest": digest("f"),
            "fence_control_id": "FENCE-001",
            "fence_control_result": "pass",
            "authorization_digest_sha256": digest("8"),
            "signature_reference": "synthetic-signature-reference",
        },
        "full_m0_proof_authorized": False,
        "student_execution_authorized": False,
        "production_execution_authorized": False,
    }

def custom_errors(manifest: dict) -> list[str]:
    errors = []
    calibration = manifest.get("calibration", {})
    scenario_ids = calibration.get("scenario_ids", [])
    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("duplicate scenario IDs are prohibited")
    if set(scenario_ids) != set(REQUIRED_SCENARIOS):
        errors.append("the authorization must include every CAL-CLEAN scenario exactly once")
    signoff = manifest.get("signoff", {})
    evidence = manifest.get("evidence", {})
    verifier = evidence.get("host_fencing_verifier_id")
    acquirer = evidence.get("host_fencing_acquired_by_id")
    owner = signoff.get("host_owner_id")
    reviewer = signoff.get("independent_reviewer_id")
    if verifier in {owner, reviewer, acquirer}:
        errors.append("host-fencing evidence verifier must be distinct from acquirer, host owner and independent reviewer")
    if acquirer in {owner, reviewer}:
        errors.append("host-fencing evidence acquirer must be distinct from host owner and independent reviewer")
    try:
        fence_verified = datetime.fromisoformat(manifest["host"]["provider_fence_verified_at"].replace("Z", "+00:00"))
        evidence_acquired = datetime.fromisoformat(evidence["host_fencing_evidence_acquired_at"].replace("Z", "+00:00"))
        evidence_verified = datetime.fromisoformat(evidence["host_fencing_verification_completed_at"].replace("Z", "+00:00"))
        reviewed_at = datetime.fromisoformat(signoff["reviewed_at"].replace("Z", "+00:00"))
        issued_at = datetime.fromisoformat(manifest["issued_at"].replace("Z", "+00:00"))
        times = [fence_verified, evidence_acquired, evidence_verified, reviewed_at, issued_at]
        if any(value.tzinfo is None for value in times):
            errors.append("fence verification, evidence acquisition/verification, review and issuance timestamps must be timezone-aware")
        elif times != sorted(times):
            errors.append("provider fence, evidence acquisition, independent verification, review and authorization must follow nondecreasing chronology")
    except (KeyError, ValueError, TypeError):
        errors.append("provider fence, review and issuance timestamps must be parseable")
    if signoff.get("host_owner_id") == signoff.get("independent_reviewer_id"):
        errors.append("host owner and independent reviewer must be different identities")
    try:
        issued = datetime.fromisoformat(manifest["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
        if expires <= issued:
            errors.append("authorization expiry must be later than issuance")
    except (KeyError, ValueError, TypeError):
        errors.append("issuance and expiry timestamps must be parseable")
    return errors

def validate(validator: Draft202012Validator, manifest: dict) -> list[str]:
    schema_errors = [error.message for error in validator.iter_errors(manifest)]
    return schema_errors + custom_errors(manifest)

def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    packet = PACKET_PATH.read_text(encoding="utf-8")
    if "version 1.1.0" not in packet or "complete predecessor set" not in packet or "host-qualification record digest" not in packet:
        raise AssertionError("Phase A packet must bind authorization to the externally fenced host incarnation and qualification record")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    valid = synthetic_manifest()
    errors = validate(validator, valid)
    if errors:
        raise AssertionError("synthetic valid manifest rejected: " + "; ".join(errors))
    cases = []
    unsafe_phase = deepcopy(valid)
    unsafe_phase["full_m0_proof_authorized"] = True
    cases.append(("full M0 proof enabled in Phase A", unsafe_phase))
    student_path = deepcopy(valid)
    student_path["student_execution_authorized"] = True
    cases.append(("student execution enabled", student_path))
    public_endpoint = deepcopy(valid)
    public_endpoint["calibration"]["general_execution_endpoint_enabled"] = True
    cases.append(("general execution endpoint enabled", public_endpoint))
    queue = deepcopy(valid)
    queue["calibration"]["queue_consumer_enabled"] = True
    cases.append(("ordinary queue consumer enabled", queue))
    missing_scenario = deepcopy(valid)
    missing_scenario["calibration"]["scenario_ids"].pop()
    cases.append(("missing calibration scenario", missing_scenario))
    duplicate_scenario = deepcopy(valid)
    duplicate_scenario["calibration"]["scenario_ids"][-1] = duplicate_scenario["calibration"]["scenario_ids"][0]
    cases.append(("duplicate calibration scenario", duplicate_scenario))
    disabled_stop_policy = deepcopy(valid)
    disabled_stop_policy["stop_conditions"]["stop_on_cleanup_unverified"] = False
    cases.append(("cleanup uncertainty stop policy disabled", disabled_stop_policy))
    no_outer_watchdog = deepcopy(valid)
    no_outer_watchdog["outer_safety"]["independence_attested"] = False
    cases.append(("outer watchdog independence not attested", no_outer_watchdog))
    no_network_deny = deepcopy(valid)
    no_network_deny["network_containment"]["metadata_link_local_denied_before_host_uplink"] = False
    cases.append(("metadata network deny not proven", no_network_deny))
    fence_control_not_passed = deepcopy(valid)
    fence_control_not_passed["signoff"]["fence_control_result"] = "not-reviewed"
    cases.append(("FENCE-001 review not passed", fence_control_not_passed))
    missing_review_record = deepcopy(valid)
    del missing_review_record["signoff"]["independent_security_review_record_ref"]
    cases.append(("missing signed independent security review record reference", missing_review_record))
    same_fence_verifier = deepcopy(valid)
    same_fence_verifier["evidence"]["host_fencing_verifier_id"] = same_fence_verifier["signoff"]["independent_reviewer_id"]
    cases.append(("fence evidence verifier is also independent reviewer", same_fence_verifier))
    same_fence_acquirer = deepcopy(valid)
    same_fence_acquirer["evidence"]["host_fencing_acquired_by_id"] = same_fence_acquirer["signoff"]["host_owner_id"]
    cases.append(("fence evidence acquired by host owner", same_fence_acquirer))
    early_evidence = deepcopy(valid)
    early_evidence["evidence"]["host_fencing_evidence_acquired_at"] = "2026-11-09T23:59:00Z"
    cases.append(("fence evidence acquired before provider fence verification", early_evidence))
    late_verification = deepcopy(valid)
    late_verification["evidence"]["host_fencing_verification_completed_at"] = "2026-11-10T00:01:00Z"
    cases.append(("fence evidence independently verified after review", late_verification))
    late_fence = deepcopy(valid)
    late_fence["host"]["provider_fence_verified_at"] = "2026-11-10T00:02:00Z"
    cases.append(("provider fence verified after independent review", late_fence))
    missing_epoch = deepcopy(valid)
    del missing_epoch["host"]["host_incarnation_epoch"]
    cases.append(("missing externally anchored host incarnation epoch", missing_epoch))
    same_reviewer = deepcopy(valid)
    same_reviewer["signoff"]["independent_reviewer_id"] = same_reviewer["signoff"]["host_owner_id"]
    cases.append(("host owner also acts as independent reviewer", same_reviewer))
    expired = deepcopy(valid)
    expired["expires_at"] = "2026-11-09T00:00:00Z"
    cases.append(("authorization expires before issuance", expired))
    for label, manifest in cases:
        if not validate(validator, manifest):
            raise AssertionError(f"unsafe authorization accepted: {label}")
    print("PASS  Draft 2020-12 schema validation")
    print("PASS  complete synthetic Phase A authorization manifest")
    for label, _ in cases:
        print(f"PASS  rejects {label}")
    print("PASS  all nine calibration scenario IDs required exactly once")
    print("PASS  distinct host owner and independent reviewer required")
    print("NOTE  synthetic contract tests only; no real authorization or host proof")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
