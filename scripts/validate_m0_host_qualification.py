#!/usr/bin/env python3
"""Validate M0 host/journal qualification record structure using synthetic data only.

This does not inspect/provision a host, run destructive tests, verify real evidence,
or authorize Phase A, Phase B, student or production execution.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-host-qualification-record.schema.json"
TEMPLATE_PATH = ROOT / "docs/schemas/m0-host-qualification-record.template.json"
PROTOCOL_PATH = ROOT / "docs/specifications/m0-host-and-journal-qualification-protocol.md"
JOURNAL_PATH = ROOT / "docs/specifications/m0-journal-backend-evaluation.md"
RUNBOOK_PATH = ROOT / "docs/specifications/m0-host-preflight-and-proof-runbook.md"
RESOURCE_PATH = ROOT / "docs/specifications/m0-proof-resource-profile-v1.md"
CHECKLIST_PATH = ROOT / "docs/security/m0-independent-security-review-checklist.md"

TESTS = [{"id":"HST-001","domain":"host-baseline","evidenceTypes":["host-configuration"]},{"id":"HST-002","domain":"host-baseline","evidenceTypes":["host-configuration"]},{"id":"HST-003","domain":"host-baseline","evidenceTypes":["filesystem-storage"]},{"id":"HST-004","domain":"host-baseline","evidenceTypes":["host-configuration"]},{"id":"HST-005","domain":"host-baseline","evidenceTypes":["supply-chain"]},{"id":"AUTH-001","domain":"runtime","evidenceTypes":["host-configuration","fault-injection"]},{"id":"RUN-001","domain":"runtime","evidenceTypes":["host-runtime","fault-injection"]},{"id":"CG-001","domain":"runtime","evidenceTypes":["host-runtime","fault-injection"]},{"id":"NET-001","domain":"network","evidenceTypes":["network-observation","host-configuration"]},{"id":"NET-002","domain":"network","evidenceTypes":["network-observation","host-configuration"]},{"id":"FS-001","domain":"runtime","evidenceTypes":["host-runtime","fault-injection"]},{"id":"OUT-001","domain":"runtime","evidenceTypes":["host-runtime","fault-injection"]},{"id":"WDG-001","domain":"watchdog","evidenceTypes":["fault-injection","host-runtime"]},{"id":"WDG-002","domain":"watchdog","evidenceTypes":["fault-injection","host-configuration"]},{"id":"WDG-003","domain":"watchdog","evidenceTypes":["watchdog-control-plane","operator-record"]},{"id":"CLK-001","domain":"clock","evidenceTypes":["host-runtime","fault-injection"]},{"id":"CLK-002","domain":"clock","evidenceTypes":["fault-injection","host-runtime"]},{"id":"JRN-001","domain":"journal","evidenceTypes":["journal-durability","host-configuration"]},{"id":"JRN-002","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-003","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-004","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-005","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-006","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-007","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-008","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-009","domain":"journal","evidenceTypes":["fault-injection","host-configuration"]},{"id":"JRN-010","domain":"integrated-lifecycle","evidenceTypes":["fault-injection","host-runtime"]},{"id":"JRN-011","domain":"integrated-lifecycle","evidenceTypes":["fault-injection","journal-durability"]},{"id":"JRN-012","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-013","domain":"journal","evidenceTypes":["journal-durability","fault-injection"]},{"id":"JRN-014","domain":"journal","evidenceTypes":["host-configuration","fault-injection"]},{"id":"JRN-015","domain":"journal","evidenceTypes":["filesystem-storage","fault-injection"]},{"id":"EVID-001","domain":"evidence","evidenceTypes":["host-runtime","fault-injection"]}]
TEST_IDS = [test["id"] for test in TESTS]
TEST_BY_ID = {test["id"]: test for test in TESTS}
ROOTLESS_TESTS = [
    {"id":"RLS-001","evidenceTypes":["host-runtime","fault-injection"]},
    {"id":"RLS-002","evidenceTypes":["host-configuration","supply-chain","fault-injection"]},
    {"id":"RLS-003","evidenceTypes":["host-runtime","fault-injection"]},
    {"id":"RLS-004","evidenceTypes":["network-observation","host-configuration","fault-injection"]},
]
ROOTLESS_TEST_IDS = {test["id"] for test in ROOTLESS_TESTS}
ROOTLESS_TEST_BY_ID = {test["id"]: test for test in ROOTLESS_TESTS}

def canonical_rootless_profile_sha256(profile):
    """Hash the profile without its self-referential profile_sha256 field.

    Canonical bytes are compact sorted-key JSON, UTF-8, ASCII-escaped, and
    reject non-finite numbers. The profile schema intentionally uses only
    strings, bounded integers and arrays, so this serialization is stable.
    """
    unsigned_profile = {key: value for key, value in profile.items() if key != "profile_sha256"}
    canonical = json.dumps(
        unsigned_profile,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

AUTH_FLAGS = ["phase_a_authorized", "phase_b_authorized", "student_execution_authorized", "production_execution_authorized"]
BASELINE_IDS = {"HST-001", "HST-002", "HST-003", "HST-004", "HST-005"}
RUNTIME_IDS = {"AUTH-001", "RUN-001", "CG-001", "FS-001", "OUT-001"}
NETWORK_IDS = {"NET-001", "NET-002"}
WATCHDOG_IDS = {"WDG-001", "WDG-002", "WDG-003"}
WATCHDOG_SCENARIO_IDS = {f"WD-{i:03d}" for i in range(1, 8)}
OUTER_IDS = {"WDG-003"}
CLOCK_IDS = {"CLK-001", "CLK-002"}
JOURNAL_IDS = {f"JRN-{i:03d}" for i in range(1, 10)} | {f"JRN-{i:03d}" for i in range(12, 16)}
INTEGRATED_IDS = {"JRN-010", "JRN-011"}
EVIDENCE_IDS = {"EVID-001"}

def errors_for(record, schema_validator):
    review = record.get("review", {})
    errors = [error.message for error in schema_validator.iter_errors(record)]
    results = record.get("test_results", [])
    ids = [item.get("test_id") for item in results]
    if len(ids) != len(set(ids)):
        errors.append("duplicate test IDs are prohibited")
    if set(ids) != set(TEST_IDS):
        errors.append("every required qualification test ID must appear exactly once")
    by_id = {item.get("test_id"): item for item in results}

    rootless_results = record.get("candidate_specific_test_results", [])
    rootless_ids = [item.get("test_id") for item in rootless_results]
    if len(rootless_ids) != len(set(rootless_ids)):
        errors.append("duplicate rootless candidate-specific test IDs are prohibited")
    target_architecture = record.get("scope", {}).get("target_architecture")
    if target_architecture == "rootless-containerd-userns" and set(rootless_ids) != ROOTLESS_TEST_IDS:
        errors.append("rootless candidate requires all four candidate-specific qualification tests exactly once")
    if target_architecture == "rootful-supervisor" and rootless_results:
        errors.append("rootful candidate must not claim rootless-only qualification tests")
    if target_architecture == "not-selected" and rootless_results:
        errors.append("unselected architecture cannot contain candidate-specific test results")

    for test_id, finding in by_id.items():
        expected = TEST_BY_ID.get(test_id)
        if not expected:
            continue
        if finding.get("domain") != expected["domain"]:
            errors.append(f"{test_id}: test domain mismatch")
        refs = finding.get("evidence_refs", [])
        if finding.get("result") == "passed":
            if not finding.get("verification_method", "").strip() or not refs:
                errors.append(f"{test_id}: passed requires method and evidence")
            if any(ref.get("verification_status") != "verified" or not ref.get("independent_verifier_id") for ref in refs):
                errors.append(f"{test_id}: passed requires independently verified evidence")
            review_roles = {review.get("reviewer_id"), review.get("host_owner_id")} - {None, ""}
            if any(ref.get("independent_verifier_id") in review_roles for ref in refs):
                errors.append(f"{test_id}: evidence verifier must be independent of reviewer and host owner")
            if any(ref.get("acquired_by_id") in review_roles or
                   ref.get("acquired_by_id") == ref.get("independent_verifier_id") for ref in refs):
                errors.append(f"{test_id}: evidence acquirer must be distinct from verifier, reviewer and host owner")
            allowed = set(expected["evidenceTypes"])
            if not any(ref.get("evidence_type") in allowed for ref in refs):
                errors.append(f"{test_id}: passed requires a test-specific evidence type")
        if finding.get("result") == "failed":
            if finding.get("severity") in {"unassigned", "none"} or not finding.get("finding_summary", "").strip():
                errors.append(f"{test_id}: failed requires severity and finding")

        if test_id == "WDG-002" and finding.get("result") == "passed":
            subtests = finding.get("watchdog_subtests", {})
            if set(subtests) != WATCHDOG_SCENARIO_IDS:
                errors.append("WDG-002: passed requires all seven watchdog subtests exactly once")
            for scenario_id, subtest in subtests.items():
                refs = subtest.get("evidence_refs", [])
                if subtest.get("result") != "passed" or not subtest.get("verification_method", "").strip() or not refs:
                    errors.append(f"WDG-002/{scenario_id}: passed watchdog gate requires passed subtest, method and evidence")
                if any(ref.get("verification_status") != "verified" or not ref.get("independent_verifier_id") for ref in refs):
                    errors.append(f"WDG-002/{scenario_id}: subtest evidence must be independently verified")
                if any(ref.get("independent_verifier_id") in review_roles for ref in refs):
                    errors.append(f"WDG-002/{scenario_id}: verifier must be independent of reviewer and host owner")
                if any(ref.get("acquired_by_id") in review_roles or ref.get("acquired_by_id") == ref.get("independent_verifier_id") for ref in refs):
                    errors.append(f"WDG-002/{scenario_id}: acquirer must be distinct from verifier, reviewer and host owner")
                if any(ref.get("evidence_type") not in {"fault-injection","host-runtime","host-configuration","watchdog-control-plane","operator-record"} for ref in refs):
                    errors.append(f"WDG-002/{scenario_id}: unsupported watchdog subtest evidence type")
                if not any(ref.get("evidence_type") == "fault-injection" for ref in refs):
                    errors.append(f"WDG-002/{scenario_id}: every watchdog subtest requires independently verified fault-injection evidence")
        if finding.get("result") in {"blocked", "deferred"} and not finding.get("finding_summary", "").strip():
            errors.append(f"{test_id}: blocked/deferred requires a reason")

    for finding in rootless_results:
        test_id = finding.get("test_id")
        expected = ROOTLESS_TEST_BY_ID.get(test_id)
        if not expected:
            continue
        if finding.get("domain") != "rootless-compatibility":
            errors.append(f"{test_id}: rootless test domain mismatch")
        refs = finding.get("evidence_refs", [])
        if finding.get("result") == "passed":
            if not finding.get("verification_method", "").strip() or not refs:
                errors.append(f"{test_id}: passed rootless test requires method and evidence")
            if any(ref.get("verification_status") != "verified" or not ref.get("independent_verifier_id") for ref in refs):
                errors.append(f"{test_id}: passed rootless test requires independently verified evidence")
            review_roles = {review.get("reviewer_id"), review.get("host_owner_id")} - {None, ""}
            if any(ref.get("independent_verifier_id") in review_roles for ref in refs):
                errors.append(f"{test_id}: rootless evidence verifier must be independent of reviewer and host owner")
            if any(ref.get("acquired_by_id") in review_roles or
                   ref.get("acquired_by_id") == ref.get("independent_verifier_id") for ref in refs):
                errors.append(f"{test_id}: rootless evidence acquirer must be distinct from verifier, reviewer and host owner")
            if not any(ref.get("evidence_type") in set(expected["evidenceTypes"]) for ref in refs):
                errors.append(f"{test_id}: passed rootless test requires a test-specific evidence type")
        if finding.get("result") == "failed":
            if finding.get("severity") in {"unassigned", "none"} or not finding.get("finding_summary", "").strip():
                errors.append(f"{test_id}: failed rootless test requires severity and finding")
        if finding.get("result") in {"blocked", "deferred"} and not finding.get("finding_summary", "").strip():
            errors.append(f"{test_id}: blocked/deferred rootless test requires a reason")

    gates = record.get("gates", {})
    if gates.get("baseline_inspection") == "passed":
        if not BASELINE_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
            errors.append("baseline inspection gate requires HST-001 through HST-005")
        if not record.get("host_identity", {}).get("selected"):
            errors.append("baseline inspection cannot pass without one selected host incarnation")
    if gates.get("runtime_smoke") == "passed" and not RUNTIME_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("runtime smoke gate requires AUTH-001, RUN-001, CG-001, FS-001 and OUT-001")
    if gates.get("network_boundary") == "passed" and not NETWORK_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("network gate requires NET-001 and NET-002")
    passed_ids = {i for i, f in by_id.items() if f.get("result") == "passed"}
    if gates.get("watchdog_boundary") == "passed" and not WATCHDOG_IDS.issubset(passed_ids):
        errors.append("watchdog gate requires all three watchdog test IDs")
    if gates.get("outer_safety_boundary") == "passed" and not OUTER_IDS.issubset(passed_ids):
        errors.append("outer safety gate requires WDG-003 and external stop/rebuild evidence")
    if gates.get("clock_recovery") == "passed" and not CLOCK_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("clock gate requires CLK-001 and CLK-002")
    if gates.get("journal_durability") == "passed":
        if not JOURNAL_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
            errors.append("journal gate requires JRN-001 through JRN-015")
        journal = record.get("journal_profile", {})
        if journal.get("backend_candidate") != "sqlite-delete-extra" or journal.get("journal_mode") != "DELETE" or journal.get("synchronous") != "EXTRA":
            errors.append("journal gate requires the exact currently proposed SQLite DELETE+EXTRA candidate profile")
    if gates.get("integrated_lifecycle") == "passed" and not INTEGRATED_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("integrated lifecycle gate requires JRN-010 and JRN-011")
    if gates.get("evidence_integrity") == "passed" and not EVIDENCE_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("evidence gate requires EVID-001")
    rootless_gate = gates.get("rootless_userns_compatibility")
    rootless_passed_ids = {f.get("test_id") for f in rootless_results if f.get("result") == "passed"}
    host_profile = record.get("host_identity", {})
    rootless_profile = host_profile.get("rootless_profile")
    rootless_profile_digest = host_profile.get("rootless_profile_digest")
    if target_architecture == "rootless-containerd-userns":
        if not isinstance(rootless_profile, dict):
            errors.append("rootless candidate requires a complete rootless host profile object")
        else:
            if rootless_profile.get("daemon_uid", 0) == 0 or rootless_profile.get("daemon_gid", 0) == 0:
                errors.append("rootless daemon must use non-root UID and GID")
            if rootless_profile.get("user_namespace_mode") != "caller-configured-userns":
                errors.append("rootless host profile must use caller-configured user namespaces")
            controllers = set(rootless_profile.get("delegated_controllers", []))
            if not {"cpu", "memory", "pids"}.issubset(controllers):
                errors.append("rootless profile must explicitly delegate cpu, memory and pids controllers")
            computed_profile_digest = canonical_rootless_profile_sha256(rootless_profile)
            if rootless_profile.get("profile_sha256") != computed_profile_digest:
                errors.append("rootless profile content does not match its canonical SHA-256")
            if rootless_profile_digest != computed_profile_digest:
                errors.append("rootless profile digest does not match canonical profile content")
    elif target_architecture == "rootful-supervisor":
        if rootless_profile is not None or rootless_profile_digest is not None:
            errors.append("rootful candidate must not carry a rootless host profile")
    elif rootless_profile is not None or rootless_profile_digest is not None:
        errors.append("unselected architecture must not carry a rootless host profile")
    if target_architecture == "rootless-containerd-userns":
        if rootless_gate == "passed" and rootless_passed_ids != ROOTLESS_TEST_IDS:
            errors.append("rootless userns compatibility gate requires RLS-001 through RLS-004 to pass")
        if rootless_gate == "not-applicable":
            errors.append("rootless candidate cannot mark its compatibility gate not-applicable")
    elif target_architecture == "rootful-supervisor":
        if rootless_gate != "not-applicable":
            errors.append("rootful candidate must mark rootless userns compatibility not-applicable")
    elif rootless_gate not in {"not-run", None}:
        errors.append("unselected architecture must leave rootless compatibility not-run")

    if record.get("qualification_status") == "candidate-qualified":
        passed_ids = {i for i, f in by_id.items() if f.get("result") == "passed"}
        if set(TEST_IDS) != passed_ids:
            errors.append("candidate-qualified requires every catalogue test to pass")
        if any(gates.get(name) != "passed" for name in [
            "baseline_inspection", "runtime_smoke", "network_boundary", "outer_safety_boundary",
            "watchdog_boundary", "clock_recovery", "journal_durability", "integrated_lifecycle", "evidence_integrity"
        ]):
            errors.append("candidate-qualified requires every qualification sub-gate to pass")
        if target_architecture == "rootless-containerd-userns":
            if gates.get("rootless_userns_compatibility") != "passed" or rootless_passed_ids != ROOTLESS_TEST_IDS:
                errors.append("rootless candidate-qualified requires all four rootless-specific tests and compatibility gate to pass")
        elif target_architecture == "rootful-supervisor":
            if gates.get("rootless_userns_compatibility") != "not-applicable" or rootless_results:
                errors.append("rootful candidate-qualified cannot claim rootless-specific tests")
        else:
            errors.append("candidate-qualified requires rootful or rootless architecture identity")
        host = record.get("host_identity", {})
        baseline_sha = record.get("scope", {}).get("reviewed_commit_sha")
        if not isinstance(baseline_sha, str) or len(baseline_sha) != 40:
            errors.append("candidate-qualified requires an exact 40-character reviewed commit SHA")
        required_host = ["provider", "region", "vm_shape", "host_instance_id", "host_incarnation_epoch", "prior_incarnation_fence_evidence_ref", "host_incarnation_authority_id", "host_incarnation_authority_key_version", "host_incarnation_epoch_evidence_ref", "host_incarnation_issuance_nonce_digest", "predecessor_incarnation_set_digest", "provider_fence_method", "provider_fence_verified_at", "provider_fence_evidence_digest", "boot_id", "image_digest",
            "os_release", "kernel_release", "architecture", "filesystem_type", "storage_device_identity",
            "storage_class", "containerd_version", "containerd_config_digest", "runsc_version", "shim_version",
            "host_profile_digest", "runtime_profile_digest", "resource_profile_digest", "supervisor_digest",
            "watchdog_digest", "test_harness_digest"]
        if not host.get("selected") or any(not host.get(field) for field in required_host):
            errors.append("candidate-qualified requires exact selected host/runtime/storage identity")
        scope = record.get("scope", {})
        if not scope.get("host_provisioning_authorization_ref") or scope.get("target_architecture") == "not-selected":
            errors.append("candidate-qualified requires a separately authorized host and selected architecture")
        if not host.get("mount_options") or host.get("cgroup_mode") != "unified-v2":
            errors.append("candidate-qualified requires recorded mount options and unified cgroup v2")
        journal = record.get("journal_profile", {})
        if journal.get("backend_candidate") != "sqlite-delete-extra":
            errors.append("current M0 host-candidate qualification is limited to the proposed SQLite DELETE+EXTRA candidate; another backend requires an ADR/schema revision")
        if journal.get("backend_candidate") == "sqlite-delete-extra":
            required_journal = ["sqlite_version", "sqlite_source_id", "go_driver_module", "go_driver_version",
                "schema_revision", "journal_owner", "journal_mode_bits", "lock_mechanism",
                "max_database_bytes", "free_space_low_watermark_bytes", "backup_method", "restore_procedure_digest"]
            if any(not journal.get(field) for field in required_journal) or journal.get("journal_mode") != "DELETE" or journal.get("synchronous") != "EXTRA":
                errors.append("SQLite DELETE+EXTRA candidate-qualified record requires exact build, driver, settings and durability profile")
        review = record.get("review", {})
        if record.get("record_status") != "completed" or review.get("status") != "completed":
            errors.append("candidate-qualified requires completed qualification and independent review")
        if not review.get("reviewer_id") or not review.get("host_owner_id") or review.get("reviewer_id") == review.get("host_owner_id"):
            errors.append("candidate-qualified requires distinct reviewer and host owner")
        if not review.get("independence_attested") or not review.get("signature_reference") or not review.get("reviewed_commit_sha"):
            errors.append("candidate-qualified requires independence attestation, reviewed commit and signature reference")
        if review.get("decision") != "accept-host-candidate":
            errors.append("candidate-qualified requires independent accept-host-candidate decision")
        if not review.get("independence_basis", "").strip() or not review.get("reviewed_at") or not review.get("expires_at"):
            errors.append("candidate-qualified requires independence basis and review validity dates")
        if review.get("reviewed_commit_sha") != record.get("scope", {}).get("reviewed_commit_sha"):
            errors.append("reviewed commit must equal the qualification record baseline")
        try:
            review_date = review.get("reviewed_at")
            expiry_date = review.get("expires_at")
            if not review_date or not expiry_date:
                errors.append("candidate-qualified requires valid review dates")
            else:
                reviewed_at = datetime.fromisoformat(review_date.replace("Z", "+00:00"))
                expires_at = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
                if expires_at <= reviewed_at:
                    errors.append("independent review is expired at issuance")
                if expires_at <= datetime.now(timezone.utc):
                    errors.append("independent review has expired at validation time")
            if record.get("reviewed_at") and record.get("expires_at"):
                qualification_reviewed_at = datetime.fromisoformat(record["reviewed_at"].replace("Z", "+00:00"))
                qualification_expires_at = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
                if qualification_expires_at <= qualification_reviewed_at:
                    errors.append("qualification expiry must be later than qualification review date")
                if qualification_expires_at <= datetime.now(timezone.utc):
                    errors.append("qualification record has expired at validation time")
        except (ValueError, TypeError):
            errors.append("candidate-qualified requires valid review dates")
        if not record.get("qualification_rationale", "").strip():
            errors.append("candidate-qualified requires a written qualification rationale")
        unresolved = [risk for risk in record.get("residual_risks", []) if risk.get("severity") in {"high", "critical"} and risk.get("status") != "closed"]
        if unresolved:
            errors.append("candidate-qualified cannot retain unresolved high/critical risks")
    if record.get("qualification_status") == "failed" and not (
        any(f.get("result") == "failed" for f in results) or
        any(f.get("result") == "failed" for f in rootless_results)
    ):
        errors.append("failed qualification requires at least one failed common or candidate-specific test")
    if record.get("record_status") == "not-started":
        if record.get("qualification_status") != "not-qualified":
            errors.append("not-started record must remain not-qualified")
        if record.get("host_identity", {}).get("selected") or any(f.get("result") != "not-run" for f in results):
            errors.append("not-started record cannot have a selected host or executed test")
        if any(value != "not-run" for value in gates.values()):
            errors.append("not-started record cannot have a passed/failed qualification gate")
        if rootless_results:
            errors.append("not-started record cannot contain candidate-specific tests")
        if record.get("scope", {}).get("target_architecture") != "not-selected":
            errors.append("not-started record must have no selected architecture")
        if record.get("journal_profile", {}).get("backend_candidate") != "not-selected":
            errors.append("not-started record must have no selected journal backend")
    review = record.get("review", {})
    if review.get("status") == "completed":
        if not review.get("reviewer_id") or not review.get("host_owner_id") or review.get("reviewer_id") == review.get("host_owner_id"):
            errors.append("completed review requires distinct reviewer and host owner")
        if not review.get("independence_attested") or not review.get("independence_basis", "").strip():
            errors.append("completed review requires an independence attestation and basis")
        if not review.get("reviewed_at") or not review.get("signature_reference"):
            errors.append("completed review requires date and signature reference")
    for flag in AUTH_FLAGS:
        if record.get(flag) is not False:
            errors.append(f"{flag} must remain false in the qualification record")
    return errors

def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    protocol = PROTOCOL_PATH.read_text(encoding="utf-8")
    journal_doc = JOURNAL_PATH.read_text(encoding="utf-8")
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
    resource = RESOURCE_PATH.read_text(encoding="utf-8")
    checklist = CHECKLIST_PATH.read_text(encoding="utf-8")

    if template.get("schema_version") != schema.get("properties", {}).get("schema_version", {}).get("const"):
        raise AssertionError("qualification schema and blank template versions must match")
    Draft202012Validator.check_schema(schema)
    schema_validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = errors_for(template, schema_validator)
    if errors:
        raise AssertionError("blank qualification template rejected: " + "; ".join(errors))
    if template["qualification_status"] != "not-qualified" or template["record_status"] != "not-started":
        raise AssertionError("blank template must remain not-started/not-qualified")
    if template["host_identity"]["selected"] or any(item["result"] != "not-run" for item in template["test_results"]):
        raise AssertionError("blank template cannot contain selected host or executed tests")
    if any(template[flag] is not False for flag in AUTH_FLAGS):
        raise AssertionError("blank template must never authorize execution")

    schema_ids = set(schema["$defs"]["testFinding"]["properties"]["test_id"]["enum"])
    template_ids = {item["test_id"] for item in template["test_results"]}
    if schema_ids != set(TEST_IDS) or template_ids != set(TEST_IDS):
        raise AssertionError("schema/template/test inventory IDs diverge")
    rootless_schema_ids = set(schema["$defs"]["candidateSpecificTestFinding"]["properties"]["test_id"]["enum"])
    if rootless_schema_ids != ROOTLESS_TEST_IDS or template["candidate_specific_test_results"] != []:
        raise AssertionError("rootless-specific schema/template test inventory diverges")
    for test in TESTS:
        if f"| {test['id']} |" not in protocol:
            raise AssertionError(f"protocol missing common test ID {test['id']}")
    for scenario_id in WATCHDOG_SCENARIO_IDS:
        row_marker = f"| {scenario_id} |"
        if protocol.count(row_marker) != 1:
            raise AssertionError(f"protocol must contain exactly one qualification-table row for watchdog subtest {scenario_id}")
    for test in ROOTLESS_TESTS:
        if f"| {test['id']} |" not in protocol:
            raise AssertionError(f"protocol missing rootless-only test ID {test['id']}")
        if test["id"] not in checklist:
            raise AssertionError(f"independent security checklist missing rootless-only test ID {test['id']}")
    if "m0-host-and-journal-qualification-protocol.md" not in journal_doc or "m0-host-and-journal-qualification-protocol.md" not in runbook:
        raise AssertionError("journal evaluation and host runbook must link qualification protocol")
    for setting in ["M0_CONTAINERD_CONFIG", "M0_CONTAINERD_SOCKET", "M0_CONTAINERD_SOCKET_OWNER"]:
        if setting not in runbook:
            raise AssertionError(f"host runbook must document candidate-specific preflight setting {setting}")
    if "m0-host-and-journal-qualification-protocol.md" not in resource or "m0-host-and-journal-qualification-protocol.md" not in checklist:
        raise AssertionError("resource profile and independent security checklist must link qualification protocol")
    if "all seven `WD-001` through `WD-007`" not in checklist:
        raise AssertionError("independent security checklist must require all seven watchdog subtests")
    print("PASS  blank qualification record remains not-started and not-qualified")
    print(f"PASS  schema, template and {len(TESTS)} common qualification tests are synchronized")
    print(f"PASS  rootless candidate schema and {len(ROOTLESS_TESTS)} rootless-only tests are synchronized")
    print("PASS  runbook, journal evaluation, resource profile and security checklist cross-reference protocol")

    cases = []
    case = deepcopy(template); case["test_results"].pop(); cases.append(("missing test",case))
    case = deepcopy(template); case["test_results"][-1]["test_id"] = case["test_results"][0]["test_id"]; cases.append(("duplicate test ID",case))
    case = deepcopy(template); case["test_results"][0]["result"] = "passed"; cases.append(("pass without evidence",case))
    case = deepcopy(template); case["test_results"][0]["result"] = "passed"; case["test_results"][0]["verification_method"] = "synthetic"; case["test_results"][0]["finding_summary"] = "synthetic"; case["test_results"][0]["severity"] = "none"; case["test_results"][0]["evidence_refs"] = [{"reference_id":"x","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_by_id":"synthetic-evidence-acquirer","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1","evidence_type":"host-runtime","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-verifier","verification_note":"synthetic only"}]; cases.append(("passed test with wrong evidence type",case))
    case = deepcopy(template); wdg = next(item for item in case["test_results"] if item["test_id"] == "WDG-002"); wdg.update(result="passed",verification_method="synthetic",finding_summary="synthetic",severity="none",evidence_refs=[{"reference_id":"synthetic-wdg","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_by_id":"synthetic-acquirer","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1","evidence_type":"fault-injection","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-verifier","verification_note":"synthetic"}]); cases.append(("WDG-002 pass with unrun subtests",case))
    case = deepcopy(template); wdg = next(item for item in case["test_results"] if item["test_id"] == "WDG-002"); wdg.update(result="passed",verification_method="synthetic",finding_summary="synthetic",severity="none",evidence_refs=[{"reference_id":"synthetic-wdg","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_by_id":"synthetic-acquirer","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1","evidence_type":"fault-injection","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-verifier","verification_note":"synthetic"}]);
    for subtest in wdg["watchdog_subtests"].values(): subtest.update(result="passed",verification_method="synthetic",finding_summary="synthetic",severity="none",evidence_refs=[{"reference_id":"synthetic-subtest","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_by_id":"synthetic-acquirer","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1","evidence_type":"operator-record","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-verifier","verification_note":"synthetic"}]); cases.append(("WDG-002 subtest without fault-injection evidence",case))
    case = deepcopy(template); case["gates"]["journal_durability"] = "passed"; cases.append(("journal gate without all journal tests",case))
    case = deepcopy(template); case["gates"]["network_boundary"] = "passed"; cases.append(("network gate without both network tests",case))
    case = deepcopy(template); case["qualification_status"] = "candidate-qualified"; cases.append(("qualification without full gates/host identity",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootless-containerd-userns"; case["gates"]["rootless_userns_compatibility"] = "passed"; cases.append(("rootless gate without four passing tests",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootless-containerd-userns"; case["candidate_specific_test_results"] = [{"test_id":"RLS-001","domain":"rootless-compatibility","result":"passed","verification_method":"synthetic","finding_summary":"synthetic","severity":"none","remediation_owner":"","evidence_refs":[]}]; cases.append(("partial rootless-specific test inventory",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootful-supervisor"; case["gates"]["rootless_userns_compatibility"] = "passed"; cases.append(("rootful record claiming rootless compatibility",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootless-containerd-userns"; case["candidate_specific_test_results"] = [{"test_id":"RLS-001","domain":"rootless-compatibility","result":"passed","verification_method":"synthetic","finding_summary":"synthetic","severity":"none","remediation_owner":"","evidence_refs":[{"reference_id":"synthetic","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_by_id":"synthetic-evidence-acquirer","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1","evidence_type":"design-document","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic","verification_note":"synthetic"}]}]; cases.append(("rootless test with wrong evidence type",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootless-containerd-userns"; cases.append(("rootless host profile missing",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootful-supervisor"; case["host_identity"]["rootless_profile"] = {"daemon_uid":1000}; cases.append(("rootful record carrying rootless profile",case))
    profile={"daemon_uid":1000,"daemon_gid":1000,"daemon_identity_digest":"a"*64,"user_namespace_mode":"caller-configured-userns","subuid_map_digest":"b"*64,"subgid_map_digest":"c"*64,"subuid_range_count":1,"subgid_range_count":1,"rootlesskit_version":"synthetic-rootlesskit","rootlesskit_sha256":"d"*64,"newuidmap_sha256":"e"*64,"newgidmap_sha256":"f"*64,"helper_inventory_sha256":"1"*64,"state_directory_policy_sha256":"2"*64,"daemon_socket_policy_sha256":"3"*64,"apparmor_profile_sha256":"4"*64,"network_backend":"synthetic-slirp","network_namespace_profile_sha256":"5"*64,"systemd_delegation_profile_sha256":"6"*64,"delegated_controllers":["cpu","memory","pids"],"profile_sha256":"7"*64}
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootless-containerd-userns"; case["host_identity"]["rootless_profile"] = deepcopy(profile); case["host_identity"]["rootless_profile_digest"]="7"*64; case["host_identity"]["rootless_profile"]["daemon_uid"]=0; cases.append(("rootless daemon using UID zero",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootless-containerd-userns"; case["host_identity"]["rootless_profile"] = deepcopy(profile); case["host_identity"]["rootless_profile_digest"]="7"*64; case["host_identity"]["rootless_profile"]["delegated_controllers"]=["memory","pids"]; cases.append(("rootless profile missing CPU delegation",case))
    case = deepcopy(template); case["scope"]["target_architecture"] = "rootless-containerd-userns"; case["host_identity"]["rootless_profile"] = deepcopy(profile); case["host_identity"]["rootless_profile_digest"]="8"*64; cases.append(("rootless profile digest mismatch",case))
    case = deepcopy(template); case["phase_a_authorized"] = True; cases.append(("Phase A authorization",case))
    case = deepcopy(template); case["phase_b_authorized"] = True; cases.append(("Phase B authorization",case))
    case = deepcopy(template); case["student_execution_authorized"] = True; cases.append(("student execution authorization",case))
    case = deepcopy(template); case["production_execution_authorized"] = True; cases.append(("production authorization",case))
    for label, record in cases:
        if not errors_for(record,schema_validator):
            raise AssertionError(f"unsafe qualification record accepted: {label}")
        print(f"PASS  rejects {label}")

    # Positive synthetic record: demonstrates structural acceptance only.
    synthetic_now = datetime.now(timezone.utc)
    synthetic_reviewed_at = (synthetic_now - timedelta(minutes=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    synthetic_expires_at = (synthetic_now + timedelta(days=30)).isoformat(timespec="seconds").replace("+00:00", "Z")
    complete = deepcopy(template)
    complete["record_status"] = "completed"
    complete["qualification_status"] = "candidate-qualified"
    complete["scope"].update({
        "reviewed_commit_sha":"5"*40,
        "qualification_protocol_digest":"a"*64, "qualification_harness_digest":"b"*64,
        "target_architecture":"rootful-supervisor", "host_provisioning_authorization_ref":"synthetic-provisioning-reference"
    })
    complete["host_identity"].update({
        "selected":True,"provider":"synthetic-provider","region":"synthetic-region","vm_shape":"synthetic-shape",
        "host_instance_id":"synthetic-host-instance","host_incarnation_epoch":"synthetic-host-epoch",
        "prior_incarnation_fence_evidence_ref":"synthetic-prior-incarnation-fence-evidence",
        "host_incarnation_authority_id":"synthetic-authority","host_incarnation_authority_key_version":"synthetic-key-v1",
        "host_incarnation_epoch_evidence_ref":"synthetic-epoch-evidence","host_incarnation_issuance_nonce_digest":"a"*64,
        "predecessor_incarnation_set_digest":"b"*64,"provider_fence_method":"synthetic-provider-hard-stop",
        "provider_fence_verified_at":"2026-11-10T00:00:00Z","provider_fence_evidence_digest":"c"*64,"boot_id":"synthetic-boot-id","image_digest":"c"*64,
        "os_release":"synthetic-os","kernel_release":"synthetic-kernel","architecture":"x86_64",
        "filesystem_type":"synthetic-fs","mount_options":["synthetic-option"],"storage_device_identity":"synthetic-device",
        "storage_class":"synthetic-storage","cgroup_mode":"unified-v2","containerd_version":"synthetic-containerd",
        "containerd_config_digest":"d"*64,"runsc_version":"synthetic-runsc","shim_version":"synthetic-shim",
        "host_profile_digest":"e"*64,"runtime_profile_digest":"f"*64,"resource_profile_digest":"1"*64,
        "supervisor_digest":"2"*64,"watchdog_digest":"3"*64,"test_harness_digest":"b"*64
    })
    complete["journal_profile"].update({
        "backend_candidate":"sqlite-delete-extra","sqlite_version":"synthetic-version","sqlite_source_id":"synthetic-source",
        "go_driver_module":"synthetic-driver","go_driver_version":"synthetic-driver-version",
        "journal_mode":"DELETE","synchronous":"EXTRA","schema_revision":"synthetic-schema",
        "journal_owner":"root:root","journal_mode_bits":"0600","lock_mechanism":"synthetic-kernel-lock",
        "max_database_bytes":1048576,"free_space_low_watermark_bytes":1048576,
        "backup_method":"synthetic-online-backup","restore_procedure_digest":"4"*64
    })
    for gate in complete["gates"]:
        complete["gates"][gate] = "passed"
    complete["gates"]["rootless_userns_compatibility"] = "not-applicable"
    evidence_types = {test["id"]:test["evidenceTypes"][0] for test in TESTS}
    for finding in complete["test_results"]:
        finding.update(result="passed",verification_method="synthetic test",finding_summary="Synthetic positive case only",severity="none")
        if finding["test_id"] == "WDG-002":
            finding["watchdog_subtests"] = {}
            for scenario_id in sorted(WATCHDOG_SCENARIO_IDS):
                finding["watchdog_subtests"][scenario_id] = {
                    "result":"passed","verification_method":"synthetic subtest",
                    "finding_summary":"Synthetic only","severity":"none",
                    "evidence_refs":[{
                        "reference_id":"synthetic-"+scenario_id,"object_version":"v1","sha256":"a"*64,"byte_count":1,
                        "evidence_root_id":"synthetic-root","acquired_by_id":"synthetic-evidence-acquirer","acquired_at":"2026-11-10T00:00:00Z",
                        "acquisition_tool":"synthetic-validator","tool_version":"1.0","evidence_type":"fault-injection",
                        "redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-reviewer",
                        "verification_note":"Synthetic only; not a real host measurement."
                    }]
                }
        finding["evidence_refs"] = [{
            "reference_id":"synthetic-"+finding["test_id"],"object_version":"v1","sha256":"a"*64,"byte_count":1,
            "evidence_root_id":"synthetic-root","acquired_by_id":"synthetic-evidence-acquirer","acquired_at":"2026-11-10T00:00:00Z",
            "acquisition_tool":"synthetic-validator","tool_version":"1.0","evidence_type":evidence_types[finding["test_id"]],
            "redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-reviewer",
            "verification_note":"Synthetic only; not a real host measurement."
        }]
    complete["review"].update({
        "status":"completed","reviewer_id":"synthetic-independent-reviewer","host_owner_id":"synthetic-host-owner",
        "independence_attested":True,"independence_basis":"synthetic identity separation",
        "conflict_disclosure":"synthetic none","decision":"accept-host-candidate",
        "reviewed_commit_sha":complete["scope"]["reviewed_commit_sha"],"reviewed_at":synthetic_reviewed_at,
        "expires_at":synthetic_expires_at,"signature_reference":"synthetic-signature"
    })
    complete["reviewed_at"]=synthetic_reviewed_at
    complete["expires_at"]=synthetic_expires_at
    complete["signature_reference"]="synthetic-signature"
    complete["qualification_rationale"]="Synthetic positive test case only; no real host qualification is asserted."
    if errors_for(complete,schema_validator):
        raise AssertionError("synthetic fully-qualified record failed: " + "; ".join(errors_for(complete,schema_validator)))

    missing_epoch = deepcopy(complete)
    missing_epoch["host_identity"]["host_incarnation_epoch"] = None
    if not any("exact selected host/runtime/storage identity" in error for error in errors_for(missing_epoch,schema_validator)):
        raise AssertionError("candidate-qualified record accepted without external host-incarnation epoch")
    missing_fence = deepcopy(complete)
    missing_fence["host_identity"]["prior_incarnation_fence_evidence_ref"] = None
    if not any("exact selected host/runtime/storage identity" in error for error in errors_for(missing_fence,schema_validator)):
        raise AssertionError("candidate-qualified record accepted without prior-incarnation fence evidence")
    epoch_evidence_fields = [
        "host_incarnation_authority_id", "host_incarnation_authority_key_version",
        "host_incarnation_epoch_evidence_ref", "host_incarnation_issuance_nonce_digest",
        "predecessor_incarnation_set_digest", "provider_fence_method",
        "provider_fence_verified_at", "provider_fence_evidence_digest"
    ]
    for field in epoch_evidence_fields:
        missing_proof = deepcopy(complete)
        missing_proof["host_identity"][field] = None
        if not any("exact selected host/runtime/storage identity" in error for error in errors_for(missing_proof,schema_validator)):
            raise AssertionError(f"candidate-qualified record accepted without {field}")
    print("PASS  requires authenticated epoch authority, nonce, predecessor-set and provider-fence evidence")

    verifier_is_host_owner = deepcopy(complete)
    verifier_is_host_owner["test_results"][0]["evidence_refs"][0]["independent_verifier_id"] = verifier_is_host_owner["review"]["host_owner_id"]
    if not any("evidence verifier must be independent" in error for error in errors_for(verifier_is_host_owner,schema_validator)):
        raise AssertionError("host owner was accepted as independent evidence verifier")
    verifier_is_reviewer = deepcopy(complete)
    verifier_is_reviewer["test_results"][0]["evidence_refs"][0]["independent_verifier_id"] = verifier_is_reviewer["review"]["reviewer_id"]
    if not any("evidence verifier must be independent" in error for error in errors_for(verifier_is_reviewer,schema_validator)):
        raise AssertionError("security reviewer was accepted as independent evidence verifier")
    print("PASS  rejects evidence verification by host owner or independent security reviewer")

    acquired_by_owner = deepcopy(complete)
    acquired_by_owner["test_results"][0]["evidence_refs"][0]["acquired_by_id"] = acquired_by_owner["review"]["host_owner_id"]
    if not any("evidence acquirer must be distinct" in error for error in errors_for(acquired_by_owner, schema_validator)):
        raise AssertionError("host owner was accepted as evidence acquirer")
    acquired_by_verifier = deepcopy(complete)
    acquired_by_verifier["test_results"][0]["evidence_refs"][0]["acquired_by_id"] = acquired_by_verifier["test_results"][0]["evidence_refs"][0]["independent_verifier_id"]
    if not any("evidence acquirer must be distinct" in error for error in errors_for(acquired_by_verifier, schema_validator)):
        raise AssertionError("evidence verifier was accepted as evidence acquirer")
    print("PASS  rejects evidence acquisition by host owner or evidence verifier")

    expired_complete = deepcopy(complete)
    expired_complete["review"]["expires_at"] = "2020-01-02T00:00:00Z"
    expired_complete["expires_at"] = "2020-01-02T00:00:00Z"
    expired_errors = errors_for(expired_complete, schema_validator)
    if not any("expired at validation time" in error for error in expired_errors):
        raise AssertionError("expired independent qualification/review was accepted")
    print("PASS  rejects expired host qualification and independent review")

    if any(complete[flag] is not False for flag in AUTH_FLAGS):
        raise AssertionError("synthetic qualification improperly authorizes execution")
    rootless_complete = deepcopy(complete)
    rootless_complete["scope"]["target_architecture"] = "rootless-containerd-userns"
    rootless_complete["gates"]["rootless_userns_compatibility"] = "passed"
    rootless_profile = {
        "daemon_uid":1000,"daemon_gid":1000,"daemon_identity_digest":"a"*64,
        "user_namespace_mode":"caller-configured-userns","subuid_map_digest":"b"*64,"subgid_map_digest":"c"*64,
        "subuid_range_count":1,"subgid_range_count":1,"rootlesskit_version":"synthetic-rootlesskit",
        "rootlesskit_sha256":"d"*64,"newuidmap_sha256":"e"*64,"newgidmap_sha256":"f"*64,
        "helper_inventory_sha256":"1"*64,"state_directory_policy_sha256":"2"*64,
        "daemon_socket_policy_sha256":"3"*64,"apparmor_profile_sha256":"4"*64,
        "network_backend":"synthetic-slirp","network_namespace_profile_sha256":"5"*64,
        "systemd_delegation_profile_sha256":"6"*64,"delegated_controllers":["cpu","memory","pids"]
    }
    rootless_profile["profile_sha256"] = canonical_rootless_profile_sha256(rootless_profile)
    rootless_complete["host_identity"]["rootless_profile"] = rootless_profile
    rootless_complete["host_identity"]["rootless_profile_digest"] = rootless_profile["profile_sha256"]
    rootless_types = {test["id"]: test["evidenceTypes"][0] for test in ROOTLESS_TESTS}
    rootless_complete["candidate_specific_test_results"] = [{
        "test_id": test["id"], "domain":"rootless-compatibility", "result":"passed",
        "verification_method":"Synthetic rootless compatibility test",
        "finding_summary":"Synthetic only; not a real host measurement.",
        "severity":"none", "remediation_owner":"",
        "evidence_refs":[{
            "reference_id":"synthetic-"+test["id"],"object_version":"v1","sha256":"b"*64,"byte_count":1,
            "evidence_root_id":"synthetic-root","acquired_by_id":"synthetic-evidence-acquirer","acquired_at":"2026-11-10T00:00:00Z",
            "acquisition_tool":"synthetic-validator","tool_version":"1.0","evidence_type":rootless_types[test["id"]],
            "redaction_status":"non-sensitive","verification_status":"verified",
            "independent_verifier_id":"synthetic-reviewer","verification_note":"Synthetic only; not a real host measurement."
        }]
    } for test in ROOTLESS_TESTS]
    rootless_errors = errors_for(rootless_complete, schema_validator)
    if rootless_errors:
        raise AssertionError("synthetic rootless candidate-qualified record rejected: " + "; ".join(rootless_errors))
    stale_profile = deepcopy(rootless_complete)
    stale_profile["host_identity"]["rootless_profile"]["rootlesskit_version"] = "tampered-rootlesskit"
    stale_errors = errors_for(stale_profile, schema_validator)
    if not any("canonical SHA-256" in error for error in stale_errors):
        raise AssertionError("rootless profile content changed without a digest update was accepted")
    print("PASS  rejects rootless profile content changed without canonical digest update")
    print("PASS  accepts rootless qualification only with all four candidate-specific tests")
    print("PASS  accepts synthetic complete qualification while all execution authorizations remain false")
    print("NOTE  synthetic contract tests only; no host selected/tested and no real evidence/signature")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}",file=sys.stderr)
        raise
