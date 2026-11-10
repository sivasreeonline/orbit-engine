#!/usr/bin/env python3
"""Validate M0 host/journal qualification record structure using synthetic data only.

This does not inspect/provision a host, run destructive tests, verify real evidence,
or authorize Phase A, Phase B, student or production execution.
"""
from copy import deepcopy
from datetime import datetime
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
AUTH_FLAGS = ["phase_a_authorized", "phase_b_authorized", "student_execution_authorized", "production_execution_authorized"]
BASELINE_IDS = {"HST-001", "HST-002", "HST-003", "HST-004", "HST-005"}
RUNTIME_IDS = {"AUTH-001", "RUN-001", "CG-001", "FS-001", "OUT-001"}
NETWORK_IDS = {"NET-001", "NET-002"}
WATCHDOG_IDS = {"WDG-001", "WDG-002", "WDG-003"}
CLOCK_IDS = {"CLK-001", "CLK-002"}
JOURNAL_IDS = {f"JRN-{i:03d}" for i in range(1, 16)}
INTEGRATED_IDS = {"JRN-010", "JRN-011"}
EVIDENCE_IDS = {"EVID-001"}

def errors_for(record, schema_validator):
    errors = [error.message for error in schema_validator.iter_errors(record)]
    results = record.get("test_results", [])
    ids = [item.get("test_id") for item in results]
    if len(ids) != len(set(ids)):
        errors.append("duplicate test IDs are prohibited")
    if set(ids) != set(TEST_IDS):
        errors.append("every required qualification test ID must appear exactly once")
    by_id = {item.get("test_id"): item for item in results}

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
            allowed = set(expected["evidenceTypes"])
            if not any(ref.get("evidence_type") in allowed for ref in refs):
                errors.append(f"{test_id}: passed requires a test-specific evidence type")
        if finding.get("result") == "failed":
            if finding.get("severity") in {"unassigned", "none"} or not finding.get("finding_summary", "").strip():
                errors.append(f"{test_id}: failed requires severity and finding")
        if finding.get("result") in {"blocked", "deferred"} and not finding.get("finding_summary", "").strip():
            errors.append(f"{test_id}: blocked/deferred requires a reason")

    gates = record.get("gates", {})
    if gates.get("baseline_inspection") == "passed" and not BASELINE_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("baseline inspection gate requires HST-001 through HST-005")
    if gates.get("runtime_smoke") == "passed" and not RUNTIME_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("runtime smoke gate requires AUTH-001, RUN-001, CG-001, FS-001 and OUT-001")
    if gates.get("network_boundary") == "passed" and not NETWORK_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("network gate requires NET-001 and NET-002")
    if gates.get("watchdog_boundary") == "passed" and not WATCHDOG_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("watchdog gate requires all three watchdog test IDs")
    if gates.get("clock_recovery") == "passed" and not CLOCK_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("clock gate requires CLK-001 and CLK-002")
    if gates.get("journal_durability") == "passed" and not JOURNAL_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("journal gate requires JRN-001 through JRN-015")
    if gates.get("integrated_lifecycle") == "passed" and not INTEGRATED_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("integrated lifecycle gate requires JRN-010 and JRN-011")
    if gates.get("evidence_integrity") == "passed" and not EVIDENCE_IDS.issubset({i for i, f in by_id.items() if f.get("result") == "passed"}):
        errors.append("evidence gate requires EVID-001")

    if record.get("qualification_status") == "candidate-qualified":
        passed_ids = {i for i, f in by_id.items() if f.get("result") == "passed"}
        if set(TEST_IDS) != passed_ids:
            errors.append("candidate-qualified requires every catalogue test to pass")
        if any(gates.get(name) != "passed" for name in [
            "baseline_inspection", "runtime_smoke", "network_boundary", "outer_safety_boundary",
            "watchdog_boundary", "clock_recovery", "journal_durability", "integrated_lifecycle", "evidence_integrity"
        ]):
            errors.append("candidate-qualified requires every qualification sub-gate to pass")
        host = record.get("host_identity", {})
        required_host = ["provider", "region", "vm_shape", "host_instance_id", "boot_id", "image_digest",
            "os_release", "kernel_release", "architecture", "filesystem_type", "storage_device_identity",
            "storage_class", "containerd_version", "containerd_config_digest", "runsc_version", "shim_version",
            "host_profile_digest", "runtime_profile_digest", "resource_profile_digest", "supervisor_digest",
            "watchdog_digest", "test_harness_digest"]
        if not host.get("selected") or any(not host.get(field) for field in required_host):
            errors.append("candidate-qualified requires exact selected host/runtime/storage identity")
        journal = record.get("journal_profile", {})
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
        unresolved = [risk for risk in record.get("residual_risks", []) if risk.get("severity") in {"high", "critical"} and risk.get("status") != "closed"]
        if unresolved:
            errors.append("candidate-qualified cannot retain unresolved high/critical risks")
    if record.get("qualification_status") == "failed" and not any(f.get("result") == "failed" for f in results):
        errors.append("failed qualification requires at least one failed test")
    if record.get("record_status") == "not-started":
        if record.get("qualification_status") != "not-qualified":
            errors.append("not-started record must remain not-qualified")
        if record.get("host_identity", {}).get("selected") or any(f.get("result") != "not-run" for f in results):
            errors.append("not-started record cannot have a selected host or executed test")
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
    for test in TESTS:
        if f"| {test['id']} |" not in protocol:
            raise AssertionError(f"protocol missing test ID {test['id']}")
    if "m0-host-and-journal-qualification-protocol.md" not in journal_doc or "m0-host-and-journal-qualification-protocol.md" not in runbook:
        raise AssertionError("journal evaluation and host runbook must link qualification protocol")
    if "m0-host-and-journal-qualification-protocol.md" not in resource or "m0-host-and-journal-qualification-protocol.md" not in checklist:
        raise AssertionError("resource profile and independent security checklist must link qualification protocol")
    print("PASS  blank qualification record remains not-started and not-qualified")
    print(f"PASS  schema, template and {len(TESTS)}-test protocol catalogue are synchronized")
    print("PASS  runbook, journal evaluation, resource profile and security checklist cross-reference protocol")

    cases = []
    case = deepcopy(template); case["test_results"].pop(); cases.append(("missing test",case))
    case = deepcopy(template); case["test_results"][-1]["test_id"] = case["test_results"][0]["test_id"]; cases.append(("duplicate test ID",case))
    case = deepcopy(template); case["test_results"][0]["result"] = "passed"; cases.append(("pass without evidence",case))
    case = deepcopy(template); case["test_results"][0]["result"] = "passed"; case["test_results"][0]["verification_method"] = "synthetic"; case["test_results"][0]["finding_summary"] = "synthetic"; case["test_results"][0]["severity"] = "none"; case["test_results"][0]["evidence_refs"] = [{"reference_id":"x","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1","evidence_type":"host-runtime","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-verifier","verification_note":"synthetic only"}]; cases.append(("passed test with wrong evidence type",case))
    case = deepcopy(template); case["gates"]["journal_durability"] = "passed"; cases.append(("journal gate without all journal tests",case))
    case = deepcopy(template); case["gates"]["network_boundary"] = "passed"; cases.append(("network gate without both network tests",case))
    case = deepcopy(template); case["qualification_status"] = "candidate-qualified"; cases.append(("qualification without full gates/host identity",case))
    case = deepcopy(template); case["phase_a_authorized"] = True; cases.append(("Phase A authorization",case))
    case = deepcopy(template); case["phase_b_authorized"] = True; cases.append(("Phase B authorization",case))
    case = deepcopy(template); case["student_execution_authorized"] = True; cases.append(("student execution authorization",case))
    case = deepcopy(template); case["production_execution_authorized"] = True; cases.append(("production authorization",case))
    for label, record in cases:
        if not errors_for(record,schema_validator):
            raise AssertionError(f"unsafe qualification record accepted: {label}")
        print(f"PASS  rejects {label}")

    # Positive synthetic record: demonstrates structural acceptance only.
    complete = deepcopy(template)
    complete["record_status"] = "completed"
    complete["qualification_status"] = "candidate-qualified"
    complete["scope"].update({
        "qualification_protocol_digest":"a"*64, "qualification_harness_digest":"b"*64,
        "target_architecture":"rootful-supervisor", "host_provisioning_authorization_ref":"synthetic-provisioning-reference"
    })
    complete["host_identity"].update({
        "selected":True,"provider":"synthetic-provider","region":"synthetic-region","vm_shape":"synthetic-shape",
        "host_instance_id":"synthetic-host-instance","boot_id":"synthetic-boot-id","image_digest":"c"*64,
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
    evidence_types = {test["id"]:test["evidenceTypes"][0] for test in TESTS}
    for finding in complete["test_results"]:
        finding.update(result="passed",verification_method="synthetic test",finding_summary="Synthetic positive case only",severity="none")
        finding["evidence_refs"] = [{
            "reference_id":"synthetic-"+finding["test_id"],"object_version":"v1","sha256":"a"*64,"byte_count":1,
            "evidence_root_id":"synthetic-root","acquired_at":"2026-11-10T00:00:00Z",
            "acquisition_tool":"synthetic-validator","tool_version":"1.0","evidence_type":evidence_types[finding["test_id"]],
            "redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-reviewer",
            "verification_note":"Synthetic only; not a real host measurement."
        }]
    complete["review"].update({
        "status":"completed","reviewer_id":"synthetic-independent-reviewer","host_owner_id":"synthetic-host-owner",
        "independence_attested":True,"independence_basis":"synthetic identity separation",
        "conflict_disclosure":"synthetic none","decision":"accept-host-candidate",
        "reviewed_commit_sha":"5"*40,"reviewed_at":"2026-11-10T00:00:00Z",
        "expires_at":"2026-12-10T00:00:00Z","signature_reference":"synthetic-signature"
    })
    complete["reviewed_at"]="2026-11-10T00:00:00Z"
    complete["expires_at"]="2026-12-10T00:00:00Z"
    complete["signature_reference"]="synthetic-signature"
    if errors_for(complete,schema_validator):
        raise AssertionError("synthetic fully-qualified record failed: " + "; ".join(errors_for(complete,schema_validator)))
    if any(complete[flag] is not False for flag in AUTH_FLAGS):
        raise AssertionError("synthetic qualification improperly authorizes execution")
    print("PASS  accepts synthetic complete qualification while all execution authorizations remain false")
    print("NOTE  synthetic contract tests only; no host selected/tested and no real evidence/signature")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}",file=sys.stderr)
        raise
