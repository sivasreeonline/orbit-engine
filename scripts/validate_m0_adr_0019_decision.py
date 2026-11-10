#!/usr/bin/env python3
"""Validate ADR-0019 decision-record contract with synthetic records only.

This does not conduct a security review, qualify a real host, verify real signatures,
provision infrastructure, or authorize execution.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-adr-0019-decision-record.schema.json"
TEMPLATE_PATH = ROOT / "docs/schemas/m0-adr-0019-decision-record.template.json"
DOSSIER_PATH = ROOT / "docs/adr/ADR-0019-decision-dossier.md"
ADR_PATH = ROOT / "docs/adr/ADR-0019-m0-host-launch-boundary.md"
SECURITY_PATH = ROOT / "docs/security/m0-sandbox-security-review-packet.md"
QUALIFICATION_PATH = ROOT / "docs/specifications/m0-host-and-journal-qualification-protocol.md"
CHECKLIST_PATH = ROOT / "docs/security/m0-independent-security-review-checklist.md"

CONTROL_CLASSES = {"ARCH-001":"design","ARCH-002":"design","AUTH-001":"host","AUTH-002":"host","AUTH-003":"mixed","API-001":"design","PRIV-001":"host","PRIV-002":"host","RUNTIME-001":"host","RUNTIME-002":"host","OCI-001":"host","NET-001":"host","NET-002":"host","CGROUP-001":"host","FS-001":"host","OUTPUT-001":"host","LIFE-001":"mixed","LIFE-002":"host","LIFE-003":"host","CLOCK-001":"host","CLOCK-002":"host","JOURNAL-001":"host","JOURNAL-002":"host","JOURNAL-003":"host","WATCH-001":"host","WATCH-002":"host","WATCH-003":"host","EVID-001":"mixed","EVID-002":"host","SUPPLY-001":"mixed","OPS-001":"mixed","OPS-002":"design"}
CONTROL_IDS = ["ARCH-001","ARCH-002","AUTH-001","AUTH-002","AUTH-003","API-001","PRIV-001","PRIV-002","RUNTIME-001","RUNTIME-002","OCI-001","NET-001","NET-002","CGROUP-001","FS-001","OUTPUT-001","LIFE-001","LIFE-002","LIFE-003","CLOCK-001","CLOCK-002","JOURNAL-001","JOURNAL-002","JOURNAL-003","WATCH-001","WATCH-002","WATCH-003","EVID-001","EVID-002","SUPPLY-001","OPS-001","OPS-002"]
TEST_IDS = ["HST-001","HST-002","HST-003","HST-004","HST-005","AUTH-001","RUN-001","CG-001","NET-001","NET-002","FS-001","OUT-001","WDG-001","WDG-002","WDG-003","CLK-001","CLK-002","EVID-001","JRN-001","JRN-002","JRN-003","JRN-004","JRN-005","JRN-006","JRN-007","JRN-008","JRN-009","JRN-010","JRN-011","JRN-012","JRN-013","JRN-014","JRN-015"]
AUTH_FLAGS = ["privileged_implementation_authorized", "phase_a_authorized", "phase_b_authorized",
               "student_execution_authorized", "production_execution_authorized"]
HOST_EVIDENCE_TYPES = {"host-configuration", "host-runtime", "filesystem-storage", "supply-chain",
                       "network-observation", "watchdog-control-plane", "journal-durability",
                       "fault-injection", "operator-record", "host-qualification-record"}
DESIGN_EVIDENCE_TYPES = {"architecture-review", "design-document", "security-review-record"}

def add_error(errors, condition, message):
    if condition:
        errors.append(message)

def validate_record(record, validator):
    errors = [error.message for error in validator.iter_errors(record)]
    candidates = record.get("candidate_assessments", [])
    candidate_ids = [candidate.get("candidate_id") for candidate in candidates]
    add_error(errors, len(candidate_ids) != len(set(candidate_ids)), "candidate IDs must be unique")
    add_error(errors, set(candidate_ids) != {"rootful-supervisor", "rootless-containerd-userns"},
              "both architecture candidates must appear exactly once")
    by_candidate = {candidate.get("candidate_id"): candidate for candidate in candidates}

    for candidate in candidates:
        cid = candidate.get("candidate_id")
        expected_mode = {"rootful-supervisor": "containerd-rootful-supervisor",
                         "rootless-containerd-userns": "containerd-caller-configured-userns"}.get(cid)
        config = candidate.get("configuration", {})
        add_error(errors, config.get("runtime_integration_mode") != expected_mode,
                  f"{cid}: runtime integration mode does not match candidate definition")
        if candidate.get("assessment_status") != "not-assessed":
            if cid == "rootful-supervisor":
                required = ["profile_id", "profile_digest", "runner_identity", "host_controller_identity",
                            "containerd_access_principal", "privilege_inventory_digest", "syscall_inventory_digest",
                            "writable_path_inventory_digest", "service_hardening_digest", "socket_policy_digest"]
                add_error(errors, any(not config.get(name) for name in required),
                          "rootful candidate requires exact supervisor, socket and privilege inventory")
            elif cid == "rootless-containerd-userns":
                required = ["profile_id", "profile_digest", "runner_identity", "host_controller_identity",
                            "containerd_access_principal", "network_backend", "cgroup_delegation_reference",
                            "user_namespace_mapping_reference", "rootlesskit_version"]
                add_error(errors, any(not config.get(name) for name in required),
                          "rootless candidate requires exact daemon, userns, RootlessKit, network and cgroup profile")

        findings = candidate.get("design_findings", [])
        finding_ids = [finding.get("control_id") for finding in findings]
        add_error(errors, len(finding_ids) != len(set(finding_ids)), f"{cid}: duplicate security control IDs")
        add_error(errors, set(finding_ids) != set(CONTROL_IDS), f"{cid}: all 32 controls must appear exactly once")
        for finding in findings:
            control_id = finding.get("control_id")
            expected_class = CONTROL_CLASSES.get(control_id)
            add_error(errors, expected_class and finding.get("evidence_class") != expected_class,
                      f"{cid}/{control_id}: evidence class mismatch")
            refs, result = finding.get("evidence_refs", []), finding.get("result")
            if result == "pass":
                add_error(errors, not finding.get("verification_method", "").strip() or not refs,
                          f"{cid}/{control_id}: pass requires method and evidence")
                add_error(errors, any(ref.get("verification_status") != "verified" or
                                      not ref.get("independent_verifier_id") for ref in refs),
                          f"{cid}/{control_id}: pass requires independently verified references")
                if expected_class == "host":
                    add_error(errors, not any(ref.get("evidence_type") in HOST_EVIDENCE_TYPES for ref in refs),
                              f"{cid}/{control_id}: host control cannot pass on design-only evidence")
                elif expected_class == "design":
                    add_error(errors, not any(ref.get("evidence_type") in DESIGN_EVIDENCE_TYPES for ref in refs),
                              f"{cid}/{control_id}: design control requires design/architecture evidence")
                elif expected_class == "mixed":
                    add_error(errors, not any(ref.get("evidence_type") in HOST_EVIDENCE_TYPES for ref in refs) or
                              not any(ref.get("evidence_type") in DESIGN_EVIDENCE_TYPES for ref in refs),
                              f"{cid}/{control_id}: mixed control requires both design and host evidence")
            if result in {"fail", "conditional"}:
                add_error(errors, finding.get("severity") in {"unassigned", "none"},
                          f"{cid}/{control_id}: fail/conditional requires severity")
                add_error(errors, finding.get("severity") in {"high", "critical"} and
                          not finding.get("remediation_owner", "").strip(),
                          f"{cid}/{control_id}: high/critical finding requires remediation owner")

        design_findings = [f for f in findings if CONTROL_CLASSES.get(f.get("control_id")) == "design"]
        status = candidate.get("assessment_status")
        add_error(errors, status in {"design-assessed", "host-qualified", "rejected"} and
                  any(f.get("result") == "not-reviewed" for f in design_findings),
                  f"{cid}: assessed candidate must have all design controls reviewed")
        add_error(errors, status == "rejected" and not candidate.get("rejection_rationale", "").strip(),
                  f"{cid}: rejected candidate requires a concrete rejection rationale")
        add_error(errors, status in {"design-assessed", "host-qualified"} and
                  not candidate.get("assessment_rationale", "").strip(),
                  f"{cid}: assessed candidate requires a written rationale")

        qualification = candidate.get("qualification_report")
        if status == "host-qualified":
            add_error(errors, not qualification, f"{cid}: host-qualified requires its own qualification report")
            if qualification:
                expected_arch = "rootful-supervisor" if cid == "rootful-supervisor" else "rootless-containerd-userns"
                add_error(errors, qualification.get("target_architecture") != expected_arch,
                          f"{cid}: qualification belongs to a different architecture")
                add_error(errors, qualification.get("record_commit_sha") != record.get("reviewed_commit_sha"),
                          f"{cid}: qualification commit does not match decision baseline")
                add_error(errors, qualification.get("host_profile_digest") != config.get("profile_digest"),
                          f"{cid}: host profile digest mismatch")
                add_error(errors, qualification.get("reviewer_id") == qualification.get("host_owner_id"),
                          f"{cid}: qualification reviewer and host owner must be distinct")
                add_error(errors, not qualification.get("independence_attested"),
                          f"{cid}: qualification independence not attested")
                add_error(errors, set(qualification.get("test_ids", [])) != set(TEST_IDS),
                          f"{cid}: qualification must contain the exact 33 test IDs")
                add_error(errors, any(f.get("result") != "pass" for f in findings),
                          f"{cid}: host-qualified requires all 32 security controls to pass")
                try:
                    reviewed = datetime.fromisoformat(qualification["reviewed_at"].replace("Z", "+00:00"))
                    expires = datetime.fromisoformat(qualification["expires_at"].replace("Z", "+00:00"))
                    add_error(errors, expires <= reviewed, f"{cid}: qualification expiry precedes review")
                    add_error(errors, expires <= datetime.now(timezone.utc), f"{cid}: qualification report is expired")
                except (KeyError, TypeError, ValueError):
                    errors.append(f"{cid}: qualification review dates are invalid")
        else:
            add_error(errors, qualification is not None,
                      f"{cid}: qualification report is only valid for host-qualified status")

    outcome, selected = record.get("outcome"), record.get("selected_candidate")
    expected_selection = {"select-rootful-for-m0-proof": "rootful-supervisor",
                          "select-rootless-for-m0-proof": "rootless-containerd-userns"}.get(outcome)
    add_error(errors, selected != expected_selection, "selected_candidate must match the decision outcome")
    if outcome in {"select-rootful-for-m0-proof", "select-rootless-for-m0-proof"}:
        add_error(errors, record.get("record_status") != "completed",
                  "candidate selection requires completed independent decision")
        add_error(errors, record.get("adr_status") != "accepted-for-m0-proof-boundary",
                  "candidate selection requires ADR accepted-for-M0-proof-boundary status")
        chosen, other = by_candidate.get(expected_selection, {}), by_candidate.get(
            "rootless-containerd-userns" if expected_selection == "rootful-supervisor" else "rootful-supervisor", {})
        add_error(errors, chosen.get("assessment_status") != "host-qualified",
                  "selected candidate must have its own fully qualified host report")
        add_error(errors, other.get("assessment_status") == "not-assessed",
                  "alternative candidate must at least be assessed")
        add_error(errors, not record.get("decision_rationale", "").strip(),
                  "candidate selection requires written decision rationale")
        add_error(errors, any(f.get("result") in {"fail", "conditional"} and f.get("severity") in {"high", "critical"}
                              for candidate in candidates for f in candidate.get("design_findings", [])),
                  "candidate selection cannot retain unresolved high/critical findings")
        add_error(errors, any(risk.get("severity") in {"high", "critical"} and risk.get("status") != "closed"
                              for candidate in candidates for risk in candidate.get("residual_risks", [])),
                  "candidate selection cannot retain unresolved high/critical risks")
    if outcome == "reject-both":
        add_error(errors, record.get("adr_status") != "rejected", "reject-both requires rejected ADR status")
        add_error(errors, any(c.get("assessment_status") != "rejected" for c in candidates),
                  "reject-both requires both candidates explicitly rejected")
    if outcome == "defer":
        add_error(errors, record.get("adr_status") != "deferred", "defer requires deferred ADR status")
    if outcome == "pending":
        add_error(errors, selected is not None or record.get("adr_status") != "proposed",
                  "pending decision must not select a candidate or change proposed ADR status")

    participants = record.get("participants", {})
    reviewer, owner = participants.get("reviewer_id"), participants.get("host_owner_id")
    add_error(errors, reviewer and owner and reviewer == owner, "independent reviewer and host owner must differ")
    if record.get("record_status") == "completed":
        add_error(errors, not reviewer or not owner or reviewer == owner,
                  "completed decision requires distinct reviewer and host owner")
        add_error(errors, not participants.get("independence_attested") or
                  not participants.get("independence_basis", "").strip(),
                  "completed decision requires reviewer independence basis")
        add_error(errors, not record.get("reviewed_commit_sha") or not record.get("reviewed_at") or
                  not record.get("signature_reference"),
                  "completed decision requires exact commit, date and signature reference")
        add_error(errors, outcome == "pending", "completed decision cannot remain pending")
        try:
            reviewed = datetime.fromisoformat(record["reviewed_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
            add_error(errors, expires <= reviewed, "decision expiry precedes review")
        except (KeyError, TypeError, ValueError):
            errors.append("completed decision dates are invalid")
    if record.get("record_status") == "not-started":
        add_error(errors, outcome != "pending" or selected is not None,
                  "not-started record must remain pending with no selection")
        add_error(errors, any(c.get("assessment_status") != "not-assessed" for c in candidates),
                  "not-started record must leave both candidates not-assessed")
        add_error(errors, any(any(f.get("result") != "not-reviewed" for f in c.get("design_findings", []))
                              for c in candidates),
                  "not-started record must leave every finding not-reviewed")
    for flag in AUTH_FLAGS:
        if record.get(flag) is not False:
            errors.append(f"{flag} must remain false in ADR decision record")
    return errors

def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    dossier = DOSSIER_PATH.read_text(encoding="utf-8")
    adr = ADR_PATH.read_text(encoding="utf-8")
    security = SECURITY_PATH.read_text(encoding="utf-8")
    qualification = QUALIFICATION_PATH.read_text(encoding="utf-8")
    checklist = CHECKLIST_PATH.read_text(encoding="utf-8")

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = validate_record(template, validator)
    if errors:
        raise AssertionError("blank ADR decision template invalid: " + "; ".join(errors))
    if template["record_status"] != "not-started" or template["outcome"] != "pending":
        raise AssertionError("blank decision record must remain not-started/pending")
    if template["selected_candidate"] is not None or template["reviewed_commit_sha"] is not None:
        raise AssertionError("blank record cannot select a candidate or review baseline")
    if any(template[flag] is not False for flag in AUTH_FLAGS):
        raise AssertionError("blank ADR decision record cannot authorize execution")
    candidate_map = {c["candidate_id"]: c for c in template["candidate_assessments"]}
    if set(candidate_map) != {"rootful-supervisor", "rootless-containerd-userns"}:
        raise AssertionError("both exact candidate definitions must be present")
    if candidate_map["rootful-supervisor"]["configuration"]["runtime_integration_mode"] != "containerd-rootful-supervisor":
        raise AssertionError("rootful candidate mode mismatch")
    if candidate_map["rootless-containerd-userns"]["configuration"]["runtime_integration_mode"] != "containerd-caller-configured-userns":
        raise AssertionError("rootless candidate must use caller-configured user namespaces")
    for candidate in template["candidate_assessments"]:
        if {f["control_id"] for f in candidate["design_findings"]} != set(CONTROL_IDS):
            raise AssertionError("candidate security control inventory diverges")
    if not all(test_id in dossier for test_id in TEST_IDS):
        raise AssertionError("dossier missing a host qualification test ID")
    for content in [adr, security, qualification, checklist]:
        if "ADR-0019-decision-dossier.md" not in content:
            raise AssertionError("ADR/security/qualification/checklist cross-reference missing")
    if "Proposed" not in adr or "pending independent security review" not in adr.lower():
        raise AssertionError("ADR-0019 must remain proposed pending actual review")
    print("PASS  blank ADR decision record is pending, unassigned and non-authorizing")
    print("PASS  both candidate definitions use the exact allowed integration modes")
    print("PASS  both candidates include the same 32 security controls")
    print("PASS  decision dossier maps all 33 host qualification tests")
    print("PASS  ADR, security packet, qualification protocol and checklist link the dossier")

    cases = []
    case=deepcopy(template); case["candidate_assessments"].pop(); cases.append(("missing candidate",case))
    case=deepcopy(template); case["candidate_assessments"][1]["candidate_id"]="rootful-supervisor"; cases.append(("duplicate candidate",case))
    case=deepcopy(template); case["candidate_assessments"][1]["configuration"]["runtime_integration_mode"]="containerd-rootful-supervisor"; cases.append(("rootless using rootful mode",case))
    case=deepcopy(template); case["candidate_assessments"][1]["configuration"]["runtime_integration_mode"]="runsc-rootless-cli"; cases.append(("runsc CLI rootless conflation",case))
    case=deepcopy(template); case["candidate_assessments"][0]["design_findings"].pop(); cases.append(("missing security control",case))
    case=deepcopy(template); case["candidate_assessments"][0]["design_findings"][-1]["control_id"]=case["candidate_assessments"][0]["design_findings"][0]["control_id"]; cases.append(("duplicate security control",case))
    case=deepcopy(template); case["candidate_assessments"][0]["design_findings"][0]["result"]="pass"; cases.append(("pass without evidence",case))
    case=deepcopy(template); case["candidate_assessments"][0]["assessment_status"]="host-qualified"; cases.append(("host-qualified without report",case))
    case=deepcopy(template); case["outcome"]="select-rootful-for-m0-proof"; case["selected_candidate"]="rootful-supervisor"; cases.append(("selection while pending",case))
    for key,label in [("privileged_implementation_authorized","implementation"),("phase_a_authorized","Phase A"),("phase_b_authorized","Phase B"),("student_execution_authorized","student execution"),("production_execution_authorized","production")]:
        case=deepcopy(template); case[key]=True; cases.append((label+" authorization",case))
    for label,record in cases:
        if not validate_record(record,validator):
            raise AssertionError(f"unsafe decision record accepted: {label}")
        print(f"PASS  rejects {label}")

    # Synthetic positive record: the selected candidate has its own independent
    # qualification record; the alternative is at least design-assessed.
    complete=deepcopy(template)
    complete["record_status"]="completed"
    complete["reviewed_commit_sha"]="a"*40
    complete["outcome"]="select-rootful-for-m0-proof"
    complete["selected_candidate"]="rootful-supervisor"
    complete["adr_status"]="accepted-for-m0-proof-boundary"
    complete["decision_rationale"]="Synthetic contract test only."
    complete["participants"]={"reviewer_id":"synthetic-independent-reviewer","host_owner_id":"synthetic-host-owner",
        "independence_attested":True,"independence_basis":"Synthetic separation","conflict_disclosure":"Synthetic none"}
    complete["reviewed_at"]="2026-11-10T00:00:00Z"
    complete["expires_at"]="2026-12-10T00:00:00Z"
    complete["signature_reference"]="synthetic-signature"
    rootful=next(c for c in complete["candidate_assessments"] if c["candidate_id"]=="rootful-supervisor")
    rootful["assessment_status"]="host-qualified"
    rootful["assessment_rationale"]="Synthetic qualified candidate only."
    rootful["configuration"].update({"profile_id":"synthetic-rootful","profile_digest":"b"*64,
        "runner_identity":"synthetic-runner","host_controller_identity":"synthetic-supervisor",
        "containerd_access_principal":"synthetic-supervisor","privilege_inventory_digest":"c"*64,
        "syscall_inventory_digest":"d"*64,"writable_path_inventory_digest":"e"*64,
        "service_hardening_digest":"f"*64,"socket_policy_digest":"1"*64})
    for finding in rootful["design_findings"]:
        finding.update(result="pass",verification_method="Synthetic test",finding="Synthetic only",severity="none")
        types=["design-document"] if finding["evidence_class"]=="design" else (
            ["design-document","host-configuration"] if finding["evidence_class"]=="mixed" else ["host-configuration"])
        finding["evidence_refs"]=[{
            "reference_id":"synthetic-"+finding["control_id"]+"-"+et,"object_version":"v1","sha256":"2"*64,
            "byte_count":1,"evidence_root_id":"synthetic-root","evidence_type":et,
            "acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1",
            "verification_status":"verified","independent_verifier_id":"synthetic-verifier",
            "verification_note":"Synthetic only","redaction_status":"non-sensitive"} for et in types]
    rootful["qualification_report"]={
        "record_id":"11111111-1111-4111-8111-111111111111","record_sha256":"3"*64,"record_commit_sha":"a"*40,
        "target_architecture":"rootful-supervisor","qualification_status":"candidate-qualified",
        "host_instance_id":"synthetic-host","boot_id":"synthetic-boot","host_profile_digest":"b"*64,
        "runtime_profile_digest":"4"*64,"resource_profile_digest":"5"*64,"journal_profile_digest":"6"*64,
        "supervisor_digest":"7"*64,"watchdog_digest":"8"*64,"test_harness_digest":"9"*64,"test_ids":TEST_IDS,
        "reviewer_id":"synthetic-independent-reviewer","host_owner_id":"synthetic-host-owner","independence_attested":True,
        "reviewed_at":"2026-11-10T00:00:00Z","expires_at":"2026-12-10T00:00:00Z","signature_reference":"synthetic-qualification"}
    rootless=next(c for c in complete["candidate_assessments"] if c["candidate_id"]=="rootless-containerd-userns")
    rootless["assessment_status"]="design-assessed"
    rootless["assessment_rationale"]="Synthetic design assessment only."
    rootless["configuration"].update({
        "profile_id":"synthetic-rootless-profile", "profile_digest":"b"*64,
        "runner_identity":"synthetic-runner", "host_controller_identity":"synthetic-rootless-daemon",
        "containerd_access_principal":"synthetic-rootless-daemon", "network_backend":"synthetic-rootless-network",
        "cgroup_delegation_reference":"synthetic-cgroup-delegation",
        "user_namespace_mapping_reference":"synthetic-subuid-map", "rootlesskit_version":"synthetic-rootlesskit"
    })
    for finding in rootless["design_findings"]:
        if finding["evidence_class"]=="design":
            finding.update(result="pass",verification_method="Synthetic design review",finding="Synthetic only",severity="none",
                evidence_refs=[{"reference_id":"synthetic-rootless-"+finding["control_id"],"object_version":"v1","sha256":"a"*64,
                    "byte_count":1,"evidence_root_id":"synthetic-root","evidence_type":"design-document",
                    "acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","tool_version":"1",
                    "verification_status":"verified","independent_verifier_id":"synthetic-verifier",
                    "verification_note":"Synthetic only","redaction_status":"non-sensitive"}])
    errors=validate_record(complete,validator)
    if errors:
        raise AssertionError("synthetic valid selection rejected: "+"; ".join(errors))
    if any(complete[flag] is not False for flag in AUTH_FLAGS):
        raise AssertionError("architecture selection improperly authorized execution")
    print("PASS  accepts synthetic selection only with candidate-specific complete qualification")
    print("PASS  ADR acceptance leaves implementation and all execution authorizations false")
    print("NOTE  synthetic contract fixtures only; no actual review, host qualification or signature")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
