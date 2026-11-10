#!/usr/bin/env python3
"""Validate the M0 independent-review record contract using synthetic data only.

This does not perform a security review, verify signatures, or authorize execution.
"""
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/security/m0-independent-security-review-record.schema.json"
TEMPLATE_PATH = ROOT / "docs/security/m0-independent-security-review-record.template.json"
CHECKLIST_PATH = ROOT / "docs/security/m0-independent-security-review-checklist.md"
PACKET_PATH = ROOT / "docs/security/m0-sandbox-security-review-packet.md"
ADR_PATH = ROOT / "docs/adr/ADR-0019-m0-host-launch-boundary.md"

EXPECTED_CLASSES = {
    "ARCH-001": "design", "ARCH-002": "design", "AUTH-001": "host",
    "AUTH-002": "host", "AUTH-003": "mixed", "API-001": "design",
    "PRIV-001": "host", "PRIV-002": "host", "RUNTIME-001": "host",
    "RUNTIME-002": "host", "OCI-001": "host", "NET-001": "host",
    "NET-002": "host", "CGROUP-001": "host", "FS-001": "host",
    "OUTPUT-001": "host", "LIFE-001": "mixed", "LIFE-002": "host",
    "LIFE-003": "host", "CLOCK-001": "host", "CLOCK-002": "host",
    "JOURNAL-001": "host", "JOURNAL-002": "host", "JOURNAL-003": "host",
    "WATCH-001": "host", "WATCH-002": "host", "WATCH-003": "host",
    "EVID-001": "mixed", "EVID-002": "host", "SUPPLY-001": "mixed",
    "OPS-001": "mixed", "OPS-002": "design",
}
EXPECTED_CONTROL_IDS = list(EXPECTED_CLASSES)
HOST_EVIDENCE_BY_CONTROL = {
    "AUTH-001": {"host-configuration", "fault-injection"},
    "AUTH-002": {"host-configuration", "fault-injection"},
    "AUTH-003": {"host-configuration", "fault-injection"},
    "PRIV-001": {"host-configuration", "fault-injection"},
    "PRIV-002": {"host-configuration", "fault-injection"},
    "RUNTIME-001": {"supply-chain", "host-configuration"},
    "RUNTIME-002": {"host-runtime", "fault-injection"},
    "OCI-001": {"supply-chain", "host-configuration"},
    "NET-001": {"host-configuration", "fault-injection"},
    "NET-002": {"host-configuration", "fault-injection"},
    "CGROUP-001": {"host-runtime", "fault-injection"},
    "FS-001": {"host-runtime", "host-configuration", "fault-injection"},
    "OUTPUT-001": {"host-runtime", "fault-injection"},
    "LIFE-001": {"host-runtime", "fault-injection"},
    "LIFE-002": {"fault-injection"},
    "LIFE-003": {"host-runtime", "fault-injection"},
    "CLOCK-001": {"host-runtime", "fault-injection"},
    "CLOCK-002": {"host-runtime", "fault-injection"},
    "JOURNAL-001": {"host-configuration", "fault-injection"},
    "JOURNAL-002": {"host-configuration", "fault-injection"},
    "JOURNAL-003": {"host-configuration", "fault-injection"},
    "WATCH-001": {"host-runtime", "fault-injection"},
    "WATCH-002": {"host-configuration", "fault-injection"},
    "WATCH-003": {"host-configuration", "operator-record"},
    "EVID-001": {"host-configuration", "fault-injection"},
    "EVID-002": {"host-runtime", "fault-injection"},
    "SUPPLY-001": {"supply-chain"},
    "OPS-001": {"operator-record", "fault-injection"},
}
AUTHORIZATION_FLAGS = [
    "privileged_implementation_authorized",
    "phase_a_authorized",
    "phase_b_authorized",
    "student_execution_authorized",
    "production_execution_authorized",
]

def custom_errors(record):
    errors = []
    findings = record.get("control_findings", [])
    ids_found = [item.get("control_id") for item in findings]
    if len(ids_found) != len(set(ids_found)):
        errors.append("duplicate control IDs are prohibited")
    if set(ids_found) != set(EXPECTED_CONTROL_IDS):
        errors.append("every required control ID must appear exactly once")

    for finding in findings:
        control_id = finding.get("control_id")
        expected_class = EXPECTED_CLASSES.get(control_id)
        if expected_class and finding.get("evidence_class") != expected_class:
            errors.append(f"{control_id}: evidence class must be {expected_class}")

        refs = finding.get("evidence_refs", [])
        for ref in refs:
            if ref.get("verification_status") == "verified":
                if not ref.get("independent_verifier_id") or not ref.get("verifier_note", "").strip():
                    errors.append(f"{control_id}: verified evidence requires independent verifier identity and note")

        if finding.get("result") == "pass":
            if not refs or not finding.get("verification_method", "").strip():
                errors.append(f"{control_id}: pass requires method and evidence")
                continue
            if any(ref.get("verification_status") != "verified" for ref in refs):
                errors.append(f"{control_id}: pass requires independently verified references")
            allowed = HOST_EVIDENCE_BY_CONTROL.get(control_id)
            if expected_class in {"host", "mixed"} and allowed:
                if not any(ref.get("evidence_type") in allowed for ref in refs):
                    errors.append(f"{control_id}: pass requires one of the control-specific host evidence types")

        if finding.get("result") in {"fail", "conditional"}:
            if finding.get("severity") in {"high", "critical"} and not finding.get("remediation_owner", "").strip():
                errors.append(f"{control_id}: high/critical finding requires remediation owner")

    actors = record.get("participants", {})
    reviewer, owner = actors.get("reviewer_id"), actors.get("host_owner_id")
    if reviewer and owner and reviewer == owner:
        errors.append("reviewer and host owner must be distinct")

    decisions = record.get("decisions", {})
    review_status = record.get("review_status")

    if decisions.get("review_decision") == "approve-architecture-candidate":
        if review_status != "completed":
            errors.append("architecture recommendation requires completed review")
        if not reviewer or not owner or not actors.get("reviewer_independence_attested"):
            errors.append("architecture recommendation requires independent reviewer and host owner")
        design_findings = [f for f in findings if f.get("evidence_class") == "design"]
        if any(f.get("result") not in {"pass", "conditional"} for f in design_findings):
            errors.append("architecture recommendation requires every design control to be reviewed without failure")
        if any(f.get("result") in {"fail", "conditional"} and f.get("severity") in {"high", "critical"} for f in findings):
            errors.append("architecture recommendation has unresolved high/critical finding")
        if any(r.get("severity") in {"high", "critical"} and r.get("status") != "closed" for r in record.get("residual_risks", [])):
            errors.append("architecture recommendation has unresolved high/critical risk")
        if decisions.get("architecture_recommendation") not in {"rootful-supervisor-candidate", "rootless-containerd-candidate"}:
            errors.append("architecture recommendation must choose a candidate")

    if decisions.get("implementation_recommendation") == "recommend-after-separate-authorization":
        if review_status != "completed":
            errors.append("implementation recommendation requires completed review")
        if any(f.get("result") in {"fail", "conditional"} and f.get("severity") in {"high", "critical"} for f in findings):
            errors.append("implementation recommendation has unresolved high/critical finding")

    if decisions.get("phase_a_recommendation") == "eligible-for-separate-calibration-authorization":
        required = {"NET-001", "NET-002", "JOURNAL-001", "CLOCK-001", "CLOCK-002", "WATCH-001", "WATCH-002", "WATCH-003"}
        by_id = {f.get("control_id"): f for f in findings}
        if review_status != "completed" or any(by_id.get(cid, {}).get("result") != "pass" for cid in required):
            errors.append("Phase A eligibility requires completed review and passing required host controls")

    if decisions.get("phase_b_recommendation") == "eligible-after-profile-approval":
        if decisions.get("phase_a_recommendation") != "eligible-for-separate-calibration-authorization":
            errors.append("Phase B recommendation requires prior Phase A eligibility")
        if not record.get("scope", {}).get("resource_profile_revision"):
            errors.append("Phase B recommendation requires an identified reviewed resource-profile revision")

    if review_status == "completed":
        if not reviewer or not owner or reviewer == owner:
            errors.append("completed review requires distinct reviewer and host owner")
        if not actors.get("reviewer_independence_attested") or not actors.get("independence_basis", "").strip():
            errors.append("completed review requires independence basis")
        if not record.get("review_id"):
            errors.append("completed review requires an assigned review UUID")
        if not record.get("reviewed_at") or not record.get("signature_reference"):
            errors.append("completed review requires date and signature reference")
        if decisions.get("review_decision") == "not-reviewed":
            errors.append("completed review cannot have not-reviewed decision")
        if any(f.get("result") == "not-reviewed" and f.get("evidence_class") == "design" for f in findings):
            errors.append("completed review has unreviewed design control")
        if record.get("scope", {}).get("review_scope") == "design-and-host-evidence":
            if not record["scope"].get("host_selected"):
                errors.append("design-and-host review requires a selected host")
            if any(f.get("result") == "not-reviewed" for f in findings):
                errors.append("design-and-host review cannot leave controls not-reviewed")

    try:
        if record.get("reviewed_at") and record.get("expires_at"):
            reviewed = datetime.fromisoformat(record["reviewed_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
            if expires <= reviewed:
                errors.append("review expiry must be later than review date")
    except (ValueError, TypeError):
        errors.append("review dates must be parseable")

    for key in AUTHORIZATION_FLAGS:
        if record.get(key) is not False:
            errors.append(f"{key} must remain false in this review record")
    return errors

def validate(validator, record):
    return [error.message for error in validator.iter_errors(record)] + custom_errors(record)

def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    checklist = CHECKLIST_PATH.read_text(encoding="utf-8")
    packet = PACKET_PATH.read_text(encoding="utf-8")
    adr = ADR_PATH.read_text(encoding="utf-8")

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = validate(validator, template)
    if errors:
        raise AssertionError("blank template invalid: " + "; ".join(errors))
    if template["scope"]["reviewed_commit_sha"] is not None:
        raise AssertionError("blank review template must not pin a stale commit baseline")
    required_documents = ["docs/adr/ADR-0019-decision-dossier.md","docs/adr/ADR-0019-upstream-compatibility-evidence.md","docs/adr/ADR-0019-upstream-source-manifest.json","docs/specifications/m0-host-and-journal-qualification-protocol.md"]
    if not set(required_documents).issubset(set(template["scope"]["documents"])):
        raise AssertionError("review template must include the current ADR-0019 dossier, upstream ledger/manifest and host qualification protocol")
    if template["review_status"] != "not-reviewed" or template["decisions"]["review_decision"] != "not-reviewed":
        raise AssertionError("blank template must remain not-reviewed")
    if any(template[key] is not False for key in AUTHORIZATION_FLAGS):
        raise AssertionError("blank template must never authorize execution")

    template_findings = {item["control_id"]: item for item in template["control_findings"]}
    schema_ids = set(schema["$defs"]["controlFinding"]["properties"]["control_id"]["enum"])
    if schema_ids != set(EXPECTED_CONTROL_IDS) or set(template_findings) != set(EXPECTED_CONTROL_IDS):
        raise AssertionError("schema/template control IDs diverge")
    for control_id, expected_class in EXPECTED_CLASSES.items():
        if template_findings[control_id]["evidence_class"] != expected_class:
            raise AssertionError(f"template evidence class mismatch: {control_id}")
        if f"| {control_id} |" not in checklist:
            raise AssertionError(f"checklist missing control ID: {control_id}")
    if "m0-independent-security-review-checklist.md" not in packet or "m0-independent-security-review-record.schema.json" not in packet:
        raise AssertionError("security packet does not link the independent review package")
    if "m0-independent-security-review-checklist.md" not in adr:
        raise AssertionError("ADR-0019 does not link the independent review checklist")
    if "Independent review: pending." not in packet:
        raise AssertionError("security packet must retain pending review status")
    print("PASS  blank template validates and remains not-reviewed/non-authorizing")
    print("PASS  schema, template, 32-control checklist and evidence classes are synchronized")
    print("PASS  ADR and security packet link the independent review package")

    cases = []
    case = deepcopy(template); case["control_findings"].pop(); cases.append(("missing control", case))
    case = deepcopy(template); case["control_findings"][-1]["control_id"] = case["control_findings"][0]["control_id"]; cases.append(("duplicate control ID", case))
    case = deepcopy(template); case["control_findings"][0]["result"] = "approved"; cases.append(("unsupported status", case))
    case = deepcopy(template); case["control_findings"][0]["result"] = "pass"; cases.append(("pass without evidence", case))
    case = deepcopy(template); case["participants"] = {"reviewer_id":"same","host_owner_id":"same","reviewer_independence_attested":True,"independence_basis":"synthetic","conflict_disclosure":"none"}; cases.append(("same reviewer and host owner", case))
    case = deepcopy(template); case["control_findings"][2]["evidence_class"] = "design"; cases.append(("host control mislabeled as design", case))
    case = deepcopy(template); case["control_findings"][2]["result"] = "pass"; case["control_findings"][2]["verification_method"] = "synthetic"; case["control_findings"][2]["reviewer_finding"] = "synthetic"; case["control_findings"][2]["severity"] = "none"; case["control_findings"][2]["evidence_refs"] = [{"reference_id":"x","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","evidence_type":"design-document","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"reviewer","verifier_note":"synthetic"}]; cases.append(("host pass supported only by design document", case))
    case = deepcopy(template); case["control_findings"][0]["result"] = "pass"; case["control_findings"][0]["verification_method"] = "synthetic"; case["control_findings"][0]["reviewer_finding"] = "synthetic"; case["control_findings"][0]["severity"] = "none"; case["control_findings"][0]["evidence_refs"] = [{"reference_id":"x","object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","evidence_type":"design-document","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":None,"verifier_note":""}]; cases.append(("verified evidence without independent verifier", case))
    for key, label in [
        ("privileged_implementation_authorized", "privileged implementation"),
        ("phase_a_authorized", "Phase A"), ("phase_b_authorized", "Phase B"),
        ("student_execution_authorized", "student execution"),
        ("production_execution_authorized", "production")
    ]:
        case = deepcopy(template); case[key] = True; cases.append((label + " authorization", case))
    case = deepcopy(template); case["review_status"] = "completed"; case["reviewed_at"] = "2026-11-10T00:00:00Z"; case["expires_at"] = "2026-11-09T00:00:00Z"; cases.append(("expired review", case))
    case = deepcopy(template); case["review_status"] = "completed"; cases.append(("completed review without assigned UUID", case))
    case = deepcopy(template); case["review_status"] = "completed"; case["scope"]["reviewed_commit_sha"] = None; cases.append(("completed review without pinned commit", case))

    for label, record in cases:
        if not validate(validator, record):
            raise AssertionError(f"unsafe record accepted: {label}")
        print(f"PASS  rejects {label}")

    complete = deepcopy(template)
    complete["review_status"] = "completed"
    complete["scope"]["reviewed_commit_sha"] = "a" * 40
    complete["review_id"] = "11111111-1111-4111-8111-111111111111"
    complete["participants"] = {
        "reviewer_id":"independent-reviewer", "host_owner_id":"host-owner",
        "reviewer_independence_attested":True, "independence_basis":"synthetic separation test",
        "conflict_disclosure":"none"
    }
    complete["reviewed_at"] = "2026-11-10T00:00:00Z"
    complete["expires_at"] = "2026-12-10T00:00:00Z"
    complete["signature_reference"] = "synthetic-signature-reference"
    complete["decisions"] = {
        "review_decision":"approve-architecture-candidate",
        "architecture_recommendation":"rootful-supervisor-candidate",
        "implementation_recommendation":"recommend-after-separate-authorization",
        "phase_a_recommendation":"defer", "phase_b_recommendation":"blocked"
    }
    for item in complete["control_findings"]:
        if item["evidence_class"] == "design":
            item.update(result="pass", verification_method="synthetic design review",
                        reviewer_finding="Synthetic test only", severity="none")
            item["evidence_refs"] = [{
                "reference_id":"synthetic-" + item["control_id"], "object_version":"v1",
                "sha256":"a"*64, "byte_count":1, "evidence_root_id":"synthetic",
                "acquired_at":"2026-11-10T00:00:00Z", "acquisition_tool":"validator",
                "evidence_type":"design-document", "redaction_status":"non-sensitive",
                "verification_status":"verified", "independent_verifier_id":"synthetic-verifier",
                "verifier_note":"synthetic only"
            }]
    errors = validate(validator, complete)
    if errors:
        raise AssertionError("valid synthetic design review rejected: " + "; ".join(errors))
    if any(complete[key] is not False for key in AUTHORIZATION_FLAGS):
        raise AssertionError("architecture recommendation improperly authorized execution")
    print("PASS  architecture-candidate recommendation cannot authorize implementation or execution")
    print("NOTE  synthetic contract tests only; no actual reviewer/evidence/signature")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
