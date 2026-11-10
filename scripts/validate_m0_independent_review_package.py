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
EXPECTED_CONTROL_IDS = ["ARCH-001","ARCH-002","AUTH-001","AUTH-002","AUTH-003","API-001","PRIV-001","PRIV-002","RUNTIME-001","RUNTIME-002","OCI-001","NET-001","NET-002","CGROUP-001","FS-001","OUTPUT-001","LIFE-001","LIFE-002","LIFE-003","CLOCK-001","CLOCK-002","JOURNAL-001","JOURNAL-002","JOURNAL-003","WATCH-001","WATCH-002","WATCH-003","EVID-001","EVID-002","SUPPLY-001","OPS-001","OPS-002"]
HOST_EVIDENCE_TYPES = {"host-runtime", "host-configuration", "fault-injection", "supply-chain", "operator-record"}

def custom_errors(record):
    errors = []
    findings = record.get("control_findings", [])
    ids_found = [item.get("control_id") for item in findings]
    if len(ids_found) != len(set(ids_found)): errors.append("duplicate control IDs are prohibited")
    if set(ids_found) != set(EXPECTED_CONTROL_IDS): errors.append("every required control ID must appear exactly once")
    for finding in findings:
        if finding.get("result") == "pass":
            refs = finding.get("evidence_refs", [])
            if not refs or not finding.get("verification_method", "").strip():
                errors.append(f"{finding.get('control_id')}: pass requires method and evidence"); continue
            if any(ref.get("verification_status") != "verified" for ref in refs):
                errors.append(f"{finding.get('control_id')}: pass requires verified references")
            if finding.get("evidence_class") in {"host", "mixed"} and not any(ref.get("evidence_type") in HOST_EVIDENCE_TYPES for ref in refs):
                errors.append(f"{finding.get('control_id')}: host/mixed pass requires host evidence")
        if finding.get("result") in {"fail", "conditional"} and finding.get("severity") in {"high", "critical"} and not finding.get("remediation_owner", "").strip():
            errors.append(f"{finding.get('control_id')}: high/critical finding requires remediation owner")
    actors = record.get("participants", {})
    reviewer, owner = actors.get("reviewer_id"), actors.get("host_owner_id")
    if reviewer and owner and reviewer == owner: errors.append("reviewer and host owner must be distinct")
    decisions = record.get("decisions", {})
    if decisions.get("review_decision") == "approve-architecture-candidate":
        if record.get("review_status") != "completed": errors.append("architecture recommendation requires completed review")
        if not reviewer or not owner or not actors.get("reviewer_independence_attested"): errors.append("architecture recommendation requires independent reviewer and host owner")
        if any(f.get("result") == "not-reviewed" for f in findings if f.get("evidence_class") == "design"): errors.append("architecture recommendation has unreviewed design control")
        if any(f.get("result") in {"fail","conditional"} and f.get("severity") in {"high","critical"} for f in findings): errors.append("architecture recommendation has unresolved high/critical finding")
        if any(r.get("severity") in {"high","critical"} and r.get("status") != "closed" for r in record.get("residual_risks", [])): errors.append("architecture recommendation has unresolved high/critical risk")
        if decisions.get("architecture_recommendation") not in {"rootful-supervisor-candidate","rootless-containerd-candidate"}: errors.append("architecture recommendation must choose a candidate")
    if record.get("review_status") == "completed":
        if not reviewer or not owner or reviewer == owner: errors.append("completed review requires distinct reviewer and host owner")
        if not actors.get("reviewer_independence_attested") or not actors.get("independence_basis", "").strip(): errors.append("completed review requires independence basis")
        if not record.get("reviewed_at") or not record.get("signature_reference"): errors.append("completed review requires date and signature reference")
        if decisions.get("review_decision") == "not-reviewed": errors.append("completed review cannot have not-reviewed decision")
        if any(f.get("result") == "not-reviewed" and f.get("evidence_class") == "design" for f in findings): errors.append("completed review has unreviewed design control")
    try:
        if record.get("reviewed_at") and record.get("expires_at"):
            reviewed = datetime.fromisoformat(record["reviewed_at"].replace("Z","+00:00"))
            expires = datetime.fromisoformat(record["expires_at"].replace("Z","+00:00"))
            if expires <= reviewed: errors.append("review expiry must be later than review date")
    except (ValueError, TypeError): errors.append("review dates must be parseable")
    for key in ["privileged_implementation_authorized","phase_a_authorized","phase_b_authorized","student_execution_authorized","production_execution_authorized"]:
        if record.get(key) is not False: errors.append(f"{key} must remain false in this review record")
    return errors

def validate(validator, record):
    return [e.message for e in validator.iter_errors(record)] + custom_errors(record)

def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = validate(validator, template)
    if errors: raise AssertionError("blank template invalid: " + "; ".join(errors))
    assert template["review_status"] == "not-reviewed"
    assert template["decisions"]["review_decision"] == "not-reviewed"
    assert all(template[k] is False for k in ["privileged_implementation_authorized","phase_a_authorized","phase_b_authorized","student_execution_authorized","production_execution_authorized"])
    print("PASS  blank template validates and remains not-reviewed/non-authorizing")
    cases = []
    x=deepcopy(template); x["control_findings"].pop(); cases.append(("missing control",x))
    x=deepcopy(template); x["control_findings"][-1]["control_id"]=x["control_findings"][0]["control_id"]; cases.append(("duplicate control ID",x))
    x=deepcopy(template); x["control_findings"][0]["result"]="approved"; cases.append(("unsupported status",x))
    x=deepcopy(template); x["control_findings"][0]["result"]="pass"; cases.append(("pass without evidence",x))
    x=deepcopy(template); x["participants"]={"reviewer_id":"same","host_owner_id":"same","reviewer_independence_attested":True,"independence_basis":"synthetic","conflict_disclosure":"none"}; cases.append(("same reviewer and host owner",x))
    for key,label in [("privileged_implementation_authorized","privileged implementation"),("phase_a_authorized","Phase A"),("phase_b_authorized","Phase B"),("student_execution_authorized","student execution"),("production_execution_authorized","production")]:
        x=deepcopy(template); x[key]=True; cases.append((label+" authorization",x))
    x=deepcopy(template); x["review_status"]="completed"; x["reviewed_at"]="2026-11-10T00:00:00Z"; x["expires_at"]="2026-11-09T00:00:00Z"; cases.append(("expired review",x))
    for label, record in cases:
        if not validate(validator,record): raise AssertionError(f"unsafe record accepted: {label}")
        print(f"PASS  rejects {label}")
    complete=deepcopy(template)
    complete["review_status"]="completed"
    complete["participants"]={"reviewer_id":"independent-reviewer","host_owner_id":"host-owner","reviewer_independence_attested":True,"independence_basis":"synthetic separation test","conflict_disclosure":"none"}
    complete["reviewed_at"]="2026-11-10T00:00:00Z"; complete["expires_at"]="2026-12-10T00:00:00Z"; complete["signature_reference"]="synthetic-signature-reference"
    complete["decisions"]={"review_decision":"approve-architecture-candidate","architecture_recommendation":"rootful-supervisor-candidate","implementation_recommendation":"recommend-after-separate-authorization","phase_a_recommendation":"defer","phase_b_recommendation":"blocked"}
    for item in complete["control_findings"]:
        if item["evidence_class"] == "design":
            item.update(result="pass",verification_method="synthetic design review",reviewer_finding="Synthetic test only",severity="none")
            item["evidence_refs"]=[{"reference_id":"synthetic-"+item["control_id"],"object_version":"v1","sha256":"a"*64,"byte_count":1,"evidence_root_id":"synthetic","acquired_at":"2026-11-10T00:00:00Z","acquisition_tool":"validator","evidence_type":"design-document","redaction_status":"non-sensitive","verification_status":"verified","independent_verifier_id":"synthetic-verifier","verifier_note":"synthetic only"}]
    errors=validate(validator,complete)
    if errors: raise AssertionError("valid synthetic design review rejected: " + "; ".join(errors))
    assert complete["privileged_implementation_authorized"] is False and complete["phase_a_authorized"] is False and complete["phase_b_authorized"] is False
    print("PASS  architecture-candidate recommendation cannot authorize implementation or execution")
    print("NOTE  synthetic contract tests only; no actual reviewer/evidence/signature")

if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print(f'ERROR: {exc}',file=sys.stderr); raise
