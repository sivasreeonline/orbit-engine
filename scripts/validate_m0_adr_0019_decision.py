#!/usr/bin/env python3
"""Validate ADR-0019 decision-record contract with synthetic records only.

This does not conduct a security review, qualify a real host, verify real signatures,
provision infrastructure, or authorize execution.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-adr-0019-decision-record.schema.json"
TEMPLATE_PATH = ROOT / "docs/schemas/m0-adr-0019-decision-record.template.json"
DOSSIER_PATH = ROOT / "docs/adr/ADR-0019-decision-dossier.md"
UPSTREAM_EVIDENCE_PATH = ROOT / "docs/adr/ADR-0019-upstream-compatibility-evidence.md"
UPSTREAM_MANIFEST_PATH = ROOT / "docs/adr/ADR-0019-upstream-source-manifest.json"
UPSTREAM_MANIFEST_SCHEMA_PATH = ROOT / "docs/schemas/ADR-0019-upstream-source-manifest.schema.json"
ADR_PATH = ROOT / "docs/adr/ADR-0019-m0-host-launch-boundary.md"
SECURITY_PATH = ROOT / "docs/security/m0-sandbox-security-review-packet.md"
QUALIFICATION_PATH = ROOT / "docs/specifications/m0-host-and-journal-qualification-protocol.md"
CHECKLIST_PATH = ROOT / "docs/security/m0-independent-security-review-checklist.md"

CONTROL_CLASSES = {"ARCH-001":"design","ARCH-002":"design","AUTH-001":"host","AUTH-002":"host","AUTH-003":"mixed","API-001":"design","PRIV-001":"host","PRIV-002":"host","RUNTIME-001":"host","RUNTIME-002":"host","OCI-001":"host","NET-001":"host","NET-002":"host","CGROUP-001":"host","FS-001":"host","OUTPUT-001":"host","LIFE-001":"mixed","LIFE-002":"host","LIFE-003":"host","CLOCK-001":"host","CLOCK-002":"host","JOURNAL-001":"host","JOURNAL-002":"host","JOURNAL-003":"host","WATCH-001":"host","WATCH-002":"host","WATCH-003":"host","EVID-001":"mixed","EVID-002":"host","SUPPLY-001":"mixed","OPS-001":"mixed","OPS-002":"design"}
CONTROL_IDS = ["ARCH-001","ARCH-002","AUTH-001","AUTH-002","AUTH-003","API-001","PRIV-001","PRIV-002","RUNTIME-001","RUNTIME-002","OCI-001","NET-001","NET-002","CGROUP-001","FS-001","OUTPUT-001","LIFE-001","LIFE-002","LIFE-003","CLOCK-001","CLOCK-002","JOURNAL-001","JOURNAL-002","JOURNAL-003","WATCH-001","WATCH-002","WATCH-003","EVID-001","EVID-002","SUPPLY-001","OPS-001","OPS-002"]
TEST_IDS = ["HST-001","HST-002","HST-003","HST-004","HST-005","AUTH-001","RUN-001","CG-001","NET-001","NET-002","FS-001","OUT-001","WDG-001","WDG-002","WDG-003","CLK-001","CLK-002","EVID-001","JRN-001","JRN-002","JRN-003","JRN-004","JRN-005","JRN-006","JRN-007","JRN-008","JRN-009","JRN-010","JRN-011","JRN-012","JRN-013","JRN-014","JRN-015"]
ROOTLESS_TEST_IDS = ["RLS-001", "RLS-002", "RLS-003", "RLS-004"]
AUTH_FLAGS = ["privileged_implementation_authorized", "phase_a_authorized", "phase_b_authorized",
               "student_execution_authorized", "production_execution_authorized"]
HOST_EVIDENCE_TYPES = {"host-configuration", "host-runtime", "filesystem-storage", "supply-chain",
                       "network-observation", "watchdog-control-plane", "journal-durability",
                       "fault-injection", "operator-record", "host-qualification-record"}
DESIGN_EVIDENCE_TYPES = {"architecture-review", "design-document", "security-review-record"}

def add_error(errors, condition, message):
    if condition:
        errors.append(message)

def canonical_rootless_profile_sha256(profile):
    """Hash profile fields excluding profile_sha256 itself.

    Canonical bytes are compact sorted-key JSON, UTF-8, ASCII-escaped, and
    reject non-finite numbers. The profile schema uses strings, bounded
    integers and arrays only, making this serialization deterministic.
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

def upstream_manifest_sha256():
    return hashlib.sha256(UPSTREAM_MANIFEST_PATH.read_bytes()).hexdigest()

def validate_record(record, validator):
    errors = [error.message for error in validator.iter_errors(record)]
    if record.get("record_status") == "completed":
        add_error(errors, record.get("upstream_source_manifest_sha256") != upstream_manifest_sha256(),
                  "completed decision must pin the exact upstream source manifest SHA-256")
    if record.get("record_status") == "not-started":
        add_error(errors, record.get("upstream_source_manifest_sha256") is not None,
                  "not-started decision must not pre-pin an upstream source manifest")
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
        profile = config.get("rootless_profile")
        if cid == "rootful-supervisor":
            add_error(errors, profile is not None or config.get("rootless_profile_digest") is not None,
                      "rootful candidate must not carry a rootless host profile or digest")
        elif cid == "rootless-containerd-userns" and candidate.get("assessment_status") != "not-assessed":
            add_error(errors, not isinstance(profile, dict),
                      "assessed rootless candidate requires a complete structured rootless host profile")
            if isinstance(profile, dict):
                add_error(errors, profile.get("daemon_uid", 0) == 0 or profile.get("daemon_gid", 0) == 0,
                          "rootless daemon identity must be non-root")
                add_error(errors, profile.get("user_namespace_mode") != "caller-configured-userns",
                          "rootless profile must use caller-configured user namespaces")
                computed_profile_digest = canonical_rootless_profile_sha256(profile)
                add_error(errors, profile.get("profile_sha256") != computed_profile_digest,
                          "rootless profile content does not match its canonical SHA-256")
                add_error(errors, config.get("rootless_profile_digest") != computed_profile_digest,
                          "rootless profile digest must match canonical profile content")
                add_error(errors, profile.get("network_backend") != config.get("network_backend"),
                          "rootless network backend must match structured rootless profile")
                add_error(errors, profile.get("rootlesskit_version") != config.get("rootlesskit_version"),
                          "RootlessKit version must match structured rootless profile")
                add_error(errors, not {"cpu", "memory", "pids"}.issubset(set(profile.get("delegated_controllers", []))),
                          "rootless profile must delegate CPU, memory and PID controllers")
        if candidate.get("assessment_status") != "not-assessed":
            if cid == "rootful-supervisor":
                required = ["profile_id", "profile_digest", "runtime_profile_digest", "resource_profile_digest", "journal_profile_digest",
                            "supervisor_digest", "watchdog_digest", "test_harness_digest", "runner_identity", "host_controller_identity",
                            "containerd_access_principal", "privilege_inventory_digest", "syscall_inventory_digest",
                            "writable_path_inventory_digest", "service_hardening_digest", "socket_policy_digest", "network_backend"]
                add_error(errors, any(not config.get(name) for name in required),
                          "rootful candidate requires exact supervisor, socket and privilege inventory")
            elif cid == "rootless-containerd-userns":
                required = ["profile_id", "profile_digest", "runtime_profile_digest", "resource_profile_digest", "journal_profile_digest",
                            "supervisor_digest", "watchdog_digest", "test_harness_digest", "runner_identity", "host_controller_identity",
                            "containerd_access_principal", "privilege_inventory_digest", "syscall_inventory_digest",
                            "writable_path_inventory_digest", "service_hardening_digest", "socket_policy_digest", "network_backend",
                            "cgroup_delegation_reference", "user_namespace_mapping_reference", "rootlesskit_version"]
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
        add_error(errors, status in {"design-assessed", "host-qualified", "rejected", "deferred"} and
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
                qualification_evidence = qualification.get("qualification_record_evidence", {})
                add_error(errors, qualification_evidence.get("reference_id") != qualification.get("record_id"),
                          f"{cid}: qualification evidence reference must identify the exact qualification record UUID")
                add_error(errors, qualification_evidence.get("sha256") != qualification.get("record_sha256"),
                          f"{cid}: qualification evidence SHA-256 must match the signed qualification record digest")
                add_error(errors, qualification_evidence.get("evidence_type") != "host-qualification-record",
                          f"{cid}: qualification evidence must be typed as host-qualification-record")
                add_error(errors, qualification_evidence.get("verification_status") != "verified" or
                          not qualification_evidence.get("independent_verifier_id"),
                          f"{cid}: qualification record must have independently verified evidence")
                add_error(errors, qualification.get("host_profile_digest") != config.get("profile_digest"),
                          f"{cid}: host profile digest mismatch")
                if cid == "rootless-containerd-userns":
                    report_profile = qualification.get("rootless_profile")
                    config_profile = config.get("rootless_profile")
                    add_error(errors, not isinstance(report_profile, dict) or report_profile != config_profile,
                              f"{cid}: qualified rootless host profile must exactly match candidate configuration")
                    add_error(errors, qualification.get("rootless_profile_digest") != config.get("rootless_profile_digest"),
                              f"{cid}: qualified rootless profile digest must match candidate rootless_profile_digest")
                    if isinstance(report_profile, dict):
                        report_profile_digest = canonical_rootless_profile_sha256(report_profile)
                        add_error(errors, report_profile.get("profile_sha256") != report_profile_digest,
                                  f"{cid}: qualification rootless profile content does not match its canonical SHA-256")
                        add_error(errors, qualification.get("rootless_profile_digest") != report_profile_digest,
                                  f"{cid}: qualification rootless profile digest does not match canonical profile content")
                        add_error(errors, report_profile.get("daemon_uid", 0) == 0 or report_profile.get("daemon_gid", 0) == 0,
                                  f"{cid}: qualification rootless daemon identity must be non-root")
                        add_error(errors, not {"cpu", "memory", "pids"}.issubset(set(report_profile.get("delegated_controllers", []))),
                                  f"{cid}: qualification rootless profile must delegate cpu, memory and pids")
                else:
                    add_error(errors, qualification.get("rootless_profile") is not None or
                              qualification.get("rootless_profile_digest") is not None,
                              f"{cid}: rootful qualification cannot carry rootless profile identity")
                for report_field in ["runtime_profile_digest", "resource_profile_digest", "journal_profile_digest",
                                     "supervisor_digest", "watchdog_digest", "test_harness_digest"]:
                    add_error(errors, qualification.get(report_field) != config.get(report_field),
                              f"{cid}: {report_field} does not match candidate configuration")
                add_error(errors, qualification.get("reviewer_id") == qualification.get("host_owner_id"),
                          f"{cid}: qualification reviewer and host owner must be distinct")
                add_error(errors, not qualification.get("independence_attested"),
                          f"{cid}: qualification independence not attested")
                add_error(errors, set(qualification.get("test_ids", [])) != set(TEST_IDS),
                          f"{cid}: qualification must contain the exact 33 test IDs")
                rootless_ids = set(qualification.get("candidate_specific_test_ids", []))
                required_rootless_ids = {"RLS-001", "RLS-002", "RLS-003", "RLS-004"}
                if cid == "rootless-containerd-userns":
                    add_error(errors, rootless_ids != required_rootless_ids,
                              f"{cid}: qualification must include RLS-001 through RLS-004")
                    add_error(errors, qualification.get("rootless_userns_compatibility_gate") != "passed",
                              f"{cid}: rootless compatibility gate must be passed")
                    add_error(errors, qualification.get("rootless_profile") != config.get("rootless_profile"),
                              f"{cid}: qualification rootless host profile does not match candidate configuration")
                    add_error(errors, qualification.get("rootless_profile_digest") != config.get("rootless_profile_digest"),
                              f"{cid}: qualification rootless profile digest does not match candidate rootless_profile_digest")
                else:
                    add_error(errors, bool(rootless_ids) or
                              qualification.get("rootless_userns_compatibility_gate") != "not-applicable",
                              f"{cid}: rootful qualification cannot claim rootless-specific tests")
                    add_error(errors, qualification.get("rootless_profile") is not None or
                              qualification.get("rootless_profile_digest") is not None,
                              f"{cid}: rootful qualification cannot carry rootless profile identity")
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
    add_error(errors, outcome != "pending" and record.get("record_status") != "completed",
              "every non-pending architecture outcome requires completed independent sign-off")
    add_error(errors, selected != expected_selection, "selected_candidate must match the decision outcome")
    if outcome in {"select-rootful-for-m0-proof", "select-rootless-for-m0-proof"}:
        add_error(errors, record.get("record_status") != "completed",
                  "candidate selection requires completed independent decision")
        add_error(errors, record.get("review_scope") != "design-and-host-evidence",
                  "candidate selection requires design and host evidence review scope")
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
        add_error(errors, not record.get("decision_record_id"),
                  "completed decision requires an assigned decision-record UUID")
        add_error(errors, not record.get("reviewed_commit_sha") or not record.get("reviewed_at") or
                  not record.get("signature_reference"),
                  "completed decision requires exact commit, date and signature reference")
        add_error(errors, outcome == "pending", "completed decision cannot remain pending")
        try:
            reviewed = datetime.fromisoformat(record["reviewed_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
            add_error(errors, expires <= reviewed, "decision expiry precedes review")
            add_error(errors, expires <= datetime.now(timezone.utc), "decision record is expired")
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
    upstream_evidence = UPSTREAM_EVIDENCE_PATH.read_text(encoding="utf-8")
    source_manifest = json.loads(UPSTREAM_MANIFEST_PATH.read_text(encoding="utf-8"))
    source_manifest_schema = json.loads(UPSTREAM_MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    adr = ADR_PATH.read_text(encoding="utf-8")
    security = SECURITY_PATH.read_text(encoding="utf-8")
    qualification = QUALIFICATION_PATH.read_text(encoding="utf-8")
    checklist = CHECKLIST_PATH.read_text(encoding="utf-8")

    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(source_manifest_schema)
    source_manifest_validator = Draft202012Validator(source_manifest_schema, format_checker=FormatChecker())
    source_manifest_errors = [error.message for error in source_manifest_validator.iter_errors(source_manifest)]
    if source_manifest_errors:
        raise AssertionError("upstream source manifest schema invalid: " + "; ".join(source_manifest_errors))
    expected_source_ids = {"gvisor-rootless", "gvisor-containerd", "gvisor-platforms", "gvisor-networking", "containerd-rootless", "rootlesskit-v3.3.0", "runc-cgroup"}
    source_ids = [entry["source_id"] for entry in source_manifest["entries"]]
    if len(source_ids) != len(set(source_ids)) or set(source_ids) != expected_source_ids:
        raise AssertionError("upstream source manifest must contain exactly seven unique pinned source IDs")
    for entry in source_manifest["entries"]:
        expected_url = f"https://github.com/{entry['repository']}/blob/{entry['commit_sha']}/{entry['path']}"
        if entry["immutable_file_url"] != expected_url or entry["immutable_file_url"] not in upstream_evidence:
            raise AssertionError(f"{entry['source_id']}: immutable source URL mismatch or missing from ledger")
    if "https://gvisor.dev/docs/" in upstream_evidence:
        raise AssertionError("upstream ledger must not rely on mutable gvisor.dev documentation URLs")
    manifest_digest = upstream_manifest_sha256()
    if template.get("upstream_source_manifest_sha256") is not None:
        raise AssertionError("blank decision template must not pin an upstream source set")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = validate_record(template, validator)
    if errors:
        raise AssertionError("blank ADR decision template invalid: " + "; ".join(errors))
    if template["record_status"] != "not-started" or template["outcome"] != "pending":
        raise AssertionError("blank decision record must remain not-started/pending")
    if template["selected_candidate"] is not None or template["reviewed_commit_sha"] is not None:
        raise AssertionError("blank record cannot select a candidate or review baseline")
    if template["upstream_source_manifest_sha256"] is not None:
        raise AssertionError("blank record cannot pre-pin the upstream source manifest")
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
        raise AssertionError("dossier missing a common host qualification test ID")
    if not all(test_id in dossier for test_id in ROOTLESS_TEST_IDS):
        raise AssertionError("dossier missing a rootless-specific qualification test ID")
    if not all(test_id in qualification for test_id in ROOTLESS_TEST_IDS):
        raise AssertionError("host qualification protocol missing rootless-specific test IDs")
    if not all(test_id in checklist for test_id in ROOTLESS_TEST_IDS):
        raise AssertionError("independent reviewer checklist missing rootless-specific test IDs")
    for content in [adr, security, qualification, checklist]:
        if "ADR-0019-decision-dossier.md" not in content:
            raise AssertionError("ADR/security/qualification/checklist cross-reference missing")
        if "ADR-0019-upstream-source-manifest.json" not in content:
            raise AssertionError("ADR/security/qualification/checklist must link the immutable upstream source manifest")
    if "ADR-0019-upstream-source-manifest.json" not in dossier:
        raise AssertionError("decision dossier must link the immutable upstream source manifest")
    print(f"PASS  upstream source manifest has seven immutable pins; SHA-256 {manifest_digest}")
    required_upstream_facts = [
        "`runsc --rootless` CLI mode does not support `create`",
        "newuidmap", "newgidmap", "subordinate", "RootlessKit", "CPU",
        "containerd-shim-runsc-v1", "hard integration gate", "No architecture choice is made"
    ]
    missing_facts = [fact for fact in required_upstream_facts if fact.lower() not in upstream_evidence.lower()]
    if missing_facts:
        raise AssertionError("upstream compatibility evidence missing required fact(s): " + ", ".join(missing_facts))
    if "ADR-0019-upstream-compatibility-evidence.md" not in dossier or "ADR-0019-upstream-compatibility-evidence.md" not in adr:
        raise AssertionError("ADR decision dossier and ADR-0019 must link upstream compatibility ledger")
    if "ADR-0019-upstream-compatibility-evidence.md" not in security or "ADR-0019-upstream-compatibility-evidence.md" not in qualification or "ADR-0019-upstream-compatibility-evidence.md" not in checklist:
        raise AssertionError("security/qualification/checklist must link upstream compatibility ledger")
    print("PASS  upstream compatibility ledger covers rootless CLI limits, userns helpers, cgroup delegation and exact shim gap")
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
    case=deepcopy(template); case["candidate_assessments"][1]["assessment_status"]="host-qualified"; case["candidate_assessments"][1]["configuration"].update({"profile_id":"x","profile_digest":"a"*64,"runtime_profile_digest":"a"*64,"resource_profile_digest":"a"*64,"journal_profile_digest":"a"*64,"supervisor_digest":"a"*64,"watchdog_digest":"a"*64,"test_harness_digest":"a"*64,"runner_identity":"x","host_controller_identity":"x","containerd_access_principal":"x","privilege_inventory_digest":"a"*64,"syscall_inventory_digest":"a"*64,"writable_path_inventory_digest":"a"*64,"service_hardening_digest":"a"*64,"socket_policy_digest":"a"*64,"network_backend":"x","cgroup_delegation_reference":"x","user_namespace_mapping_reference":"x","rootlesskit_version":"x"}); case["candidate_assessments"][1]["qualification_report"]={"record_id":"11111111-1111-4111-8111-111111111111","record_sha256":"a"*64,"record_commit_sha":"a"*40,"target_architecture":"rootless-containerd-userns","qualification_status":"candidate-qualified","host_instance_id":"x","boot_id":"x","host_profile_digest":"a"*64,"runtime_profile_digest":"a"*64,"resource_profile_digest":"a"*64,"journal_profile_digest":"a"*64,"supervisor_digest":"a"*64,"watchdog_digest":"a"*64,"test_harness_digest":"a"*64,"test_ids":TEST_IDS,"candidate_specific_test_ids":[],"rootless_userns_compatibility_gate":"not-applicable","reviewer_id":"reviewer","host_owner_id":"owner","independence_attested":True,"reviewed_at":"2026-11-10T00:00:00Z","expires_at":"2026-12-10T00:00:00Z","signature_reference":"synthetic"}; cases.append(("rootless qualification missing four candidate-specific tests",case))
    case=deepcopy(template); case["outcome"]="select-rootful-for-m0-proof"; case["selected_candidate"]="rootful-supervisor"; cases.append(("selection while pending",case))
    case=deepcopy(template); case.update(record_status="completed",outcome="defer",adr_status="deferred",reviewed_commit_sha="a"*40,reviewed_at="2026-11-10T00:00:00Z",expires_at="2026-12-10T00:00:00Z",signature_reference="synthetic"); case["participants"]={"reviewer_id":"reviewer","host_owner_id":"owner","independence_attested":True,"independence_basis":"synthetic","conflict_disclosure":"none"}; cases.append(("completed decision without UUID",case))
    case=deepcopy(template); case.update(record_status="completed",decision_record_id="22222222-2222-4222-8222-222222222222",outcome="defer",adr_status="deferred",reviewed_commit_sha="a"*40,reviewed_at="2026-11-01T00:00:00Z",expires_at="2026-11-02T00:00:00Z",signature_reference="synthetic"); case["participants"]={"reviewer_id":"reviewer","host_owner_id":"owner","independence_attested":True,"independence_basis":"synthetic","conflict_disclosure":"none"}; cases.append(("expired decision record",case))
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
    complete["upstream_source_manifest_sha256"] = manifest_digest
    complete["decision_record_id"]="22222222-2222-4222-8222-222222222222"
    complete["review_scope"]="design-and-host-evidence"
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
        "runtime_profile_digest":"4"*64,"resource_profile_digest":"5"*64,"journal_profile_digest":"6"*64,
        "supervisor_digest":"7"*64,"watchdog_digest":"8"*64,"test_harness_digest":"9"*64,
        "runner_identity":"synthetic-runner","host_controller_identity":"synthetic-supervisor",
        "containerd_access_principal":"synthetic-supervisor","privilege_inventory_digest":"c"*64,
        "syscall_inventory_digest":"d"*64,"writable_path_inventory_digest":"e"*64,
        "service_hardening_digest":"f"*64,"socket_policy_digest":"1"*64,"network_backend":"synthetic-host-network"})
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
        "qualification_record_evidence":{"reference_id":"11111111-1111-4111-8111-111111111111",
            "object_version":"v1","sha256":"3"*64,"byte_count":1,"evidence_root_id":"synthetic-root",
            "evidence_type":"host-qualification-record","acquired_at":"2026-11-10T00:00:00Z",
            "acquisition_tool":"synthetic-validator","tool_version":"1","verification_status":"verified",
            "independent_verifier_id":"synthetic-evidence-verifier","verification_note":"Synthetic only",
            "redaction_status":"non-sensitive"},
        "target_architecture":"rootful-supervisor","qualification_status":"candidate-qualified",
        "host_instance_id":"synthetic-host","boot_id":"synthetic-boot","host_profile_digest":"b"*64,
        "runtime_profile_digest":"4"*64,"resource_profile_digest":"5"*64,"journal_profile_digest":"6"*64,
        "supervisor_digest":"7"*64,"watchdog_digest":"8"*64,"test_harness_digest":"9"*64,"test_ids":TEST_IDS,
        "reviewer_id":"synthetic-independent-reviewer","host_owner_id":"synthetic-host-owner","independence_attested":True,
        "candidate_specific_test_ids":[],"rootless_userns_compatibility_gate":"not-applicable","rootless_profile":None,"rootless_profile_digest":None,
        "reviewed_at":"2026-11-10T00:00:00Z","expires_at":"2026-12-10T00:00:00Z","signature_reference":"synthetic-qualification"}
    rootless=next(c for c in complete["candidate_assessments"] if c["candidate_id"]=="rootless-containerd-userns")
    mismatched_qualification = deepcopy(complete)
    mismatched_rootful = next(c for c in mismatched_qualification["candidate_assessments"] if c["candidate_id"]=="rootful-supervisor")
    mismatched_rootful["qualification_report"]["qualification_record_evidence"]["sha256"] = "0"*64
    mismatch_errors = validate_record(mismatched_qualification, validator)
    if not any("qualification evidence SHA-256" in error for error in mismatch_errors):
        raise AssertionError("qualification evidence with mismatched record digest was accepted")
    print("PASS  rejects host qualification evidence whose digest does not match the signed record")

    rootless["assessment_status"]="design-assessed"
    rootless["assessment_rationale"]="Synthetic design assessment only."
    rootless["configuration"].update({
        "profile_id":"synthetic-rootless-profile", "profile_digest":"b"*64,"rootless_profile_digest":"a"*64,"rootless_profile":{
            "daemon_uid":1000,"daemon_gid":1000,"daemon_identity_digest":"a"*64,"user_namespace_mode":"caller-configured-userns",
            "subuid_map_digest":"b"*64,"subgid_map_digest":"c"*64,"subuid_range_count":1,"subgid_range_count":1,
            "rootlesskit_version":"synthetic-rootlesskit","rootlesskit_sha256":"d"*64,"newuidmap_sha256":"e"*64,"newgidmap_sha256":"f"*64,
            "helper_inventory_sha256":"1"*64,"state_directory_policy_sha256":"2"*64,"daemon_socket_policy_sha256":"3"*64,
            "apparmor_profile_sha256":"4"*64,"network_backend":"synthetic-slirp","network_namespace_profile_sha256":"5"*64,
            "systemd_delegation_profile_sha256":"6"*64,"delegated_controllers":["cpu","memory","pids"]
        },"runtime_profile_digest":"4"*64,
        "resource_profile_digest":"5"*64,"journal_profile_digest":"6"*64,"supervisor_digest":"7"*64,
        "watchdog_digest":"8"*64,"test_harness_digest":"9"*64,
        "runner_identity":"synthetic-runner", "host_controller_identity":"synthetic-rootless-daemon",
        "containerd_access_principal":"synthetic-rootless-daemon", "privilege_inventory_digest":"c"*64,
        "syscall_inventory_digest":"d"*64,"writable_path_inventory_digest":"e"*64,
        "service_hardening_digest":"f"*64,"socket_policy_digest":"1"*64,"network_backend":"synthetic-slirp",
        "cgroup_delegation_reference":"synthetic-cgroup-delegation",
        "user_namespace_mapping_reference":"synthetic-subuid-map", "rootlesskit_version":"synthetic-rootlesskit"
    })
    synthetic_profile = rootless["configuration"]["rootless_profile"]
    synthetic_profile["profile_sha256"] = canonical_rootless_profile_sha256(synthetic_profile)
    rootless["configuration"]["rootless_profile_digest"] = synthetic_profile["profile_sha256"]
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
    source_mismatch = deepcopy(complete)
    source_mismatch["upstream_source_manifest_sha256"] = "f" * 64
    if not validate_record(source_mismatch, validator):
        raise AssertionError("completed architecture decision with a mismatched upstream source manifest digest was accepted")
    print("PASS  rejects completed decision with mismatched upstream source manifest digest")
    if any(complete[flag] is not False for flag in AUTH_FLAGS):
        raise AssertionError("architecture selection improperly authorized execution")
    mismatch=deepcopy(complete)
    mismatch_rootful=next(c for c in mismatch["candidate_assessments"] if c["candidate_id"]=="rootful-supervisor")
    mismatch_rootful["qualification_report"]["runtime_profile_digest"]="f"*64
    if not validate_record(mismatch,validator):
        raise AssertionError("candidate qualification with mismatched runtime digest was accepted")
    print("PASS  rejects selected candidate with mismatched runtime profile digest")

    # Synthetic positive rootless path: Candidate B must have its own full
    # qualification report and all four RLS tests; Candidate A is design-assessed
    # as the alternative but is not selected.
    rootless_complete = deepcopy(complete)
    rootless_complete["outcome"] = "select-rootless-for-m0-proof"
    rootless_complete["selected_candidate"] = "rootless-containerd-userns"
    rootful_alt = next(c for c in rootless_complete["candidate_assessments"] if c["candidate_id"] == "rootful-supervisor")
    rootful_alt["assessment_status"] = "design-assessed"
    rootful_alt["assessment_rationale"] = "Synthetic rootful design assessment only."
    rootful_alt["qualification_report"] = None
    rootless = next(c for c in rootless_complete["candidate_assessments"] if c["candidate_id"] == "rootless-containerd-userns")
    rootless["assessment_status"] = "host-qualified"
    rootless["assessment_rationale"] = "Synthetic fully-qualified rootless candidate."
    rootless["configuration"].update({
        "profile_id":"synthetic-rootless", "profile_digest":"b"*64,
        "runtime_profile_digest":"4"*64, "resource_profile_digest":"5"*64,
        "journal_profile_digest":"6"*64, "supervisor_digest":"7"*64,
        "watchdog_digest":"8"*64, "test_harness_digest":"9"*64,
        "runner_identity":"synthetic-runner", "host_controller_identity":"synthetic-rootless-daemon",
        "containerd_access_principal":"synthetic-rootless-daemon", "privilege_inventory_digest":"c"*64,
        "syscall_inventory_digest":"d"*64, "writable_path_inventory_digest":"e"*64,
        "service_hardening_digest":"f"*64, "socket_policy_digest":"1"*64,
        "network_backend":"synthetic-slirp", "cgroup_delegation_reference":"synthetic-delegation",
        "user_namespace_mapping_reference":"synthetic-subuid-map", "rootlesskit_version":"synthetic-rootlesskit"
    })
    for finding in rootless["design_findings"]:
        finding.update(result="pass", verification_method="Synthetic candidate review",
                       finding="Synthetic only", severity="none")
        if finding["evidence_class"] == "design":
            evidence_types = ["design-document"]
        elif finding["evidence_class"] == "host":
            evidence_types = ["host-configuration"]
        else:
            evidence_types = ["design-document", "host-configuration"]
        finding["evidence_refs"] = [{
            "reference_id":"synthetic-rootless-"+finding["control_id"]+"-"+evidence_type,
            "object_version":"v1", "sha256":"a"*64, "byte_count":1,
            "evidence_root_id":"synthetic-root", "evidence_type":evidence_type,
            "acquired_at":"2026-11-10T00:00:00Z", "acquisition_tool":"validator",
            "tool_version":"1.0", "verification_status":"verified",
            "independent_verifier_id":"synthetic-verifier", "verification_note":"Synthetic only",
            "redaction_status":"non-sensitive"
        } for evidence_type in evidence_types]
    rootless["qualification_report"] = {
        "record_id":"22222222-2222-4222-8222-222222222222", "record_sha256":"3"*64,
        "record_commit_sha":"a"*40, "target_architecture":"rootless-containerd-userns",
        "qualification_status":"candidate-qualified", "host_instance_id":"synthetic-rootless-host",
        "boot_id":"synthetic-rootless-boot", "host_profile_digest":rootless["configuration"]["profile_digest"],
        "runtime_profile_digest":"4"*64, "resource_profile_digest":"5"*64,
        "journal_profile_digest":"6"*64, "supervisor_digest":"7"*64,
        "watchdog_digest":"8"*64, "test_harness_digest":"9"*64,
        "test_ids":TEST_IDS, "candidate_specific_test_ids":ROOTLESS_TEST_IDS,
        "rootless_userns_compatibility_gate":"passed",
        "rootless_profile":deepcopy(rootless["configuration"]["rootless_profile"]),
        "rootless_profile_digest":rootless["configuration"]["rootless_profile_digest"],
        "reviewer_id":"synthetic-independent-reviewer", "host_owner_id":"synthetic-host-owner",
        "independence_attested":True, "reviewed_at":"2026-11-10T00:00:00Z",
        "expires_at":"2026-12-10T00:00:00Z", "signature_reference":"synthetic-rootless-qualification"
    }
    rootless_errors = validate_record(rootless_complete, validator)
    if rootless_errors:
        raise AssertionError("synthetic rootless candidate selection rejected: " + "; ".join(rootless_errors))
    rootless_missing = deepcopy(rootless_complete)
    selected_rootless = next(c for c in rootless_missing["candidate_assessments"] if c["candidate_id"] == "rootless-containerd-userns")
    selected_rootless["qualification_report"]["candidate_specific_test_ids"].pop()
    if not validate_record(rootless_missing, validator):
        raise AssertionError("rootless selection with a missing RLS test was accepted")
    print("PASS  accepts rootless selection only with all four candidate-specific qualification tests")
    profile_uid_zero = deepcopy(rootless_complete)
    selected_profile = next(c for c in profile_uid_zero["candidate_assessments"] if c["candidate_id"] == "rootless-containerd-userns")
    selected_profile["configuration"]["rootless_profile"]["daemon_uid"] = 0
    selected_profile["qualification_report"]["rootless_profile"]["daemon_uid"] = 0
    if not validate_record(profile_uid_zero, validator):
        raise AssertionError("rootless candidate with UID zero was accepted")
    profile_mismatch = deepcopy(rootless_complete)
    selected_profile = next(c for c in profile_mismatch["candidate_assessments"] if c["candidate_id"] == "rootless-containerd-userns")
    selected_profile["qualification_report"]["rootless_profile"]["apparmor_profile_sha256"] = "f"*64
    if not validate_record(profile_mismatch, validator):
        raise AssertionError("rootless candidate with a mismatched AppArmor/profile digest was accepted")
    stale_profile = deepcopy(rootless_complete)
    stale_candidate = next(c for c in stale_profile["candidate_assessments"] if c["candidate_id"] == "rootless-containerd-userns")
    stale_candidate["configuration"]["rootless_profile"]["rootlesskit_sha256"] = "e"*64
    stale_candidate["qualification_report"]["rootless_profile"]["rootlesskit_sha256"] = "e"*64
    if not validate_record(stale_profile, validator):
        raise AssertionError("rootless candidate with matching but stale profile content digests was accepted")
    profile_cpu_missing = deepcopy(rootless_complete)
    selected_profile = next(c for c in profile_cpu_missing["candidate_assessments"] if c["candidate_id"] == "rootless-containerd-userns")
    selected_profile["configuration"]["rootless_profile"]["delegated_controllers"] = ["memory", "pids"]
    selected_profile["qualification_report"]["rootless_profile"]["delegated_controllers"] = ["memory", "pids"]
    if not validate_record(profile_cpu_missing, validator):
        raise AssertionError("rootless candidate without CPU delegation was accepted")
    print("PASS  rejects rootless daemon UID zero, profile mismatch and missing CPU delegation")
    print("PASS  rejects rootless selection with a missing candidate-specific test")
    print("PASS  accepts synthetic selection only with candidate-specific complete qualification")
    print("PASS  ADR acceptance leaves implementation and all execution authorizations false")
    print("NOTE  synthetic contract fixtures only; no actual review, host qualification or signature")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
