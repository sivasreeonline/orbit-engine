#!/usr/bin/env python3
"""Validate M0 cryptographic contract schemas and fail-closed structural fixtures.

This validator does not perform cryptography, contact a KMS/HSM, verify provider
fencing, retrieve external evidence, or authorize execution.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs" / "schemas"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validator(name: str) -> Draft202012Validator:
    schema = load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def accepted(v: Draft202012Validator, value: dict, label: str) -> None:
    errors = sorted(v.iter_errors(value), key=lambda error: list(error.path))
    check(not errors, f"{label} should validate: " + "; ".join(error.message for error in errors))


def rejected(v: Draft202012Validator, value: dict, label: str) -> None:
    check(not v.is_valid(value), f"{label} unexpectedly validated")


def parse_aware(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    check(parsed.tzinfo is not None, "timestamp must carry an explicit timezone")
    return parsed


def chronology_valid(issued_at: str, not_before: str, expires_at: str) -> bool:
    return parse_aware(issued_at) <= parse_aware(not_before) < parse_aware(expires_at)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        check(key not in result, f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def main() -> None:
    schema_names = [
        "m0-crypto-signed-envelope.schema.json",
        "m0-crypto-trust-bundle.schema.json",
        "m0-crypto-key-metadata.schema.json",
        "m0-crypto-verification-report.schema.json",
        "m0-host-epoch-response-payload.schema.json",
        "m0-provider-fence-attestation-payload.schema.json",
        "m0-phase-a-authorization-payload.schema.json",
        "m0-key-revocation-payload.schema.json",
        "m0-crypto-key-lifecycle-event.schema.json",
    ]
    schemas = {name: validator(name) for name in schema_names}
    envelope_v = schemas[schema_names[0]]
    bundle_v = schemas[schema_names[1]]
    key_v = schemas[schema_names[2]]
    report_v = schemas[schema_names[3]]
    host_v, fence_v, phase_v, revoke_v, key_event_v = (schemas[name] for name in schema_names[4:])

    envelope_schema = load_json(SCHEMAS / schema_names[0])
    payload_schema_map = {
        "host-epoch-response": schema_names[4],
        "provider-fence-attestation": schema_names[5],
        "phase-a-authorization": schema_names[6],
        "trust-bundle": schema_names[1],
        "key-revocation": schema_names[7],
    }
    envelope_rules = {
        rule["if"]["properties"]["message_type"]["const"]: rule["then"]["properties"]["payload"]
        for rule in envelope_schema["allOf"]
        if "message_type" in rule.get("if", {}).get("properties", {})
    }
    for message_type, schema_name in payload_schema_map.items():
        check(envelope_rules.get(message_type) == load_json(SCHEMAS / schema_name),
              f"envelope embedded payload schema drifted for {message_type}")

    host_payload = {
        "host_enrollment_id": "enrollment-01", "provider_id": "provider-x",
        "provider_account_id": "account-01", "provider_region": "region-1",
        "provider_instance_id": "instance-current", "incarnation_epoch": 7,
        "operation_id": "operation-01", "response_id": "response-01",
        "request_nonce_sha256": "a" * 64, "request_sha256": "b" * 64,
        "predecessor_set_sha256": "c" * 64, "fence_attestation_ref": "evidence://fence/01",
        "fence_attestation_object_version": "object-version-01", "fence_attestation_sha256": "d" * 64, "authority_observed_at": "2026-01-01T00:00:00Z",
        "authority_record_version": "record-v1",
    }
    fence_payload = {
        "provider_id": "provider-x", "provider_account_id": "account-01", "provider_region": "region-1",
        "resource_id": "resource-01", "operation_id": "operation-01", "provider_request_id": "request-01",
        "provider_response_id": "response-01", "fencing_method": "provider-native-generation-fence",
        "fence_state": "FENCED", "predecessor_instance_id": "instance-old", "predecessor_epoch": 6,
        "predecessor_set_sha256": "e" * 64, "provider_observed_at": "2026-01-01T00:00:00Z",
        "evidence_ref": "evidence://provider-fence/01", "evidence_sha256": "f" * 64,
    }
    phase_payload = {
        "authorization_id": "authorization-01", "authorization_scope": "M0_CLEANUP_CALIBRATION_ONLY",
        "environment": "test", "host_enrollment_id": "enrollment-01", "provider_id": "provider-x",
        "provider_instance_id": "instance-current", "incarnation_epoch": 7,
        "host_epoch_receipt_ref": "evidence://epoch/01", "host_epoch_receipt_sha256": "1" * 64,
        "host_acceptance_ref": "evidence://acceptance/01", "host_acceptance_sha256": "2" * 64,
        "fence_verification_report_ref": "evidence://fence-report/01", "fence_verification_report_sha256": "3" * 64,
        "host_qualification_record_ref": "evidence://qualification/01", "host_qualification_record_sha256": "4" * 64,
        "security_review_record_ref": "evidence://security-review/01", "security_review_record_sha256": "5" * 64,
        "security_review_control_count": 33, "fence_001_result": "pass",
        "authorization_manifest_sha256": "6" * 64, "max_run_count": 1,
        "not_before": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:05:00Z",
        "cleanup_calibration_authorized": True, "full_m0_proof_authorized": False, "phase_b_authorized": False,
        "host_owner_principal_id": "principal-owner", "evidence_acquirer_principal_id": "principal-acquirer",
        "fence_verifier_principal_id": "principal-fence-verifier",
        "independent_security_reviewer_principal_id": "principal-reviewer",
        "authorization_signer_principal_id": "principal-signer",
        "reviewer_role": "independent-security-reviewer", "independence_attested": True,
        "student_execution_authorized": False, "production_execution_authorized": False,
    }
    revoke_payload = {
        "authority_id": "authority-01", "key_id": "key-01", "key_version": "v2",
        "purpose": "host-epoch", "environment": "test", "revocation_id": "revoke-01",
        "reason_code": "KEY_COMPROMISE", "reason": "Synthetic contract fixture",
        "effective_at": "2026-01-01T00:00:00Z", "trust_bundle_generation": 2,
        "affected_artifact_inventory_ref": "evidence://inventory/01",
        "affected_artifact_inventory_sha256": "7" * 64, "reactivation_permitted": False,
    }

    accepted(host_v, host_payload, "host epoch payload")
    accepted(fence_v, fence_payload, "provider fence payload")
    accepted(phase_v, phase_payload, "Phase A authorization payload shape")
    accepted(revoke_v, revoke_payload, "key revocation payload")
    key_event = {
        "schema_version": "0.1.0", "event_id": "44444444-4444-4444-8444-444444444444",
        "authority_id": "synthetic-authority", "key_id": "synthetic-key", "key_version": "2",
        "purpose": "host-epoch", "environment": "test", "prior_state": "NONE",
        "new_state": "GENERATED", "event_type": "KEY_GENERATED", "trust_bundle_generation": 2,
        "occurred_at": "2026-01-01T00:00:00Z", "actor_principal_id": "key-custodian",
        "reason_code": "INITIAL_CREATION", "evidence_ref": "evidence://key-generation/02",
        "evidence_sha256": "8" * 64, "previous_event_sha256": None,
        "event_sha256": "9" * 64, "reactivation_permitted": False,
    }
    accepted(key_event_v, key_event, "key lifecycle generation event")
    rejected(key_event_v, dict(key_event, new_state="ACTIVE"), "illegal direct key activation")
    rejected(key_event_v, dict(key_event, reactivation_permitted=True), "key lifecycle reactivation")
    activated_event = dict(key_event, prior_state="PENDING", new_state="ACTIVE",
                            event_type="KEY_ACTIVATED", reason_code="INITIAL_CREATION",
                            previous_event_sha256="a" * 64)
    accepted(key_event_v, activated_event, "key activation event")
    revoked_event = dict(key_event, prior_state="ACTIVE", new_state="REVOKED",
                         event_type="KEY_REVOKED", reason_code="KEY_COMPROMISE",
                         previous_event_sha256="b" * 64)
    accepted(key_event_v, revoked_event, "terminal key revocation event")
    rejected(key_event_v, dict(revoked_event, new_state="ACTIVE"), "revoked key reactivation")

    rejected(host_v, dict(host_payload, incarnation_epoch=0), "zero host epoch")
    rejected(fence_v, dict(fence_payload, fence_state="REQUESTED"), "uncompleted provider fence")
    rejected(phase_v, dict(phase_payload, security_review_control_count=32), "incomplete review controls")
    rejected(phase_v, dict(phase_payload, phase_b_authorized=True), "Phase B privilege escalation")
    rejected(phase_v, dict(phase_payload, student_execution_authorized=True), "student execution escalation")
    principal_roles = ["host_owner_principal_id", "evidence_acquirer_principal_id",
                       "fence_verifier_principal_id", "independent_security_reviewer_principal_id",
                       "authorization_signer_principal_id"]
    def principals_separated(payload: dict) -> bool:
        return len({payload[field] for field in principal_roles}) == len(principal_roles)
    check(principals_separated(phase_payload), "distinct authorization principals rejected")
    collided = dict(phase_payload, fence_verifier_principal_id="principal-owner")
    check(not principals_separated(collided), "owner/verifier role collision was accepted")
    rejected(revoke_v, dict(revoke_payload, reactivation_permitted=True), "key reactivation")

    envelope = {
        "schema_version": "0.1.0", "envelope_id": "11111111-1111-4111-8111-111111111111",
        "message_type": "host-epoch-response", "profile_version": "candidate-profile-0",
        "canonicalization": "jcs-rfc8785-candidate", "domain": "ORBIT-M0-HOST-EPOCH-RESPONSE/v1",
        "issuer_id": "synthetic-authority", "key_id": "synthetic-key", "key_version": "1",
        "algorithm": "Ed25519-candidate", "audience": "orbit-m0-host-agent",
        "issued_at": "2026-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:05:00Z", "payload": host_payload,
        "payload_sha256": "a" * 64, "signature_encoding": "base64", "signature": "c3ludGhldGlj",
    }
    accepted(envelope_v, envelope, "typed host epoch envelope")
    rejected(envelope_v, dict(envelope, domain="ORBIT-M0-PHASE-A-AUTHORIZATION/v1"), "domain/message mismatch")
    rejected(envelope_v, dict(envelope, algorithm="RSA-NONE"), "unknown algorithm")
    rejected(envelope_v, dict(envelope, signature="%%%invalid%%%"), "malformed base64 signature")
    rejected(envelope_v, dict(envelope, payload_sha256="not-a-digest"), "invalid payload digest")
    rejected(envelope_v, dict(envelope, message_type="unknown-message"), "unknown message type")
    rejected(envelope_v, dict(envelope, payload=phase_payload), "wrong typed payload for message type")

    bundle = {
        "schema_version": "0.1.0", "bundle_id": "22222222-2222-4222-8222-222222222222",
        "generation": 1, "environment": "test", "root_id": "synthetic-root",
        "root_key_version": "1", "authority_id": "synthetic-authority",
        "purpose_allowlist": ["host-epoch"], "protocol_allowlist": ["orbit-m0/v1"],
        "keys": [{"key_id": "synthetic-key", "key_version": "1", "algorithm": "Ed25519-candidate",
                  "public_key_format": "raw-ed25519-candidate", "public_key": "PUBLIC-KEY-PLACEHOLDER",
                  "purpose": "host-epoch", "status": "ACTIVE", "valid_from": "2026-01-01T00:00:00Z",
                  "valid_until": "2027-01-01T00:00:00Z", "public_key_fingerprint_sha256": "b" * 64}],
        "revocations": [], "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2026-02-01T00:00:00Z",
        "previous_bundle_sha256": None, "bundle_sha256": "c" * 64,
        "signature_envelope_ref": "evidence://envelope/01", "signature_envelope_sha256": "d" * 64,
        "anti_rollback_witness_ref": "evidence://witness/01", "anti_rollback_witness_sha256": "e" * 64,
    }
    accepted(bundle_v, bundle, "trust bundle")
    trust_bundle_envelope = dict(envelope, message_type="trust-bundle",
                                 domain="ORBIT-M0-TRUST-BUNDLE/v1", payload=bundle)
    accepted(envelope_v, trust_bundle_envelope, "typed trust bundle envelope")
    rejected(envelope_v, dict(trust_bundle_envelope,
                              payload=dict(bundle, anti_rollback_witness_ref="")),
             "trust bundle envelope without anti-rollback witness")
    rejected(bundle_v, dict(bundle, generation=2), "generation two without predecessor digest")
    rejected(bundle_v, dict(bundle, anti_rollback_witness_ref="", anti_rollback_witness_sha256=""),
             "missing anti-rollback witness")

    key = {
        "schema_version": "0.1.0", "authority_id": "synthetic-authority", "key_id": "synthetic-key",
        "key_version": "1", "algorithm": "Ed25519-candidate", "purpose": "host-epoch",
        "environment": "test", "state": "ACTIVE", "public_key_fingerprint_sha256": "f" * 64,
        "created_at": "2026-01-01T00:00:00Z", "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z", "trust_bundle_generation": 1,
        "custody_reference": "custody://synthetic-key", "private_material_present": False,
    }
    accepted(key_v, key, "public key metadata")
    rejected(key_v, dict(key, private_material_present=True), "private key material metadata")
    revoked_key = dict(key, state="REVOKED", revoked_at="2026-01-01T00:00:00Z",
                       revocation_reason="compromised")
    accepted(key_v, revoked_key, "revoked key metadata")

    report = {
        "schema_version": "0.1.0", "report_id": "33333333-3333-4333-8333-333333333333",
        "artifact_type": "host-epoch-response", "artifact_ref": "evidence://artifact/01",
        "artifact_version": "v1", "artifact_sha256": "1" * 64,
        "decision": "AUDIT_ONLY", "reason_codes": ["STRUCTURE_ONLY_FIXTURE"],
        "verifier_principal_id": "synthetic-verifier", "verifier_build_digest": "2" * 64,
        "policy_version": "synthetic-policy-v1", "trust_bundle_generation": 1,
        "trust_bundle_sha256": "3" * 64, "key_id": "synthetic-key", "key_version": "1",
        "algorithm": "Ed25519-candidate", "profile_version": "candidate-profile-0",
        "canonicalization": "jcs-rfc8785-candidate", "signature_check": "NOT_RUN",
        "canonical_bytes_check": "NOT_RUN", "revocation_check": "UNKNOWN", "anti_rollback_check": "UNKNOWN",
        "context_binding_check": "NOT_RUN", "evidence_binding_check": "NOT_RUN",
        "trusted_time": {"source_id": "synthetic-clock", "observed_at": "2026-01-01T00:00:00Z",
                         "uncertainty_ms": 0, "evidence_ref": "clock://synthetic"},
        "verified_at": "2026-01-01T00:00:01Z", "report_sha256": "4" * 64,
    }
    accepted(report_v, report, "audit-only verification report")
    rejected(report_v, dict(report, decision="ACCEPT_FOR_FURTHER_GATES", signature_check="FAIL"),
             "acceptance with failed signature")

    signature_valid_fence_unknown = dict(
        report, signature_check="PASS", canonical_bytes_check="PASS",
        revocation_check="PASS", anti_rollback_check="PASS", context_binding_check="PASS",
        evidence_binding_check="NOT_RUN"
    )
    accepted(report_v, signature_valid_fence_unknown,
             "valid signature with provider fence evidence not independently verified")
    check(signature_valid_fence_unknown["decision"] == "AUDIT_ONLY",
          "valid signature alone must not satisfy provider fencing")
    rejected(report_v, dict(report, decision="ACCEPT_FOR_FURTHER_GATES", signature_check="PASS",
                            canonical_bytes_check="PASS", revocation_check="PASS", anti_rollback_check="PASS",
                            context_binding_check="PASS", evidence_binding_check="NOT_RUN"),
             "acceptance without evidence binding")

    check(chronology_valid(envelope["issued_at"], envelope["not_before"], envelope["expires_at"]),
          "valid envelope chronology rejected")
    check(not chronology_valid("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
                               "2025-12-31T23:59:59Z"), "expired envelope chronology accepted")
    check(chronology_valid(phase_payload["not_before"], phase_payload["not_before"],
                           phase_payload["expires_at"]),
          "cleanup-calibration authorization validity window is invalid")
    check(chronology_valid(bundle["issued_at"], bundle["issued_at"], bundle["expires_at"]),
          "trust bundle expiry must follow issuance")
    check(chronology_valid(key["created_at"], key["valid_from"], key["valid_until"]),
          "key validity window is invalid")
    try:
        json.loads('{"envelope_id":"first","envelope_id":"second"}', object_pairs_hook=reject_duplicate_keys)
        raise AssertionError("duplicate JSON object keys unexpectedly parsed")
    except AssertionError as error:
        if "unexpectedly parsed" in str(error):
            raise

    def key_admissible(record: dict, purpose: str, environment: str) -> bool:
        return (record.get("state") == "ACTIVE" and record.get("purpose") == purpose
                and record.get("environment") == environment
                and record.get("private_material_present") is False)

    check(not key_admissible(key, "provider-fence", "test"), "purpose-mismatched key admitted")
    check(not key_admissible(revoked_key, "host-epoch", "test"), "revoked key admitted")
    def valid_key_transition(prior: str, candidate: str, event_type: str) -> bool:
        allowed = {
            ("NONE", "GENERATED", "KEY_GENERATED"),
            ("GENERATED", "PENDING", "KEY_SUBMITTED_FOR_ACTIVATION"),
            ("PENDING", "ACTIVE", "KEY_ACTIVATED"),
            ("ACTIVE", "DEPRECATED_VERIFY_ONLY", "KEY_DEPRECATED"),
            ("GENERATED", "REVOKED", "KEY_REVOKED"),
            ("PENDING", "REVOKED", "KEY_REVOKED"),
            ("ACTIVE", "REVOKED", "KEY_REVOKED"),
            ("DEPRECATED_VERIFY_ONLY", "REVOKED", "KEY_REVOKED"),
            ("REVOKED", "DESTROYED", "KEY_DESTROYED"),
            ("DEPRECATED_VERIFY_ONLY", "DESTROYED", "KEY_DESTROYED"),
        }
        return (prior, candidate, event_type) in allowed
    check(valid_key_transition("PENDING", "ACTIVE", "KEY_ACTIVATED"),
          "valid key activation transition rejected")
    check(not valid_key_transition("REVOKED", "ACTIVE", "KEY_ACTIVATED"),
          "revoked key reactivation accepted")
    check(not valid_key_transition("ACTIVE", "GENERATED", "KEY_GENERATED"),
          "key lifecycle rollback accepted")
    lifecycle_chain = [
        ("NONE","GENERATED","KEY_GENERATED"),
        ("GENERATED","PENDING","KEY_SUBMITTED_FOR_ACTIVATION"),
        ("PENDING","ACTIVE","KEY_ACTIVATED"),
        ("ACTIVE","DEPRECATED_VERIFY_ONLY","KEY_DEPRECATED"),
        ("DEPRECATED_VERIFY_ONLY","REVOKED","KEY_REVOKED"),
        ("REVOKED","DESTROYED","KEY_DESTROYED"),
    ]
    state="NONE"
    for prior,candidate,event_type in lifecycle_chain:
        check(prior==state and valid_key_transition(prior,candidate,event_type),
              "valid append-only key lifecycle chain rejected")
        state=candidate
    check(state=="DESTROYED", "key lifecycle chain did not reach terminal destruction")
    check(not valid_key_transition("REVOKED","ACTIVE","KEY_ACTIVATED"),
          "terminal revocation was reversible")
    def rotation_pair_valid(old_key: dict, new_key: dict) -> bool:
        return (old_key["key_id"]==new_key["key_id"]
                and old_key["key_version"]!=new_key["key_version"]
                and old_key["purpose"]==new_key["purpose"]
                and old_key["environment"]==new_key["environment"]
                and old_key["state"]=="DEPRECATED_VERIFY_ONLY"
                and new_key["state"]=="ACTIVE"
                and old_key["public_key_fingerprint_sha256"]!=new_key["public_key_fingerprint_sha256"])
    old_key=dict(key,key_version="1",state="DEPRECATED_VERIFY_ONLY")
    new_key=dict(key,key_version="2",state="ACTIVE",public_key_fingerprint_sha256="9"*64)
    check(rotation_pair_valid(old_key,new_key), "valid overlapping key rotation rejected")
    check(not rotation_pair_valid(old_key,dict(new_key,purpose="provider-fence")),
          "cross-purpose key rotation accepted")
    check(not rotation_pair_valid(old_key,dict(new_key,environment="production")),
          "cross-environment key rotation accepted")


    def trust_bundle_successor_valid(previous: dict, candidate: dict) -> bool:
        return (candidate["generation"] == previous["generation"] + 1
                and candidate["previous_bundle_sha256"] == previous["bundle_sha256"]
                and candidate["environment"] == previous["environment"]
                and candidate["authority_id"] == previous["authority_id"]
                and candidate["root_id"] == previous["root_id"])
    successor = dict(bundle, generation=2, previous_bundle_sha256=bundle["bundle_sha256"],
                     bundle_id="55555555-5555-4555-8555-555555555555",
                     bundle_sha256="a" * 64)
    check(trust_bundle_successor_valid(bundle, successor), "valid trust bundle successor rejected")
    check(not trust_bundle_successor_valid(bundle, dict(successor, generation=3)),
          "trust bundle generation skip accepted")
    check(not trust_bundle_successor_valid(bundle, dict(successor, previous_bundle_sha256="f" * 64)),
          "trust bundle predecessor digest mismatch accepted")
    check(not trust_bundle_successor_valid(bundle, dict(successor, environment="production")),
          "cross-environment trust bundle transition accepted")

    def revocation_matches_bundle(statement: dict, bundle_value: dict) -> bool:
        matches = [item for item in bundle_value["keys"]
                   if item["key_id"] == statement["key_id"]
                   and item["key_version"] == statement["key_version"]]
        return len(matches) == 1 and matches[0]["status"] == "REVOKED"
    revoked_bundle = dict(bundle, keys=[dict(bundle["keys"][0], status="REVOKED",
                                             revoked_at="2026-01-01T00:00:00Z")],
                          revocations=[{"key_id":"synthetic-key","key_version":"1",
                                        "effective_at":"2026-01-01T00:00:00Z","reason_code":"KEY_COMPROMISE",
                                        "revocation_statement_ref":"evidence://revocation/01",
                                        "revocation_statement_sha256":"b"*64}])
    revoked_bundle["keys"][0]["revocation_reason"] = "synthetic compromise fixture"
    check(revocation_matches_bundle(revoked_bundle["revocations"][0], revoked_bundle),
          "matching bundle revocation statement rejected")
    accepted(bundle_v, revoked_bundle, "revoked key and matching trust-bundle revocation")
    check(not revocation_matches_bundle(revoked_bundle["revocations"][0],
                                        dict(revoked_bundle, keys=[dict(revoked_bundle["keys"][0],
                                                                        status="ACTIVE")])),
          "revocation statement with active key accepted")
    def bundle_identity_sets_valid(bundle_value: dict) -> bool:
        key_ids=[(item["key_id"],item["key_version"]) for item in bundle_value["keys"]]
        revocation_ids=[(item["key_id"],item["key_version"]) for item in bundle_value["revocations"]]
        return len(key_ids)==len(set(key_ids)) and len(revocation_ids)==len(set(revocation_ids))
    check(bundle_identity_sets_valid(revoked_bundle), "valid bundle identity sets rejected")
    check(not bundle_identity_sets_valid(dict(revoked_bundle,
          keys=revoked_bundle["keys"]+[dict(revoked_bundle["keys"][0]) ])),
          "duplicate key ID/version accepted in trust bundle")
    check(not bundle_identity_sets_valid(dict(revoked_bundle,
          revocations=revoked_bundle["revocations"]+[dict(revoked_bundle["revocations"][0])])),
          "duplicate revocation identity accepted in trust bundle")
    def bundle_revocation_consistency_valid(bundle_value: dict) -> bool:
        if not bundle_identity_sets_valid(bundle_value):
            return False
        key_states={(item["key_id"],item["key_version"]):item["status"] for item in bundle_value["keys"]}
        revoked_keys={identity for identity,state in key_states.items() if state=="REVOKED"}
        revocation_ids={(item["key_id"],item["key_version"]) for item in bundle_value["revocations"]}
        return revoked_keys == revocation_ids and all(
            key_states.get(identity)=="REVOKED" for identity in revocation_ids)
    check(bundle_revocation_consistency_valid(revoked_bundle),
          "matching key and revocation inventory rejected")
    check(not bundle_revocation_consistency_valid(dict(revoked_bundle,revocations=[])),
          "revoked key omitted from trust-bundle revocation inventory")
    check(not bundle_revocation_consistency_valid(dict(revoked_bundle,
          keys=[dict(revoked_bundle["keys"][0],status="ACTIVE")])),
          "active key paired with revocation inventory")



    def authorization_ledger_binding_valid(payload: dict, receipt: dict, acceptance: dict,
                                            review: dict, qualification: dict, key_record: dict,
                                            ledger_record: dict, signed_envelope: dict) -> bool:
        return (payload["host_enrollment_id"] == receipt["host_enrollment_id"]
                and payload["provider_instance_id"] == receipt["provider_instance_id"]
                and payload["incarnation_epoch"] == receipt["epoch"] == acceptance["accepted_epoch"]
                and payload["host_epoch_receipt_sha256"] == receipt["receipt_sha256"]
                and payload["host_acceptance_sha256"] == acceptance["acceptance_sha256"]
                and payload["security_review_record_sha256"] == review["digest"]
                and review["control_count"] == 33 and review["fence_001"] == "pass"
                and payload["host_qualification_record_sha256"] == qualification["digest"]
                and key_record["key_id"] == "synthetic-key"
                and key_record["key_version"] == ledger_record["signer_key_version"]
                and signed_envelope["issuer_id"] == ledger_record["signer_id"] == key_record["authority_id"]
                and signed_envelope["key_id"] == key_record["key_id"]
                and signed_envelope["key_version"] == ledger_record["signer_key_version"]
                and signed_envelope["algorithm"] == ledger_record["signature_algorithm"]
                and payload["authorization_manifest_sha256"] == ledger_record["manifest_sha256"]
                and key_admissible(key_record, "phase-a-authorization", "test"))
    receipt={"host_enrollment_id":"enrollment-01","provider_instance_id":"instance-current",
             "epoch":7,"receipt_sha256":"1"*64}
    acceptance={"accepted_epoch":7,"acceptance_sha256":"2"*64}
    review={"digest":"5"*64,"control_count":33,"fence_001":"pass"}
    qualification={"digest":"4"*64}
    authorization_key=dict(key,purpose="phase-a-authorization")
    ledger_record={"signer_id":"synthetic-authority","signer_key_version":"1",
                   "signature_algorithm":"Ed25519-candidate","manifest_sha256":"6"*64}
    phase_envelope=dict(envelope,message_type="phase-a-authorization",
                        domain="ORBIT-M0-PHASE-A-AUTHORIZATION/v1",
                        issuer_id="synthetic-authority",payload=phase_payload)
    check(authorization_ledger_binding_valid(phase_payload,receipt,acceptance,review,qualification,
                                              authorization_key,ledger_record,phase_envelope),
          "valid authorization-to-ledger bindings rejected")
    check(not authorization_ledger_binding_valid(phase_payload,dict(receipt,epoch=6),acceptance,review,qualification,authorization_key,ledger_record,phase_envelope),
          "authorization with stale host epoch accepted")
    check(not authorization_ledger_binding_valid(phase_payload,receipt,acceptance,dict(review,control_count=32),qualification,authorization_key,ledger_record,phase_envelope),
          "authorization with incomplete security review accepted")
    check(not authorization_ledger_binding_valid(phase_payload,receipt,acceptance,review,qualification,
                                                  dict(authorization_key,state="REVOKED"),ledger_record,phase_envelope),
          "authorization signed by revoked key accepted")

    def run_claim_budget_valid(maximum: int, claim_statuses: list[str], consumed: int) -> bool:
        terminal_claims={"CLAIMED","COMPLETED","FAILED","QUARANTINED"}
        return (all(status in terminal_claims for status in claim_statuses)
                and consumed == len(claim_statuses) and 0 <= consumed <= maximum)
    check(run_claim_budget_valid(3,["COMPLETED","FAILED"],2),
          "valid consumed run budget rejected")
    check(not run_claim_budget_valid(3,["COMPLETED","FAILED"],1),
          "failed run claim was silently refunded")
    check(not run_claim_budget_valid(1,["COMPLETED","QUARANTINED"],2),
          "run claim budget over-consumption accepted")
    def ledger_transition_valid(prior: str, candidate: str) -> bool:
        if prior in {"REVOKED","EXPIRED","QUARANTINED"}:
            return False
        allowed={
            "PREPARED":{"ISSUED","REVOKED","EXPIRED","QUARANTINED"},
            "ISSUED":{"ACCEPTED","REVOKED","EXPIRED","QUARANTINED"},
            "ACCEPTED":{"CONSUMED","REVOKED","EXPIRED","QUARANTINED"},
            "CONSUMED":{"CONSUMED","REVOKED","EXPIRED","QUARANTINED"},
        }
        return candidate in allowed.get(prior,set())
    check(ledger_transition_valid("ISSUED","ACCEPTED"), "valid authorization acceptance transition rejected")
    check(ledger_transition_valid("ACCEPTED","CONSUMED"), "valid run consumption transition rejected")
    check(not ledger_transition_valid("REVOKED","ACCEPTED"), "revoked authorization became accepted")
    check(not ledger_transition_valid("EXPIRED","ISSUED"), "expired authorization was reissued")
    check(not ledger_transition_valid("QUARANTINED","ACCEPTED"), "quarantined authorization was admitted")
    def authorization_event_chain_valid(events: list[dict]) -> bool:
        if not events:
            return False
        request_ids=set()
        previous_digest=None
        previous_state=None
        expected_sequence=1
        for event in events:
            if event["sequence_no"]!=expected_sequence or event["previous_event_digest"]!=previous_digest:
                return False
            if event["request_id"] in request_ids:
                return False
            if previous_state is not None and event["prior_state"]!=previous_state:
                return False
            if event["new_state"] not in {"PREPARED","ISSUED","ACCEPTED","CONSUMED","REVOKED","EXPIRED","QUARANTINED"}:
                return False
            request_ids.add(event["request_id"])
            previous_digest=event["event_digest"]
            previous_state=event["new_state"]
            expected_sequence+=1
        return True
    event_chain=[
        {"sequence_no":1,"request_id":"req-1","prior_state":None,"new_state":"PREPARED",
         "previous_event_digest":None,"event_digest":"a"*64},
        {"sequence_no":2,"request_id":"req-2","prior_state":"PREPARED","new_state":"ISSUED",
         "previous_event_digest":"a"*64,"event_digest":"b"*64},
        {"sequence_no":3,"request_id":"req-3","prior_state":"ISSUED","new_state":"ACCEPTED",
         "previous_event_digest":"b"*64,"event_digest":"c"*64},
    ]
    check(authorization_event_chain_valid(event_chain), "valid append-only authorization event chain rejected")
    check(not authorization_event_chain_valid([event_chain[0],dict(event_chain[1],previous_event_digest="f"*64),
                                               event_chain[2]]),
          "tampered authorization event digest chain accepted")
    check(not authorization_event_chain_valid([event_chain[0],dict(event_chain[1],request_id="req-1"),
                                               event_chain[2]]),
          "duplicate authorization event request ID accepted")
    check(not authorization_event_chain_valid([event_chain[0],dict(event_chain[1],sequence_no=3),
                                               event_chain[2]]),
          "authorization event sequence gap accepted")

    def run_claim_idempotency_valid(existing: dict, candidate: dict) -> bool:
        return (existing["run_id"] != candidate["run_id"]
                or existing["request_digest"] == candidate["request_digest"])
    original_claim={"run_id":"run-01","request_digest":"d"*64}
    check(run_claim_idempotency_valid(original_claim,dict(original_claim)),
          "same run ID and request digest should be idempotent")
    check(not run_claim_idempotency_valid(original_claim,
                                           {"run_id":"run-01","request_digest":"e"*64}),
          "same run ID with changed request digest did not conflict")



    def restored_ledger_fresh(external_generation: int, restored_generation: int,
                              external_digest: str, restored_digest: str) -> bool:
        return (restored_generation == external_generation
                and restored_digest == external_digest)
    check(restored_ledger_fresh(12,12,"c"*64,"c"*64), "matching external checkpoint rejected")
    check(not restored_ledger_fresh(12,11,"c"*64,"b"*64),
          "restored stale ledger passed external anti-rollback checkpoint")

    def trust_generation_advances(previous: int, candidate: int) -> bool:
        return candidate > previous
    check(trust_generation_advances(1, 2), "valid trust bundle generation advance rejected")
    check(not trust_generation_advances(2, 1), "trust bundle generation rollback accepted")
    check(host_payload["fence_attestation_ref"] != "evidence://fence/other"
          or host_payload["fence_attestation_sha256"] == "d" * 64,
          "evidence reference/digest pair is inconsistent")
    check(not (key["environment"] != "test"), "cross-environment key fixture is not test scoped")
    check(envelope["domain"] == "ORBIT-M0-HOST-EPOCH-RESPONSE/v1",
          "cross-protocol signature reuse must fail domain binding")
    replay_claims = [("nonce-a", 7), ("nonce-a", 7)]
    check(len(set(replay_claims)) != len(replay_claims), "replayed nonce/epoch fixture was not detected")
    check(report["revocation_check"] != "PASS" and report["decision"] != "ACCEPT_FOR_FURTHER_GATES",
          "unknown revocation freshness must fail closed")
    check(report["decision"] == "AUDIT_ONLY" and report["evidence_binding_check"] == "NOT_RUN",
          "provider fence without independent evidence verification must remain audit-only")

    catalog = load_json(SCHEMAS / "m0-crypto-verification-fixture-catalog.json")
    check(catalog["status"] == "contract-fixtures-only", "fixture catalog must remain structural only")
    check(catalog["cryptographic_profile_selected"] is False, "profile must remain unselected")
    lifecycle_cases = catalog.get("key_lifecycle_transition_cases", [])
    check(catalog.get("required_key_lifecycle_transition_case_count") == 10
          and len(lifecycle_cases) == 10, "key lifecycle transition matrix must contain ten cases")
    check(len({case["id"] for case in lifecycle_cases}) == 10,
          "key lifecycle transition case IDs must be unique")
    expected_lifecycle = {
        ("NONE", "GENERATED", "KEY_GENERATED"): "ACCEPT",
        ("GENERATED", "PENDING", "KEY_SUBMITTED_FOR_ACTIVATION"): "ACCEPT",
        ("PENDING", "ACTIVE", "KEY_ACTIVATED"): "ACCEPT",
        ("ACTIVE", "DEPRECATED_VERIFY_ONLY", "KEY_DEPRECATED"): "ACCEPT",
        ("ACTIVE", "REVOKED", "KEY_REVOKED"): "ACCEPT",
        ("DEPRECATED_VERIFY_ONLY", "REVOKED", "KEY_REVOKED"): "ACCEPT",
        ("REVOKED", "DESTROYED", "KEY_DESTROYED"): "ACCEPT",
        ("REVOKED", "ACTIVE", "KEY_ACTIVATED"): "REJECT",
        ("ACTIVE", "GENERATED", "KEY_GENERATED"): "REJECT",
        ("PENDING", "DESTROYED", "KEY_DESTROYED"): "REJECT",
    }
    actual_lifecycle = {}
    for case in lifecycle_cases:
        transition = case["transition"].split(" -> ")
        matching = [key_tuple for key_tuple in expected_lifecycle if
                    key_tuple[0] == transition[0] and key_tuple[1] == transition[1]]
        check(len(matching) == 1, f"unknown key lifecycle fixture transition {case['transition']}")
        actual_lifecycle[matching[0]] = case["expected"]
    check(actual_lifecycle == expected_lifecycle,
          "catalogued key lifecycle transition cases drifted from executable transition matrix")
    check(all((case["expected"] == "ACCEPT") == valid_key_transition(*next(
        item for item in expected_lifecycle if item[0] == case["transition"].split(" -> ")[0]
        and item[1] == case["transition"].split(" -> ")[1])) for case in lifecycle_cases),
        "key lifecycle catalog expectation differs from transition evaluator")

    check(catalog["required_positive_case_count"] == len(catalog["positive_cases"]) == 9,
          "positive fixture inventory must contain exactly nine cases")
    positive_ids = [item["id"] for item in catalog["positive_cases"]]
    check(len(set(positive_ids)) == 9, "positive fixture IDs must be unique")
    check(all(item["cryptography_executed"] is False for item in catalog["positive_cases"]),
          "positive structural fixtures must not claim cryptography")
    check(catalog["required_negative_case_count"] == len(catalog["negative_cases"]) == 20,
          "negative case inventory must contain exactly 20 unique cases")
    check(len(set(catalog["negative_cases"])) == 20, "negative case IDs must be unique")
    coverage = catalog.get("negative_case_coverage", [])
    check(len(coverage) == 20, "every negative case must have an explicit execution disposition")
    check({item["id"] for item in coverage} == set(catalog["negative_cases"]),
          "negative fixture coverage must exactly match the canonical inventory")
    check(all(item["cryptography_executed"] is False for item in coverage),
          "structural fixture catalog must not claim cryptography")
    check(sum(item["outcome"] == "BLOCKED_PROFILE_NOT_SELECTED" for item in coverage) == 1,
          "only profile-dependent canonical-byte fixture should remain blocked")
    check(catalog["known_answer_vectors"]["status"] == "blocked-pending-profile-selection",
          "known-answer vectors must remain blocked pending profile selection")
    check(catalog["safety_invariants"] == {
        "private_key_material_in_fixtures": False, "production_keys_in_fixtures": False,
        "signature_verification_claimed": False, "execution_authorization": False,
    }, "fixture safety invariants changed")

    contract = (ROOT / "docs/specifications/m0-cryptographic-trust-and-key-lifecycle.md").read_text(encoding="utf-8")
    ledger = (ROOT / "docs/specifications/m0-authorization-ledger-data-model.md").read_text(encoding="utf-8")
    for ledger_term in ["host_epoch_receipts", "host_epoch_acceptances", "phase_a_authorizations",
                        "max_total_runs", "signer_key_version"]:
        check(ledger_term in ledger, f"authorization payload/ledger alignment missing {ledger_term}")
    authorization_schema = load_json(SCHEMAS / "m0-cleanup-calibration-authorization.schema.json")
    check("host_incarnation_epoch" in authorization_schema["properties"]["host"]["required"],
          "cleanup-calibration authorization must bind the host incarnation epoch")
    check("host_qualification_record_ref" in authorization_schema["properties"]["host"]["required"],
          "cleanup-calibration authorization must bind host qualification evidence")
    check("independent_security_review_record_ref" in authorization_schema["properties"]["signoff"]["required"],
          "cleanup-calibration authorization must bind independent security review")

    for name in schema_names + ["m0-crypto-verification-fixture-catalog.json"]:
        check(name in contract, f"crypto contract must link {name}")

    print("M0 crypto schema meta-validation: PASS (9 schemas).")
    print("Typed payload, envelope, trust-bundle, key and verification-report fixtures: PASS.")
    print("Temporal, duplicate-key, purpose, revocation, anti-rollback, key lifecycle and ledger binding checks: PASS.")
    print("9 positive and 20 negative fixture dispositions verified; profile-dependent canonical-byte vector remains blocked.")
    print("No signature verification, provider-fence verification or execution authorization performed.")


if __name__ == "__main__":
    main()
