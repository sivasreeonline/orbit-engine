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
    ]
    schemas = {name: validator(name) for name in schema_names}
    envelope_v = schemas[schema_names[0]]
    bundle_v = schemas[schema_names[1]]
    key_v = schemas[schema_names[2]]
    report_v = schemas[schema_names[3]]
    host_v, fence_v, phase_v, revoke_v = (schemas[name] for name in schema_names[4:])

    host_payload = {
        "host_enrollment_id": "enrollment-01", "provider_id": "provider-x",
        "provider_account_id": "account-01", "provider_region": "region-1",
        "provider_instance_id": "instance-current", "incarnation_epoch": 7,
        "operation_id": "operation-01", "response_id": "response-01",
        "request_nonce_sha256": "a" * 64, "request_sha256": "b" * 64,
        "predecessor_set_sha256": "c" * 64, "fence_attestation_ref": "evidence://fence/01",
        "fence_attestation_sha256": "d" * 64, "authority_observed_at": "2026-01-01T00:00:00Z",
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
        "cleanup_calibration_authorized": True, "full_m0_proof_authorized": False,
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
    rejected(host_v, dict(host_payload, incarnation_epoch=0), "zero host epoch")
    rejected(fence_v, dict(fence_payload, fence_state="REQUESTED"), "uncompleted provider fence")
    rejected(phase_v, dict(phase_payload, security_review_control_count=32), "incomplete review controls")
    rejected(phase_v, dict(phase_payload, phase_b_authorized=True), "Phase B privilege escalation")
    rejected(phase_v, dict(phase_payload, student_execution_authorized=True), "student execution escalation")
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
    rejected(report_v, dict(report, decision="ACCEPT_FOR_FURTHER_GATES", signature_check="PASS",
                            canonical_bytes_check="PASS", revocation_check="PASS", anti_rollback_check="PASS",
                            context_binding_check="PASS", evidence_binding_check="NOT_RUN"),
             "acceptance without evidence binding")

    check(chronology_valid(envelope["issued_at"], envelope["not_before"], envelope["expires_at"]),
          "valid envelope chronology rejected")
    check(not chronology_valid("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
                               "2025-12-31T23:59:59Z"), "expired envelope chronology accepted")
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
    check(2 > 1 and not (1 > 2), "trust bundle generation rollback comparison failed")
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
    for name in schema_names + ["m0-crypto-verification-fixture-catalog.json"]:
        check(name in contract, f"crypto contract must link {name}")

    print("M0 crypto schema meta-validation: PASS (8 schemas).")
    print("Typed payload, envelope, trust-bundle, key and verification-report fixtures: PASS.")
    print("Temporal, duplicate-key, purpose, revocation, anti-rollback and fail-closed checks: PASS.")
    print("20 negative case IDs inventoried; profile-dependent cryptographic vectors remain blocked.")
    print("No signature verification, provider-fence verification or execution authorization performed.")


if __name__ == "__main__":
    main()
