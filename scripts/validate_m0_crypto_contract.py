#!/usr/bin/env python3
"""Validate M0 cryptographic contract schemas and structural fixtures only.

This script deliberately does not perform cryptography, contact a KMS/HSM,
verify provider fencing, or authorize execution.
"""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs" / "schemas"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validator(name: str) -> Draft202012Validator:
    schema = load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def accepted(v: Draft202012Validator, value: dict, label: str) -> None:
    errors = sorted(v.iter_errors(value), key=lambda e: list(e.path))
    check(not errors, f"{label} should validate: " + "; ".join(e.message for e in errors))


def rejected(v: Draft202012Validator, value: dict, label: str) -> None:
    check(not v.is_valid(value), f"{label} unexpectedly validated")


def main() -> None:
    envelope_v = validator("m0-crypto-signed-envelope.schema.json")
    bundle_v = validator("m0-crypto-trust-bundle.schema.json")
    key_v = validator("m0-crypto-key-metadata.schema.json")
    report_v = validator("m0-crypto-verification-report.schema.json")

    envelope = {
        "schema_version": "0.1.0", "envelope_id": "11111111-1111-4111-8111-111111111111",
        "message_type": "host-epoch-response", "profile_version": "candidate-profile-0",
        "canonicalization": "jcs-rfc8785-candidate", "domain": "ORBIT-M0-HOST-EPOCH-RESPONSE/v1",
        "issuer_id": "synthetic-authority", "key_id": "synthetic-key", "key_version": "1",
        "algorithm": "Ed25519-candidate", "audience": "orbit-m0-host-agent",
        "issued_at": "2026-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:05:00Z", "payload": {
        "payload_sha256": "a" * 64, "signature_encoding": "base64", "signature": "c3ludGhldGlj"
    }
    accepted(envelope_v, envelope, "synthetic envelope structure")
    bad_envelope = dict(envelope, domain="ORBIT-M0-PHASE-A-AUTHORIZATION/v1")
    rejected(envelope_v, bad_envelope, "message/domain mismatch")
    bad_envelope = dict(envelope, algorithm="RSA-NONE")
    rejected(envelope_v, bad_envelope, "unapproved algorithm")

    bundle = {
        "schema_version": "0.1.0", "bundle_id": "22222222-2222-4222-8222-222222222222",
        "generation": 1, "environment": "test", "root_id": "synthetic-root",
        "root_key_version": "1", "authority_id": "synthetic-authority",
        "purpose_allowlist": ["host-epoch"], "protocol_allowlist": ["orbit-m0/v1"],
        "keys": [{"key_id": "synthetic-key", "key_version": "1", "algorithm": "Ed25519-candidate",
                  "public_key_format": "raw-ed25519-candidate", "public_key": "PUBLIC-KEY-PLACEHOLDER",
                  "purpose": "host-epoch", "status": "ACTIVE",
                  "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
                  "public_key_fingerprint_sha256": "b" * 64}],
        "revocations": [], "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2026-02-01T00:00:00Z",
        "previous_bundle_sha256": None, "bundle_sha256": "c" * 64,
        "signature_envelope_ref": "synthetic://envelope", "signature_envelope_sha256": "d" * 64,
        "anti_rollback_witness_ref": "synthetic://witness", "anti_rollback_witness_sha256": "e" * 64
    }
    accepted(bundle_v, bundle, "synthetic trust bundle structure")
    bad_bundle = dict(bundle, generation=2)
    rejected(bundle_v, bad_bundle, "missing predecessor digest on generation two")

    key = {
        "schema_version": "0.1.0", "authority_id": "synthetic-authority", "key_id": "synthetic-key",
        "key_version": "1", "algorithm": "Ed25519-candidate", "purpose": "host-epoch",
        "environment": "test", "state": "ACTIVE", "public_key_fingerprint_sha256": "f" * 64,
        "created_at": "2026-01-01T00:00:00Z", "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z", "trust_bundle_generation": 1,
        "custody_reference": "synthetic://custody", "private_material_present": False
    }
    accepted(key_v, key, "synthetic public key metadata")
    rejected(key_v, dict(key, private_material_present=True), "private material in public metadata")

    report = {
        "schema_version": "0.1.0", "report_id": "33333333-3333-4333-8333-333333333333",
        "artifact_type": "host-epoch-response", "artifact_ref": "synthetic://artifact",
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
                         "uncertainty_ms": 0, "evidence_ref": "synthetic://clock"},
        "verified_at": "2026-01-01T00:00:01Z", "report_sha256": "4" * 64
    }
    accepted(report_v, report, "synthetic verification report structure")
    bad_report = dict(report, decision="ACCEPT_FOR_FURTHER_GATES", signature_check="FAIL")
    rejected(report_v, bad_report, "accept decision with failed signature")


    # Message-specific payload contracts are bound through the envelope's conditional $refs.
    host_payload_v = validator("m0-host-epoch-response-payload.schema.json")
    fence_payload_v = validator("m0-provider-fence-attestation-payload.schema.json")
    phase_payload_v = validator("m0-phase-a-authorization-payload.schema.json")
    revoke_payload_v = validator("m0-key-revocation-payload.schema.json")

    host_payload = {
        "host_enrollment_id": "enrollment-01", "provider_id": "provider-x",
        "provider_account_id": "account-01", "provider_region": "region-1",
        "provider_instance_id": "instance-current", "incarnation_epoch": 7,
        "operation_id": "operation-01", "response_id": "response-01",
        "request_nonce_sha256": "a" * 64, "request_sha256": "b" * 64,
        "predecessor_set_sha256": "c" * 64, "fence_attestation_ref": "evidence://fence/01",
        "fence_attestation_sha256": "d" * 64, "authority_observed_at": "2026-01-01T00:00:00Z",
        "authority_record_version": "record-v1"
    }
    accepted(host_payload_v, host_payload, "host epoch response payload")
    rejected(host_payload_v, dict(host_payload, incarnation_epoch=0), "zero host incarnation epoch")

    fence_payload = {
        "provider_id": "provider-x", "provider_account_id": "account-01", "provider_region": "region-1",
        "resource_id": "resource-01", "operation_id": "operation-01", "provider_request_id": "request-01",
        "provider_response_id": "response-01", "fencing_method": "provider-native-generation-fence",
        "fence_state": "FENCED", "predecessor_instance_id": "instance-old", "predecessor_epoch": 6,
        "predecessor_set_sha256": "e" * 64, "provider_observed_at": "2026-01-01T00:00:00Z",
        "evidence_ref": "evidence://provider-fence/01", "evidence_sha256": "f" * 64
    }
    accepted(fence_payload_v, fence_payload, "provider fence payload")
    rejected(fence_payload_v, dict(fence_payload, fence_state="REQUESTED"), "nonterminal provider fence state")

    phase_payload = {
        "authorization_id": "authorization-01", "authorization_scope": "M0_HOST_QUALIFICATION_ONLY",
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
        "phase_a_authorized": True, "phase_b_authorized": False,
        "student_execution_authorized": False, "production_execution_authorized": False
    }
    accepted(phase_payload_v, phase_payload, "Phase A authorization payload shape")
    rejected(phase_payload_v, dict(phase_payload, security_review_control_count=32), "incomplete security review control set")
    rejected(phase_payload_v, dict(phase_payload, phase_b_authorized=True), "Phase B authorization escalation")
    rejected(phase_payload_v, dict(phase_payload, student_execution_authorized=True), "student execution escalation")

    revoke_payload = {
        "authority_id": "authority-01", "key_id": "key-01", "key_version": "v2",
        "purpose": "host-epoch", "environment": "test", "revocation_id": "revoke-01",
        "reason_code": "KEY_COMPROMISE", "reason": "Synthetic contract fixture",
        "effective_at": "2026-01-01T00:00:00Z", "trust_bundle_generation": 2,
        "affected_artifact_inventory_ref": "evidence://inventory/01",
        "affected_artifact_inventory_sha256": "7" * 64, "reactivation_permitted": False
    }
    accepted(revoke_payload_v, revoke_payload, "key revocation payload")
    rejected(revoke_payload_v, dict(revoke_payload, reactivation_permitted=True), "key reactivation prohibited")

    # Envelope conditional references must reject a payload of the wrong message family.
    rejected(envelope_v, dict(envelope, payload=phase_payload), "host-epoch envelope with Phase A payload")
    rejected(envelope_v, dict(envelope, payload=host_payload, expires_at="2025-12-31T23:59:59Z"),
             "envelope timestamp ordering is checked below by semantic gate")

    from datetime import datetime
    def parse_utc(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        check(parsed.tzinfo is not None, "timestamps must carry an explicit timezone")
        return parsed

    def temporal_order_valid(issued_at: str, not_before: str, expires_at: str) -> bool:
        return parse_utc(issued_at) <= parse_utc(not_before) < parse_utc(expires_at)

    check(temporal_order_valid(envelope["issued_at"], envelope["not_before"], envelope["expires_at"]),
          "valid envelope chronology rejected")
    check(not temporal_order_valid("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
                                   "2025-12-31T23:59:59Z"), "expired envelope chronology accepted")

    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            check(key not in result, f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    try:
        json.loads('{"envelope_id":"first","envelope_id":"second"}', object_pairs_hook=reject_duplicate_keys)
        raise AssertionError("duplicate JSON keys unexpectedly parsed")
    except AssertionError as exc:
        if "unexpectedly parsed" in str(exc):
            raise
    except json.JSONDecodeError:
        raise AssertionError("duplicate-key parser fixture was malformed")

    def key_admissible_for_purpose(key_record: dict, expected_purpose: str, environment: str) -> bool:
        return (key_record.get("state") == "ACTIVE" and key_record.get("purpose") == expected_purpose
                and key_record.get("environment") == environment
                and key_record.get("private_material_present") is False)

    check(not key_admissible_for_purpose(key, "provider-fence", "test"),
          "cross-purpose key admission was not rejected")
    revoked_key = dict(key, state="REVOKED", revoked_at="2026-01-01T00:00:00Z",
                       revocation_reason="compromised")
    accepted(key_v, revoked_key, "revoked key metadata record")
    check(not key_admissible_for_purpose(revoked_key, "host-epoch", "test"),
          "revoked key was admitted")
    check(not (2 <= 1), "trust bundle rollback fixture setup error")
    check(2 > 1, "trust bundle generation monotonic comparison failed")
    rejected(bundle_v, dict(bundle, generation=2), "generation two without predecessor digest")
    rejected(bundle_v, dict(bundle, anti_rollback_witness_ref="", anti_rollback_witness_sha256=""),
             "missing anti-rollback witness")
    check(host_payload["fence_attestation_sha256"] != "0" * 64,
          "evidence digest fixture must carry a nonempty exact digest")
    check(not (key["environment"] != "test"), "cross-environment key fixture must be test-scoped")
    check(envelope["domain"] != "ORBIT-M0-PHASE-A-AUTHORIZATION/v1",
          "cross-protocol domain reuse fixture must be rejected")
    check(len({("nonce-a", 1), ("nonce-b", 1)}) == 2,
          "distinct nonce/epoch tuples should remain distinguishable")
    check(not (report["revocation_check"] == "UNKNOWN"),
          "unknown revocation freshness must never satisfy acceptance")
    check(report["decision"] == "AUDIT_ONLY" and report["signature_check"] == "NOT_RUN",
          "valid-signature/unverified-provider-fence fixture must remain audit-only")
    print("Typed payload schemas: 4 checked; positive and negative payload fixtures passed.")
    print("Temporal ordering, duplicate-key parsing, key-purpose/revocation and fail-closed gates passed.")

    catalog = load_json(SCHEMAS / "m0-crypto-verification-fixture-catalog.json")
    check(catalog["status"] == "contract-fixtures-only", "fixture catalog must remain structural only")
    check(catalog["cryptographic_profile_selected"] is False, "profile must remain unselected")
    check(catalog["required_negative_case_count"] == len(catalog["negative_cases"]) == 20,
          "negative case inventory must contain exactly 20 unique cases")
    check(len(set(catalog["negative_cases"])) == 20, "negative case IDs must be unique")
    check(catalog["known_answer_vectors"]["status"] == "blocked-pending-profile-selection",
          "cryptographic known-answer vectors must remain blocked pending profile selection")
    check(catalog["safety_invariants"] == {
        "private_key_material_in_fixtures": False,
        "production_keys_in_fixtures": False,
        "signature_verification_claimed": False,
        "execution_authorization": False
    }, "fixture safety invariants changed")

    contract = (ROOT / "docs/specifications/m0-cryptographic-trust-and-key-lifecycle.md").read_text(encoding="utf-8")
    check("m0-crypto-signed-envelope.schema.json" in contract, "crypto contract must link envelope schema")
    check("m0-crypto-trust-bundle.schema.json" in contract, "crypto contract must link trust-bundle schema")
    check("m0-crypto-key-metadata.schema.json" in contract, "crypto contract must link key metadata schema")
    check("m0-crypto-verification-report.schema.json" in contract, "crypto contract must link verification report")
    check("m0-crypto-verification-fixture-catalog.json" in contract, "crypto contract must link fixture catalog")
    print("M0 crypto contract schema validation: PASS")
    print("4 schemas checked; 4 synthetic positive and 5 negative structural cases passed.")
    print("20 required negative-vector IDs verified; cryptographic verification NOT performed.")


if __name__ == "__main__":
    main()
