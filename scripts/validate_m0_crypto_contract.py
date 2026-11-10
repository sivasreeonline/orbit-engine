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
        "expires_at": "2026-01-01T00:05:00Z", "payload": {"synthetic": True},
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
    print("4 schemas checked; 4 synthetic positive and 4 negative structural cases passed.")
    print("20 required negative-vector IDs verified; cryptographic verification NOT performed.")


if __name__ == "__main__":
    main()
