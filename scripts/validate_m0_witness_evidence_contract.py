#!/usr/bin/env python3
"""Structural and fail-closed semantic checks for proposed M0 witness/evidence receipts.

Synthetic contract validation only. This does not contact Neon, R2, a witness,
verify signatures, or prove object-lock/retention behavior.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT_SCHEMA = ROOT / "docs/schemas/m0-ledger-anti-rollback-checkpoint.schema.json"
EVIDENCE_SCHEMA = ROOT / "docs/schemas/m0-immutable-evidence-object-receipt.schema.json"


def load_schema(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def validate(schema, value, label):
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
                    key=lambda error: list(error.path))
    if errors:
        raise AssertionError(f"{label}: " + "; ".join(error.message for error in errors))


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def checkpoint_alignment(restored, witness):
    """Exact anchor equality is required before authorization operations reopen."""
    fields = (
        "generation", "ledger_event_sequence", "ledger_event_digest",
        "authorization_ledger_digest", "trust_bundle_generation",
        "trust_bundle_digest", "revocation_generation", "revocation_digest",
        "host_epoch_high_watermarks",
    )
    return all(restored.get(field) == witness.get(field) for field in fields)


def evidence_receipt_acceptable(receipt):
    """Reject unverifiable immutability, version substitution, or principal collision."""
    if receipt["retention_mode"] not in {"governance", "compliance", "provider-immutable"}:
        return False
    if receipt["object_version_id"] != receipt["readback_version_id"]:
        return False
    if receipt["content_sha256"] != receipt["readback_sha256"]:
        return False
    if parse_time(receipt["retain_until"]) < parse_time(receipt["required_retention_until"]):
        return False
    if len({receipt["writer_principal"], receipt["evidence_acquirer_principal"],
            receipt["independent_verifier_principal"]}) != 3:
        return False
    if parse_time(receipt["readback_at"]) < parse_time(receipt["created_at"]):
        return False
    return True


def main():
    checkpoint_schema = load_schema(CHECKPOINT_SCHEMA)
    evidence_schema = load_schema(EVIDENCE_SCHEMA)
    digest = "a" * 64
    checkpoint = {
        "schema_version": "1.0.0", "checkpoint_id": "00000000-0000-4000-8000-000000000001",
        "witness_id": "independent-witness-a", "authority_id": "authority-a",
        "environment": "test", "generation": 7, "ledger_event_sequence": 41,
        "ledger_event_digest": digest, "authorization_ledger_digest": "b" * 64,
        "trust_bundle_generation": 3, "trust_bundle_digest": "c" * 64,
        "revocation_generation": 5, "revocation_digest": "d" * 64,
        "host_epoch_high_watermarks": [{"host_enrollment_id": "00000000-0000-4000-8000-000000000002", "epoch": 9}],
        "issued_at": "2026-11-10T10:00:00Z", "nonce": "n" * 32,
        "signature_ref": "evidence://checkpoint-signature/1", "signature_sha256": "e" * 64
    }
    validate(checkpoint_schema, checkpoint, "valid checkpoint")
    assert checkpoint_alignment(checkpoint, dict(checkpoint))
    for field, changed in (
        ("generation", 6), ("ledger_event_sequence", 40),
        ("ledger_event_digest", "f" * 64), ("revocation_generation", 4),
        ("trust_bundle_generation", 2),
    ):
        altered = dict(checkpoint)
        altered[field] = changed
        assert not checkpoint_alignment(altered, checkpoint), f"stale {field} must quarantine"

    evidence = {
        "schema_version": "1.0.0", "receipt_id": "00000000-0000-4000-8000-000000000003",
        "provider": "cloudflare-r2", "bucket_ref": "private-evidence", "object_key": "m0/evidence/abc",
        "object_version_id": "version-001", "content_sha256": digest, "size_bytes": 128,
        "retention_mode": "compliance", "retain_until": "2030-01-01T00:00:00Z",
        "legal_hold": True, "object_lock_configuration_digest": "f" * 64,
        "writer_principal": "writer-a", "created_at": "2026-11-10T10:00:00Z",
        "readback_version_id": "version-001", "readback_sha256": digest,
        "readback_at": "2026-11-10T10:01:00Z", "evidence_acquirer_principal": "acquirer-b",
        "independent_verifier_principal": "verifier-c",
        "required_retention_until": "2029-01-01T00:00:00Z"
    }
    validate(evidence_schema, evidence, "valid evidence receipt")
    assert evidence_receipt_acceptable(evidence)
    mutations = []
    for field, value in (
        ("readback_version_id", "latest-not-pinned"),
        ("readback_sha256", "0" * 64),
        ("retention_mode", "unverified"),
        ("retain_until", "2028-01-01T00:00:00Z"),
        ("independent_verifier_principal", "acquirer-b"),
    ):
        altered = dict(evidence)
        altered[field] = value
        mutations.append(altered)
    for altered in mutations:
        assert not evidence_receipt_acceptable(altered), "unsafe evidence receipt must be rejected"

    print("PASS  anti-rollback checkpoint schema and exact restored-state alignment")
    print("PASS  stale generation, event, trust-bundle and revocation anchors fail closed")
    print("PASS  immutable evidence exact-version, digest, retention and principal-separation checks")
    print("NOTE  synthetic contract checks only; no Neon, witness, R2, object-lock or signature integration")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
