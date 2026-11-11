#!/usr/bin/env python3
"""Validate the structural and canonical predecessor-fence bundle contract."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-predecessor-fence-bundle.schema.json"


def canonical_predecessor_digest(predecessors: list[dict]) -> str:
    """Hash the normalized identity set, not mutable evidence-reference metadata."""
    identity_set = [
        {
            "provider_instance_id": item["provider_instance_id"],
            "incarnation_epoch": item["incarnation_epoch"],
            "relationship": item["relationship"],
        }
        for item in sorted(predecessors, key=lambda item: item["provider_instance_id"])
    ]
    encoded = json.dumps(
        identity_set, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_bundle(bundle: dict, schema: dict) -> None:
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(bundle),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise ValueError("schema: " + "; ".join(error.message for error in errors))

    enumeration = bundle["enumeration"]
    observed_at = datetime.fromisoformat(enumeration["observed_at"].replace("Z", "+00:00"))
    source_ids: set[str] = set()
    for evidence in enumeration["source_evidence"]:
        if evidence["reference_id"] in source_ids:
            raise ValueError("enumeration source evidence reference IDs must be unique")
        source_ids.add(evidence["reference_id"])
        if evidence["acquired_by_id"] == evidence["independent_verifier_id"]:
            raise ValueError("inventory evidence acquirer and independent verifier must differ")
        acquired_at = datetime.fromisoformat(evidence["acquired_at"].replace("Z", "+00:00"))
        if acquired_at < observed_at:
            raise ValueError("inventory evidence cannot predate the completed enumeration observation")

    predecessors = bundle["predecessors"]
    identifiers = [item["provider_instance_id"] for item in predecessors]
    if identifiers != sorted(identifiers):
        raise ValueError("predecessors must be sorted by provider_instance_id")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("predecessor provider_instance_id values must be unique")

    references = [item["fence_attestation_ref"] for item in predecessors]
    digests = [item["fence_attestation_sha256"] for item in predecessors]
    if len(references) != len(set(references)):
        raise ValueError("each predecessor must have a distinct fence attestation reference")
    if len(digests) != len(set(digests)):
        raise ValueError("each predecessor must have a distinct fence attestation digest")

    for item in predecessors:
        fence_observed_at = datetime.fromisoformat(item["fence_observed_at"].replace("Z", "+00:00"))
        if fence_observed_at < observed_at:
            raise ValueError("predecessor fencing cannot predate complete predecessor enumeration")

    expected_digest = canonical_predecessor_digest(predecessors)
    if bundle["predecessor_set_sha256"] != expected_digest:
        raise ValueError("predecessor_set_sha256 does not match the canonical predecessor identity set")


def fixture() -> dict:
    predecessors = [
        {
            "provider_instance_id": "vm-old-a",
            "incarnation_epoch": 4,
            "relationship": "prior-instance",
            "fence_method": "provider-native-instance-termination",
            "fence_state": "FENCED",
            "fence_observed_at": "2026-11-11T10:05:00Z",
            "fence_attestation_ref": "https://evidence.example/fence/vm-old-a.json",
            "fence_attestation_sha256": "a" * 64,
        },
        {
            "provider_instance_id": "vm-old-b",
            "incarnation_epoch": 5,
            "relationship": "snapshot-clone",
            "fence_method": "provider-native-generation-fence",
            "fence_state": "FENCED",
            "fence_observed_at": "2026-11-11T10:06:00Z",
            "fence_attestation_ref": "https://evidence.example/fence/vm-old-b.json",
            "fence_attestation_sha256": "b" * 64,
        },
    ]
    return {
        "schema_version": "1.0",
        "bundle_id": "fence-bundle-2026-11-11-001",
        "host_enrollment_id": "host-enrollment-001",
        "provider_id": "provider-test",
        "provider_account_id": "account-test",
        "provider_region": "region-test",
        "target_provider_instance_id": "vm-new",
        "operation_id": "restore-operation-001",
        "request_nonce_sha256": "c" * 64,
        "request_sha256": "d" * 64,
        "enumeration": {
            "complete": True,
            "observed_at": "2026-11-11T10:00:00Z",
            "source_evidence": [
                {
                    "reference_id": "inventory-export-001",
                    "object_version": "version-1",
                    "sha256": "e" * 64,
                    "byte_count": 1024,
                    "evidence_root_id": "evidence-root-001",
                    "evidence_type": "watchdog-control-plane",
                    "acquired_by_id": "inventory-operator",
                    "acquired_at": "2026-11-11T10:01:00Z",
                    "independent_verifier_id": "independent-verifier",
                    "verification_status": "verified",
                }
            ],
        },
        "predecessor_set_sha256": canonical_predecessor_digest(predecessors),
        "predecessors": predecessors,
    }


def expect_rejected(name: str, bundle: dict, schema: dict) -> None:
    try:
        validate_bundle(bundle, schema)
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError(f"invalid bundle accepted: {name}")


def self_test(schema: dict) -> None:
    valid = fixture()
    validate_bundle(valid, schema)

    empty = deepcopy(valid)
    empty["predecessors"] = []
    empty["predecessor_set_sha256"] = canonical_predecessor_digest([])
    validate_bundle(empty, schema)

    duplicate = deepcopy(valid)
    duplicate["predecessors"][1]["provider_instance_id"] = duplicate["predecessors"][0]["provider_instance_id"]
    duplicate["predecessor_set_sha256"] = canonical_predecessor_digest(duplicate["predecessors"])
    expect_rejected("duplicate predecessor", duplicate, schema)

    unsorted = deepcopy(valid)
    unsorted["predecessors"].reverse()
    expect_rejected("unsorted predecessor set", unsorted, schema)

    digest_mismatch = deepcopy(valid)
    digest_mismatch["predecessor_set_sha256"] = "f" * 64
    expect_rejected("predecessor digest mismatch", digest_mismatch, schema)

    incomplete = deepcopy(valid)
    incomplete["enumeration"]["complete"] = False
    expect_rejected("incomplete inventory", incomplete, schema)

    duplicate_attestation = deepcopy(valid)
    duplicate_attestation["predecessors"][1]["fence_attestation_ref"] = duplicate_attestation["predecessors"][0]["fence_attestation_ref"]
    expect_rejected("duplicate fence attestation reference", duplicate_attestation, schema)

    premature_fence = deepcopy(valid)
    premature_fence["predecessors"][0]["fence_observed_at"] = "2026-11-11T09:59:59Z"
    expect_rejected("fence before enumeration", premature_fence, schema)

    same_operator = deepcopy(valid)
    same_operator["enumeration"]["source_evidence"][0]["independent_verifier_id"] = "inventory-operator"
    expect_rejected("self-verified inventory evidence", same_operator, schema)

    print("PASS  complete predecessor-fence bundle schema and canonical digest")
    print("PASS  empty inventory requires a complete independently evidenced enumeration")
    print("PASS  rejects duplicate, unsorted, mismatched and prematurely fenced predecessors")
    print("PASS  rejects incomplete or self-verified inventory evidence")


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    self_test(schema)


if __name__ == "__main__":
    main()
