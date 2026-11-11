#!/usr/bin/env python3
"""Synthetic cross-binding verifier for FENCE-001 bundle and host-epoch response."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs/schemas"


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def canonical_predecessor_digest(predecessors: list[dict]) -> str:
    identities = [
        {
            "provider_instance_id": item["provider_instance_id"],
            "incarnation_epoch": item["incarnation_epoch"],
            "relationship": item["relationship"],
        }
        for item in sorted(predecessors, key=lambda item: item["provider_instance_id"])
    ]
    return hashlib.sha256(canonical_json_bytes(identities)).hexdigest()


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include an explicit UTC offset")
    return parsed


def require_schema(value: dict, schema_path: Path, label: str) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise ValueError(f"{label} schema: " + "; ".join(error.message for error in errors))


def verify_binding(
    response: dict,
    bundle_bytes: bytes,
    bundle_object_version: str,
    response_schema: dict,
    bundle_schema: dict,
) -> None:
    bundle = json.loads(bundle_bytes)
    for value, schema, label in (
        (response, response_schema, "host epoch response"),
        (bundle, bundle_schema, "predecessor fence bundle"),
    ):
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            raise ValueError(f"{label} schema: " + "; ".join(error.message for error in errors))

    if canonical_json_bytes(bundle) != bundle_bytes:
        raise ValueError("aggregate bundle bytes are not canonical JSON")
    if response["fence_attestation_object_version"] != bundle_object_version:
        raise ValueError("response bundle object version mismatch")
    if response["fence_attestation_ref"] != bundle["bundle_id"] and response["fence_attestation_ref"] != bundle_bytes_ref(bundle):
        raise ValueError("response bundle reference does not identify the supplied aggregate bundle")
    bundle_digest = hashlib.sha256(bundle_bytes).hexdigest()
    if response["fence_attestation_sha256"] != bundle_digest:
        raise ValueError("response aggregate bundle digest mismatch")

    bindings = {
        "host_enrollment_id": "host_enrollment_id",
        "provider_id": "provider_id",
        "provider_account_id": "provider_account_id",
        "provider_region": "provider_region",
        "provider_instance_id": "target_provider_instance_id",
        "operation_id": "operation_id",
        "request_nonce_sha256": "request_nonce_sha256",
        "request_sha256": "request_sha256",
        "predecessor_set_sha256": "predecessor_set_sha256",
    }
    for response_field, bundle_field in bindings.items():
        if response[response_field] != bundle[bundle_field]:
            raise ValueError(f"response/bundle binding mismatch: {response_field}")

    predecessors = bundle["predecessors"]
    if response["provider_instance_id"] in {
        item["provider_instance_id"] for item in predecessors
    }:
        raise ValueError("successor provider instance is also listed as a predecessor")
    if response["incarnation_epoch"] <= max(
        (item["incarnation_epoch"] for item in predecessors), default=0
    ):
        raise ValueError("successor epoch must exceed every enumerated predecessor epoch")
    if canonical_predecessor_digest(predecessors) != bundle["predecessor_set_sha256"]:
        raise ValueError("bundle predecessor-set digest is not canonical")

    enumeration_time = parse_time(bundle["enumeration"]["observed_at"])
    authority_time = parse_time(response["authority_observed_at"])
    if authority_time < enumeration_time:
        raise ValueError("authority response predates complete predecessor enumeration")
    for item in predecessors:
        if parse_time(item["fence_observed_at"]) < enumeration_time:
            raise ValueError("predecessor fence predates complete enumeration")
        if authority_time < parse_time(item["fence_observed_at"]):
            raise ValueError("authority response predates a predecessor fence observation")


def bundle_bytes_ref(bundle: dict) -> str:
    """Fixture contract uses a stable URI-like aggregate reference derived from bundle ID."""
    return "https://evidence.example/bundles/" + bundle["bundle_id"]


def fixtures() -> tuple[dict, dict, str]:
    predecessors = [
        {
            "provider_instance_id": "vm-old-a",
            "incarnation_epoch": 4,
            "relationship": "prior-instance",
            "fence_method": "provider-native-instance-termination",
            "fence_state": "FENCED",
            "fence_observed_at": "2026-11-11T10:05:00Z",
            "fence_attestation_ref": "https://evidence.example/fence/vm-old-a.json",
            "fence_attestation_object_version": "object-version-1",
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
            "fence_attestation_object_version": "object-version-2",
            "fence_attestation_sha256": "b" * 64,
        },
    ]
    bundle = {
        "schema_version": "1.0",
        "bundle_id": "fence-bundle-binding-001",
        "host_enrollment_id": "enrollment-01",
        "provider_id": "provider-test",
        "provider_account_id": "account-test",
        "provider_region": "region-test",
        "target_provider_instance_id": "vm-new",
        "operation_id": "operation-001",
        "request_nonce_sha256": "c" * 64,
        "request_sha256": "d" * 64,
        "enumeration": {
            "complete": True,
            "observed_at": "2026-11-11T10:00:00Z",
            "source_evidence": [
                {
                    "reference_id": "inventory-export-001",
                    "object_version": "inventory-version-1",
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
    bundle_bytes = canonical_json_bytes(bundle)
    response = {
        "host_enrollment_id": "enrollment-01",
        "provider_id": "provider-test",
        "provider_account_id": "account-test",
        "provider_region": "region-test",
        "provider_instance_id": "vm-new",
        "incarnation_epoch": 6,
        "operation_id": "operation-001",
        "response_id": "response-001",
        "request_nonce_sha256": "c" * 64,
        "request_sha256": "d" * 64,
        "predecessor_set_sha256": bundle["predecessor_set_sha256"],
        "fence_attestation_ref": bundle_bytes_ref(bundle),
        "fence_attestation_object_version": "bundle-object-version-1",
        "fence_attestation_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "authority_observed_at": "2026-11-11T10:07:00Z",
        "authority_record_version": "authority-record-9",
    }
    return response, bundle, "bundle-object-version-1"


def expect_rejected(name: str, response: dict, bundle: dict, version: str,
                    response_schema: dict, bundle_schema: dict) -> None:
    try:
        verify_binding(response, canonical_json_bytes(bundle), version, response_schema, bundle_schema)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return
    raise AssertionError(f"invalid response/bundle binding accepted: {name}")


def self_test(response_schema: dict, bundle_schema: dict) -> None:
    response, bundle, version = fixtures()
    verify_binding(response, canonical_json_bytes(bundle), version, response_schema, bundle_schema)

    cases = []
    changed = deepcopy(response)
    changed["request_nonce_sha256"] = "f" * 64
    cases.append(("nonce mismatch", changed, deepcopy(bundle), version))

    changed = deepcopy(response)
    changed["provider_instance_id"] = "vm-old-a"
    cases.append(("successor is predecessor", changed, deepcopy(bundle), version))

    changed = deepcopy(response)
    changed["incarnation_epoch"] = 5
    cases.append(("non-increasing epoch", changed, deepcopy(bundle), version))

    changed = deepcopy(response)
    changed["authority_observed_at"] = "2026-11-11T10:04:59Z"
    cases.append(("authority response before fence", changed, deepcopy(bundle), version))

    changed = deepcopy(response)
    changed["fence_attestation_object_version"] = "different-version"
    cases.append(("object version mismatch", changed, deepcopy(bundle), version))

    changed = deepcopy(response)
    changed["fence_attestation_sha256"] = "0" * 64
    cases.append(("bundle digest mismatch", changed, deepcopy(bundle), version))

    changed = deepcopy(response)
    changed["fence_attestation_ref"] = "urn:orbit:m0:predecessor-fence-bundle:other"
    cases.append(("bundle reference mismatch", changed, deepcopy(bundle), version))

    changed_bundle = deepcopy(bundle)
    changed_bundle["provider_account_id"] = "different-account"
    cases.append(("provider account mismatch", deepcopy(response), changed_bundle, version))

    changed_bundle = deepcopy(bundle)
    changed_bundle["predecessors"][0]["fence_observed_at"] = "2026-11-11T10:08:00Z"
    changed_response = deepcopy(response)
    changed_response["fence_attestation_sha256"] = hashlib.sha256(canonical_json_bytes(changed_bundle)).hexdigest()
    cases.append(("fence after authority response", changed_response, changed_bundle, version))

    changed_bundle = deepcopy(bundle)
    changed_bundle["enumeration"]["observed_at"] = "2026-11-11T10:00:00"
    changed_response = deepcopy(response)
    changed_response["fence_attestation_sha256"] = hashlib.sha256(canonical_json_bytes(changed_bundle)).hexdigest()
    cases.append(("timezone-naive enumeration timestamp", changed_response, changed_bundle, version))

    for name, candidate_response, candidate_bundle, candidate_version in cases:
        expect_rejected(name, candidate_response, candidate_bundle, candidate_version,
                        response_schema, bundle_schema)

    noncanonical = json.dumps(bundle, indent=2).encode("utf-8")
    try:
        verify_binding(response, noncanonical, version, response_schema, bundle_schema)
    except ValueError:
        pass
    else:
        raise AssertionError("non-canonical aggregate bundle bytes accepted")

    print("PASS  canonical aggregate bundle bytes and immutable object binding")
    print("PASS  host/provider/target/operation/nonce/request/predecessor-set cross-binding")
    print("PASS  strictly increasing successor epoch and predecessor exclusion")
    print("PASS  complete-enumeration, per-predecessor fence and authority chronology")
    print("PASS  rejects nonce, account, object-version, digest, reference and epoch mismatches")
    print("PASS  rejects non-canonical bytes and timezone-naive timestamps")


def main() -> None:
    response_schema = json.loads((SCHEMAS / "m0-host-epoch-response-payload.schema.json").read_text(encoding="utf-8"))
    bundle_schema = json.loads((SCHEMAS / "m0-predecessor-fence-bundle.schema.json").read_text(encoding="utf-8"))
    self_test(response_schema, bundle_schema)


if __name__ == "__main__":
    main()
