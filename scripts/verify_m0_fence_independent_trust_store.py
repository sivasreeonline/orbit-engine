#!/usr/bin/env python3
"""Verify FENCE-001 evidence against a separately governed public-key trust store.

The trust store contains public keys only. It is not generated from the manifest
being verified. Revoked keys fail closed, including for historical signatures.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from validate_m0_fence_evidence_manifest import load_json, validate_manifest
from validate_m0_fence_cloudtrail_qualified_manifest import validate_qualified_manifest

PROFILE = "sky-high-fence-trusted-key-store-v1"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs/schemas/m0-fence-trusted-key-store-v1.schema.json"
ROLES = {"COLLECTOR", "INDEPENDENT_VERIFIER"}
STATUSES = {"ACTIVE", "REVOKED"}


def parse_time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_trust_store(
    store: dict[str, Any],
    manifest: dict[str, Any],
    *,
    verification_time: datetime | None = None,
) -> list[dict[str, str]]:
    schema = load_json(SCHEMA_PATH)
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(store))
    if errors:
        raise ValueError(f"trusted-key store schema failure: {errors[0].message}")
    if store.get("profile") != PROFILE or store.get("schemaVersion") != 1:
        raise ValueError("unsupported FENCE-001 trusted-key store profile/version")
    if store.get("status") != "ACTIVE":
        raise ValueError("trusted-key store is not ACTIVE")
    if not isinstance(store.get("storeId"), str) or not store["storeId"].strip():
        raise ValueError("trusted-key store requires a stable storeId")
    if not isinstance(store.get("approvedBy"), str) or not store["approvedBy"].strip():
        raise ValueError("trusted-key store requires an accountable approver")
    if not isinstance(store.get("approvalReference"), str) or not store["approvalReference"].strip():
        raise ValueError("trusted-key store requires an external approval reference")
    if not isinstance(store.get("keys"), list) or not store["keys"]:
        raise ValueError("trusted-key store must contain public key records")

    body = manifest.get("manifestBody")
    if not isinstance(body, dict):
        raise ValueError("manifestBody is missing")
    created_at = parse_time(body.get("createdAt"), "manifest createdAt")
    now = verification_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("verification_time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if created_at > now:
        raise ValueError("manifest creation time is in the future relative to verification time")

    keys_by_id: dict[str, dict[str, Any]] = {}
    for record in store["keys"]:
        if not isinstance(record, dict):
            raise ValueError("trusted-key records must be objects")
        key_id = record.get("keyId")
        identity = record.get("identity")
        role = record.get("role")
        status = record.get("status")
        if not isinstance(key_id, str) or len(key_id) != 64:
            raise ValueError("trusted-key record has an invalid keyId")
        if key_id in keys_by_id:
            raise ValueError("trusted-key store contains duplicate key IDs")
        if not isinstance(identity, str) or not identity.strip():
            raise ValueError("trusted-key identity is required")
        if role not in ROLES:
            raise ValueError("trusted-key role is not authorized by FENCE-001")
        if status not in STATUSES:
            raise ValueError("trusted-key status must be ACTIVE or REVOKED")
        encoded_public = record.get("publicKeyBase64Url")
        if not isinstance(encoded_public, str) or not encoded_public or "=" in encoded_public:
            raise ValueError("trusted-key record must contain canonical unpadded public Ed25519 key")
        try:
            public_bytes = base64.urlsafe_b64decode(encoded_public + "=" * (-len(encoded_public) % 4))
        except Exception as error:
            raise ValueError("trusted-key public key is not valid base64url") from error
        if len(public_bytes) != 32 or base64.urlsafe_b64encode(public_bytes).decode("ascii").rstrip("=") != encoded_public:
            raise ValueError("trusted-key public key must be canonical 32-byte Ed25519 material")
        if hashlib.sha256(public_bytes).hexdigest() != key_id:
            raise ValueError("trusted-key public key fingerprint does not match keyId")
        if not isinstance(record.get("approvedBy"), str) or not record["approvedBy"].strip():
            raise ValueError("each trusted key requires an accountable approver")
        if not isinstance(record.get("approvalReference"), str) or not record["approvalReference"].strip():
            raise ValueError("each trusted key requires an external approval reference")
        not_before = parse_time(record.get("notBefore"), f"{key_id} notBefore")
        not_after = parse_time(record.get("notAfter"), f"{key_id} notAfter")
        if not_before >= not_after:
            raise ValueError("trusted-key validity interval must be ordered")
        if status == "REVOKED":
            if not isinstance(record.get("revokedAt"), str) or not record["revokedAt"]:
                raise ValueError("revoked trusted-key records require revokedAt")
            parse_time(record["revokedAt"], f"{key_id} revokedAt")
        keys_by_id[key_id] = record

    attestations = manifest.get("attestations")
    if not isinstance(attestations, list):
        raise ValueError("manifest attestations are missing")
    if len(attestations) != 2 or {item.get("role") for item in attestations} != ROLES:
        raise ValueError("manifest must contain exactly one attestation for each FENCE-001 role")

    selected: list[dict[str, str]] = []
    selected_ids: set[str] = set()
    selected_identities: set[str] = set()
    for attestation in attestations:
        key_id = attestation.get("keyId")
        record = keys_by_id.get(key_id)
        if record is None:
            raise ValueError(f"manifest attestation key {key_id} is not present in independent trust store")
        if record["status"] == "REVOKED":
            raise ValueError(f"manifest references revoked trusted key {key_id}")
        not_before = parse_time(record["notBefore"], f"{key_id} notBefore")
        not_after = parse_time(record["notAfter"], f"{key_id} notAfter")
        if not_before > created_at or created_at >= not_after:
            raise ValueError(f"manifest creation time falls outside trusted-key validity for {key_id}")
        if record["role"] != attestation.get("role"):
            raise ValueError("manifest attestation role is not authorized by trusted-key record")
        if record["identity"] != attestation.get("signerIdentity"):
            raise ValueError("manifest signer identity does not match trusted-key record")
        if key_id in selected_ids or record["identity"] in selected_identities:
            raise ValueError("collector and verifier must use distinct trusted keys and identities")
        selected_ids.add(key_id)
        selected_identities.add(record["identity"])
        selected.append({
            "keyId": record["keyId"],
            "identity": record["identity"],
            "role": record["role"],
            "publicKeyBase64Url": record["publicKeyBase64Url"],
        })

    if len(selected_ids) != 2:
        raise ValueError("collector and verifier trust records must be distinct")
    return selected


def verify_manifest_with_trust_store(
    manifest: dict[str, Any],
    store: dict[str, Any],
    *,
    verification_time: datetime | None = None,
    allow_test_only: bool = False,
) -> str:
    trusted_keys = validate_trust_store(store, manifest, verification_time=verification_time)
    return validate_manifest(manifest, trusted_keys, allow_test_only=allow_test_only)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    args = parser.parse_args()

    envelope = load_json(args.manifest)
    trust_store = load_json(args.trust_store)
    trusted_keys = validate_trust_store(trust_store, envelope)
    result = validate_qualified_manifest(
        envelope,
        trusted_keys,
        args.artifact_root,
        allow_test_only=False,
    )
    print(f"Independent trust-store verification: PASS ({result['manifestDigest']})")
    print(f"Evidence gate: {result['evidenceGateStatus']}")
    print(f"Inventory status: {result['inventoryStatus']}")
    print(f"External qualification: {result['externalQualificationStatus']}")
    print(f"Production qualification ready: {result['productionQualificationReady']}")
    print("A valid trust-store signature check does not independently establish production qualification.")


if __name__ == "__main__":
    main()
