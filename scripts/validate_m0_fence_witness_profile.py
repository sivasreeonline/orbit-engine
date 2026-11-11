#!/usr/bin/env python3
"""Executable structural and cryptographic conformance checks for FENCE-001 v1 fixtures.

This validates the published JSON Schema, strict JSON parsing, schema fixtures,
key fingerprints, canonical fixture bytes, checkpoint digests and Ed25519 receipt
signatures. It deliberately does not claim RFC 8785 implementation conformance,
provider consistency, durability, anti-equivocation or production trust.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-fence-witness-v1.schema.json"
VECTOR_PATHS = (
    ROOT / "docs/test-vectors/fence-witness-v1-001.json",
    ROOT / "docs/test-vectors/fence-witness-v1-002-unicode.json",
)
RECEIPT_PREFIX = b"SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\x00"
ZERO_DIGEST = "0" * 64


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def strict_json_load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def decode_canonical_base64url(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("base64url must be non-empty and unpadded")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    encoded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if encoded != value:
        raise ValueError("non-canonical base64url encoding")
    return decoded


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_schema_rejection(validator: Draft202012Validator, value: dict[str, Any], label: str) -> None:
    require(list(validator.iter_errors(value)) != [], f"negative schema case unexpectedly passed: {label}")


def verify_vector(
    vector: dict[str, Any], validator: Draft202012Validator, vector_path: Path
) -> dict[str, Any]:
    require(vector.get("testOnly") is True, f"{vector_path.name}: fixture is not marked testOnly")
    require(vector.get("profile") == "sky-high-fence-witness-v1", "unexpected profile")
    algorithm = vector["algorithm"]
    require(algorithm["canonicalization"] == "RFC8785-JCS", "unexpected canonicalization")
    require(algorithm["digest"] == "SHA-256", "unexpected digest algorithm")
    require(algorithm["signature"] == "Ed25519", "unexpected signature algorithm")
    require(algorithm["signatureInputPrefixUtf8"].encode("utf-8") == RECEIPT_PREFIX,
            "receipt domain-separation prefix mismatch")

    checkpoint_bytes = vector["checkpointCanonicalUtf8"].encode("utf-8")
    receipt_bytes = vector["receiptCanonicalUtf8"].encode("utf-8")
    checkpoint_from_bytes = json.loads(checkpoint_bytes, object_pairs_hook=strict_object)
    receipt_from_bytes = json.loads(receipt_bytes, object_pairs_hook=strict_object)
    require(checkpoint_from_bytes == vector["checkpointBody"],
            f"{vector_path.name}: checkpoint bytes do not represent checkpointBody")
    require(receipt_from_bytes == vector["receiptBody"],
            f"{vector_path.name}: receipt bytes do not represent receiptBody")

    checkpoint_digest = hashlib.sha256(checkpoint_bytes).hexdigest()
    require(checkpoint_digest == vector["checkpointDigest"],
            f"{vector_path.name}: checkpoint SHA-256 mismatch")
    require(checkpoint_digest == vector["receiptBody"]["checkpointDigest"],
            f"{vector_path.name}: receipt/checkpoint digest mismatch")

    public_raw = decode_canonical_base64url(vector["testKey"]["publicKeyBase64Url"])
    require(len(public_raw) == 32, "Ed25519 public key must be 32 bytes")
    key_id = hashlib.sha256(public_raw).hexdigest()
    require(key_id == vector["testKey"]["keyId"], "test public-key fingerprint mismatch")
    private_seed = bytes.fromhex(vector["testKey"]["privateSeedHex"])
    require(len(private_seed) == 32, "Ed25519 private seed must be 32 bytes")
    derived_public = Ed25519PrivateKey.from_private_bytes(private_seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    require(derived_public == public_raw, "test seed does not derive the published public key")

    signature = decode_canonical_base64url(vector["signatureBase64Url"])
    require(len(signature) == 64, "Ed25519 signature must be 64 bytes")
    Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, RECEIPT_PREFIX + receipt_bytes)

    checkpoint_artifact = {
        "body": vector["checkpointBody"],
        "checkpointDigest": vector["checkpointDigest"],
    }
    receipt_envelope = {
        "body": vector["receiptBody"],
        "signature": vector["signatureBase64Url"],
    }
    for label, artifact in (
        ("checkpoint artifact", checkpoint_artifact),
        ("receipt envelope", receipt_envelope),
    ):
        errors = list(validator.iter_errors(artifact))
        require(not errors, f"{vector_path.name}: {label} failed schema: {errors[:1]}")

    bad_checkpoint = dict(checkpoint_artifact)
    bad_checkpoint["checkpointDigest"] = "A" * 64
    expect_schema_rejection(validator, bad_checkpoint, "uppercase checkpoint digest")

    bad_receipt = json.loads(json.dumps(receipt_envelope))
    bad_receipt["body"]["committedAt"] = "2026-13-45T99:99:99Z"
    expect_schema_rejection(validator, bad_receipt, "invalid receipt timestamp")

    bad_signature = dict(receipt_envelope)
    bad_signature["signature"] = "!" * 86
    expect_schema_rejection(validator, bad_signature, "invalid signature alphabet")

    return {
        "keyId": key_id,
        "publicKeyBase64Url": vector["testKey"]["publicKeyBase64Url"],
        "witnessId": vector["receiptBody"]["witnessId"],
        "authorityId": vector["receiptBody"]["authorityId"],
    }


def verify_trust_bundle_schema(
    validator: Draft202012Validator, key_material: dict[str, str]
) -> None:
    key = {
        "keyId": key_material["keyId"],
        "publicKeyBase64Url": key_material["publicKeyBase64Url"],
        "purpose": "WITNESS_RECEIPT_SIGNING",
        "witnessId": key_material["witnessId"],
        "authorityIds": [key_material["authorityId"]],
        "notBefore": "2026-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
    }
    body = {
        "profile": "sky-high-fence-witness-v1",
        "schemaVersion": 1,
        "trustDomainId": "test-trust-domain",
        "witnessId": key_material["witnessId"],
        "generation": 1,
        "previousBundleDigest": ZERO_DIGEST,
        "keys": [key],
        "revocations": [],
    }
    envelope = {
        "body": body,
        "bundleDigest": "1" * 64,
        "rootKeyId": "2" * 64,
        "rootSignature": "A" * 86,
    }
    errors = list(validator.iter_errors(envelope))
    require(not errors, f"trust bundle fixture failed schema: {errors[:1]}")

    duplicate_ids = json.loads(json.dumps(envelope))
    duplicate_ids["body"]["keys"].append(dict(key))
    ids = [item["keyId"] for item in duplicate_ids["body"]["keys"]]
    require(len(ids) != len(set(ids)), "duplicate-key fixture did not contain duplicate IDs")
    require(
        len({item["keyId"] for item in duplicate_ids["body"]["keys"]})
        != len(duplicate_ids["body"]["keys"]),
        "duplicate key IDs must be rejected by semantic conformance checks",
    )

    wrong_fingerprint = json.loads(json.dumps(envelope))
    wrong_fingerprint["body"]["keys"][0]["keyId"] = "f" * 64
    raw_key = decode_canonical_base64url(
        wrong_fingerprint["body"]["keys"][0]["publicKeyBase64Url"]
    )
    require(hashlib.sha256(raw_key).hexdigest() !=
            wrong_fingerprint["body"]["keys"][0]["keyId"],
            "wrong-fingerprint fixture unexpectedly matches")


def main() -> None:
    schema = strict_json_load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    vectors = [strict_json_load(path) for path in VECTOR_PATHS]
    key_material = verify_vector(vectors[0], validator, VECTOR_PATHS[0])
    verify_vector(vectors[1], validator, VECTOR_PATHS[1])
    verify_trust_bundle_schema(validator, key_material)

    duplicate_json = '{"body":{"x":1,"x":2},"signature":"x"}'
    try:
        json.loads(duplicate_json, object_pairs_hook=strict_object)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate JSON object member was not rejected")

    print("FENCE-001 witness profile conformance: PASS")
    print("- Draft 2020-12 schema self-validation and format checks")
    print("- checkpoint, receipt and trust-bundle structural fixtures")
    print("- strict duplicate-member JSON parsing")
    print("- ASCII and Unicode vector byte binding, SHA-256 and Ed25519 verification")
    print("- negative schema, timestamp, signature, duplicate-key and fingerprint cases")
    print("Boundary: no RFC 8785 implementation, provider consistency or production trust is proven")


if __name__ == "__main__":
    main()
