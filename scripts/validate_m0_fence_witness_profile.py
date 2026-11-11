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
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, FormatChecker
import rfc8785

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-fence-witness-v1.schema.json"
VECTOR_PATHS = (
    ROOT / "docs/test-vectors/fence-witness-v1-001.json",
    ROOT / "docs/test-vectors/fence-witness-v1-002-unicode.json",
)
RECEIPT_PREFIX = b"SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\x00"
TRUST_BUNDLE_PREFIX = b"SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\x00"
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
    vector: dict[str, Any],
    validator: Draft202012Validator,
    vector_path: Path,
    private_seed_hex: str,
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

    # Independent RFC 8785 implementation check: the canonical bytes in the
    # published vectors must be reproduced from the parsed values byte-for-byte.
    require(rfc8785.dumps(checkpoint_from_bytes) == checkpoint_bytes,
            f"{vector_path.name}: checkpoint bytes differ from independent RFC 8785 output")
    require(rfc8785.dumps(receipt_from_bytes) == receipt_bytes,
            f"{vector_path.name}: receipt bytes differ from independent RFC 8785 output")

    checkpoint_digest = hashlib.sha256(checkpoint_bytes).hexdigest()
    require(checkpoint_digest == vector["checkpointDigest"],
            f"{vector_path.name}: checkpoint SHA-256 mismatch")
    require(checkpoint_digest == vector["receiptBody"]["checkpointDigest"],
            f"{vector_path.name}: receipt/checkpoint digest mismatch")

    public_raw = decode_canonical_base64url(vector["testKey"]["publicKeyBase64Url"])
    require(len(public_raw) == 32, "Ed25519 public key must be 32 bytes")
    key_id = hashlib.sha256(public_raw).hexdigest()
    require(key_id == vector["testKey"]["keyId"], "test public-key fingerprint mismatch")
    private_seed = bytes.fromhex(private_seed_hex)
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


def encode_canonical_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def validate_trust_bundle_key_semantics(body: dict[str, Any]) -> None:
    keys = body["keys"]
    key_ids = [item["keyId"] for item in keys]
    if len(key_ids) != len(set(key_ids)):
        raise ValueError("duplicate trust-bundle keyId")

    for item in keys:
        raw_key = decode_canonical_base64url(item["publicKeyBase64Url"])
        if len(raw_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        if hashlib.sha256(raw_key).hexdigest() != item["keyId"]:
            raise ValueError("trust-bundle keyId does not fingerprint its public key")
        if item["witnessId"] != body["witnessId"]:
            raise ValueError("trust-bundle key witness scope mismatch")

        not_before = datetime.fromisoformat(item["notBefore"].replace("Z", "+00:00"))
        not_after = datetime.fromisoformat(item["notAfter"].replace("Z", "+00:00"))
        if not_before >= not_after:
            raise ValueError("trust-bundle key validity interval is empty or reversed")
        if "retiredAt" in item:
            retired_at = datetime.fromisoformat(item["retiredAt"].replace("Z", "+00:00"))
            if retired_at < not_before:
                raise ValueError("trust-bundle key retirement precedes activation")

    revocations = body["revocations"]
    revoked_ids = [item["keyId"] for item in revocations]
    if len(revoked_ids) != len(set(revoked_ids)):
        raise ValueError("duplicate trust-bundle revocation keyId")
    for item in revocations:
        datetime.fromisoformat(item["revokedAt"].replace("Z", "+00:00"))


def sign_trust_bundle(
    body: dict[str, Any], root_signer: Ed25519PrivateKey
) -> dict[str, Any]:
    canonical_body = rfc8785.dumps(body)
    root_public_key = root_signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    root_key_id = hashlib.sha256(root_public_key).hexdigest()
    signature = root_signer.sign(TRUST_BUNDLE_PREFIX + canonical_body)
    return {
        "body": body,
        "bundleDigest": hashlib.sha256(canonical_body).hexdigest(),
        "rootKeyId": root_key_id,
        "rootSignature": encode_canonical_base64url(signature),
    }


def verify_trust_bundle_envelope(
    envelope: dict[str, Any],
    pinned_roots: dict[str, bytes],
    expected_generation: int,
    expected_predecessor_digest: str,
) -> str:
    body = envelope["body"]
    canonical_body = rfc8785.dumps(body)
    actual_digest = hashlib.sha256(canonical_body).hexdigest()
    if actual_digest != envelope["bundleDigest"]:
        raise ValueError("trust-bundle digest mismatch")

    root_key_id = envelope["rootKeyId"]
    root_public_key = pinned_roots.get(root_key_id)
    if root_public_key is None:
        raise ValueError("trust-bundle root key is not pinned")
    if hashlib.sha256(root_public_key).hexdigest() != root_key_id:
        raise ValueError("pinned root key fingerprint mismatch")

    signature = decode_canonical_base64url(envelope["rootSignature"])
    if len(signature) != 64:
        raise ValueError("root signature must be 64 bytes")
    Ed25519PublicKey.from_public_bytes(root_public_key).verify(
        signature, TRUST_BUNDLE_PREFIX + canonical_body
    )

    if body["generation"] != expected_generation + 1:
        raise ValueError("trust-bundle generation rollback or gap")
    if body["previousBundleDigest"] != expected_predecessor_digest:
        raise ValueError("trust-bundle predecessor fork")
    validate_trust_bundle_key_semantics(body)
    return actual_digest


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

    # This root is deterministic, fixture-only and never trusted by production.
    root_signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    root_public_key = root_signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    root_key_id = hashlib.sha256(root_public_key).hexdigest()
    pinned_roots = {root_key_id: root_public_key}

    envelope = sign_trust_bundle(body, root_signer)
    errors = list(validator.iter_errors(envelope))
    require(not errors, f"trust bundle fixture failed schema: {errors[:1]}")
    first_digest = verify_trust_bundle_envelope(
        envelope, pinned_roots, expected_generation=0,
        expected_predecessor_digest=ZERO_DIGEST,
    )

    successor_body = json.loads(json.dumps(body))
    successor_body["generation"] = 2
    successor_body["previousBundleDigest"] = first_digest
    successor = sign_trust_bundle(successor_body, root_signer)
    errors = list(validator.iter_errors(successor))
    require(not errors, f"successor trust bundle failed schema: {errors[:1]}")
    second_digest = verify_trust_bundle_envelope(
        successor, pinned_roots, expected_generation=1,
        expected_predecessor_digest=first_digest,
    )
    require(second_digest != first_digest, "successor trust bundle digest did not advance")

    # Reject cryptographically invalid or incorrectly chained trust updates.
    altered_body = json.loads(json.dumps(envelope))
    altered_body["body"]["trustDomainId"] = "attacker-substituted-domain"
    for label, candidate, generation, predecessor, roots in (
        ("altered body/digest", altered_body, 0, ZERO_DIGEST, pinned_roots),
        ("unknown root", {**envelope, "rootKeyId": "3" * 64}, 0, ZERO_DIGEST, pinned_roots),
        ("invalid root signature", {**envelope, "rootSignature": "A" * 86}, 0, ZERO_DIGEST, pinned_roots),
        ("generation gap", sign_trust_bundle(
            {**body, "generation": 3}, root_signer
        ), 1, first_digest, pinned_roots),
        ("predecessor fork", sign_trust_bundle(
            {**body, "generation": 2, "previousBundleDigest": "f" * 64},
            root_signer,
        ), 1, first_digest, pinned_roots),
    ):
        try:
            verify_trust_bundle_envelope(candidate, roots, generation, predecessor)
        except (ValueError, InvalidSignature):
            pass
        else:
            raise AssertionError(f"invalid trust bundle was accepted: {label}")

    duplicate_ids = json.loads(json.dumps(body))
    duplicate_ids["keys"].append(dict(key))
    try:
        validate_trust_bundle_key_semantics(duplicate_ids)
    except ValueError as error:
        require("duplicate" in str(error), "duplicate-key rejection had an unexpected reason")
    else:
        raise AssertionError("duplicate trust-bundle key IDs were accepted")

    wrong_fingerprint = json.loads(json.dumps(body))
    wrong_fingerprint["keys"][0]["keyId"] = "f" * 64
    try:
        validate_trust_bundle_key_semantics(wrong_fingerprint)
    except ValueError as error:
        require("fingerprint" in str(error), "fingerprint rejection had an unexpected reason")
    else:
        raise AssertionError("incorrect trust-bundle key fingerprint was accepted")

    wrong_scope = json.loads(json.dumps(body))
    wrong_scope["keys"][0]["witnessId"] = "another-witness"
    try:
        validate_trust_bundle_key_semantics(wrong_scope)
    except ValueError as error:
        require("scope" in str(error), "scope rejection had an unexpected reason")
    else:
        raise AssertionError("trust-bundle key with substituted witness scope was accepted")

    duplicate_revocations = json.loads(json.dumps(body))
    duplicate_revocations["revocations"] = [
        {"keyId": key_material["keyId"], "revokedAt": "2026-02-01T00:00:00Z", "reason": "test A"},
        {"keyId": key_material["keyId"], "revokedAt": "2026-02-02T00:00:00Z", "reason": "test B"},
    ]
    try:
        validate_trust_bundle_key_semantics(duplicate_revocations)
    except ValueError as error:
        require("revocation" in str(error), "duplicate-revocation rejection had an unexpected reason")
    else:
        raise AssertionError("duplicate trust-bundle revocations were accepted")

def main() -> None:
    schema = strict_json_load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)

    # jsonschema treats some optional format implementations as permissive when
    # their extras are absent. Supply an explicit stdlib RFC3339 date-time check
    # so invalid calendar/time values cannot silently pass CI.
    format_checker = FormatChecker()

    @format_checker.checks("date-time")
    def valid_date_time(value: Any) -> bool:
        if not isinstance(value, str):
            return True
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        return parsed.tzinfo is not None

    validator = Draft202012Validator(schema, format_checker=format_checker)

    vectors = [strict_json_load(path) for path in VECTOR_PATHS]
    test_seed = vectors[0]["testKey"]["privateSeedHex"]
    key_material = verify_vector(vectors[0], validator, VECTOR_PATHS[0], test_seed)
    verify_vector(vectors[1], validator, VECTOR_PATHS[1], test_seed)
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
    print("- independent RFC 8785 canonical-byte reproduction for ASCII and Unicode vectors")
    print("- SHA-256 checkpoint digest and Ed25519 receipt signature verification")
    print("- pinned-root trust-bundle digest/signature and monotonic succession checks")
    print("- negative trust-bundle root, signature, digest, generation, predecessor and scope cases")
    print("- negative schema, timestamp, signature, duplicate-key and fingerprint cases")
    print("Boundary: no provider consistency, durable storage, anti-equivocation or production trust is proven")


if __name__ == "__main__":
    main()
