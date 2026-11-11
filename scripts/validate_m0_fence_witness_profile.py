#!/usr/bin/env python3
"""Executable structural and cryptographic conformance checks for FENCE-001 v1 fixtures.

This validates the published JSON Schema, strict JSON parsing, independent RFC 8785
canonicalization, checkpoint/trust-bundle digests, Ed25519 signatures, trust-root
succession, and receipt-to-checkpoint/key-lifecycle binding. It does not prove
provider consistency, durability, anti-equivocation or production trust.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
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
TRUST_VECTOR_PATH = ROOT / "docs/test-vectors/fence-witness-v1-003-trust-bundle.json"
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
        "checkpointBody": vector["checkpointBody"],
        "checkpointDigest": vector["checkpointDigest"],
        "receiptBody": vector["receiptBody"],
        "signatureBase64Url": vector["signatureBase64Url"],
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
            if retired_at < not_before or retired_at > not_after:
                raise ValueError("trust-bundle key retirement is outside its validity interval")

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
    expected_trust_domain_id: str,
    expected_witness_id: str,
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

    if body["profile"] != "sky-high-fence-witness-v1":
        raise ValueError("trust-bundle profile mismatch")
    if body["trustDomainId"] != expected_trust_domain_id:
        raise ValueError("trust-bundle trust-domain substitution")
    if body["witnessId"] != expected_witness_id:
        raise ValueError("trust-bundle witness substitution")
    if body["generation"] != expected_generation + 1:
        raise ValueError("trust-bundle generation rollback or gap")
    if body["previousBundleDigest"] != expected_predecessor_digest:
        raise ValueError("trust-bundle predecessor fork")
    validate_trust_bundle_key_semantics(body)
    return actual_digest


def verify_trust_bundle_schema(
    validator: Draft202012Validator,
    key_material: dict[str, str],
    trust_vector: dict[str, Any],
) -> dict[str, Any]:
    require(trust_vector.get("testOnly") is True, "trust-bundle vector is not marked testOnly")
    require(trust_vector.get("profile") == "sky-high-fence-witness-v1", "unexpected trust-bundle profile")
    prefix = trust_vector["algorithm"]["trustBundleSignatureInputPrefixUtf8"].encode("utf-8")
    require(prefix == TRUST_BUNDLE_PREFIX, "trust-bundle domain-separation prefix mismatch")

    test_root = trust_vector["testRootKey"]
    root_seed = bytes.fromhex(test_root["privateSeedHex"])
    require(len(root_seed) == 32, "test root seed must be 32 bytes")
    root_signer = Ed25519PrivateKey.from_private_bytes(root_seed)
    root_public_key = decode_canonical_base64url(test_root["publicKeyBase64Url"])
    require(len(root_public_key) == 32, "Ed25519 root public key must be 32 bytes")
    derived_root_public = root_signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    require(derived_root_public == root_public_key, "test root seed does not derive the published root key")
    root_key_id = hashlib.sha256(root_public_key).hexdigest()
    require(root_key_id == test_root["keyId"], "test root-key fingerprint mismatch")
    pinned_roots = {root_key_id: root_public_key}

    def envelope_from_vector(name: str) -> dict[str, Any]:
        item = trust_vector[name]
        body_bytes = item["canonicalBodyUtf8"].encode("utf-8")
        require(rfc8785.dumps(item["body"]) == body_bytes,
                f"{name}: canonical bytes differ from independent RFC 8785 output")
        require(hashlib.sha256(body_bytes).hexdigest() == item["bundleDigest"],
                f"{name}: trust-bundle SHA-256 mismatch")
        require(item["rootKeyId"] == root_key_id, f"{name}: unexpected root key ID")
        signature = decode_canonical_base64url(item["rootSignatureBase64Url"])
        require(len(signature) == 64, f"{name}: Ed25519 root signature must be 64 bytes")
        Ed25519PublicKey.from_public_bytes(root_public_key).verify(signature, prefix + body_bytes)
        return {
            "body": item["body"],
            "bundleDigest": item["bundleDigest"],
            "rootKeyId": item["rootKeyId"],
            "rootSignature": item["rootSignatureBase64Url"],
        }

    first = envelope_from_vector("generation1")
    second = envelope_from_vector("generation2")
    for label, envelope in (("generation 1", first), ("generation 2", second)):
        errors = list(validator.iter_errors(envelope))
        require(not errors, f"{label} trust bundle failed schema: {errors[:1]}")

    first_digest = verify_trust_bundle_envelope(
        first, pinned_roots, expected_generation=0,
        expected_predecessor_digest=ZERO_DIGEST,
        expected_trust_domain_id="test-trust-domain-vector-01",
        expected_witness_id="witness-vector-01",
    )
    require(first_digest == trust_vector["generation1"]["bundleDigest"],
            "generation 1 digest did not match the published vector")
    second_digest = verify_trust_bundle_envelope(
        second, pinned_roots, expected_generation=1,
        expected_predecessor_digest=first_digest,
        expected_trust_domain_id="test-trust-domain-vector-01",
        expected_witness_id="witness-vector-01",
    )
    require(second_digest == trust_vector["generation2"]["bundleDigest"],
            "generation 2 digest did not match the published vector")
    require(second_digest != first_digest, "successor trust bundle digest did not advance")

    body = first["body"]
    key = body["keys"][0]
    require(key_material["keyId"] == key["keyId"], "trust bundle key differs from receipt vector key")
    require(key_material["witnessId"] == body["witnessId"],
            "trust bundle witness differs from receipt vector witness")

    # Reject cryptographically invalid or incorrectly chained trust updates.
    altered_body = json.loads(json.dumps(first))
    altered_body["body"]["trustDomainId"] = "attacker-substituted-domain"
    for label, candidate, generation, predecessor, roots in (
        ("altered body/digest", altered_body, 0, ZERO_DIGEST, pinned_roots),
        ("unknown root", {**first, "rootKeyId": "3" * 64}, 0, ZERO_DIGEST, pinned_roots),
        ("invalid root signature", {**first, "rootSignature": "A" * 86}, 0, ZERO_DIGEST, pinned_roots),
        ("generation gap", sign_trust_bundle(
            {**body, "generation": 3}, root_signer
        ), 1, first_digest, pinned_roots),
        ("predecessor fork", sign_trust_bundle(
            {**body, "generation": 2, "previousBundleDigest": "f" * 64},
            root_signer,
        ), 1, first_digest, pinned_roots),
        ("trust-domain substitution", sign_trust_bundle(
            {**body, "trustDomainId": "attacker-domain"}, root_signer
        ), 0, ZERO_DIGEST, pinned_roots),
        ("witness substitution", sign_trust_bundle(
            {**body, "witnessId": "attacker-witness"}, root_signer
        ), 0, ZERO_DIGEST, pinned_roots),
    ):
        try:
            verify_trust_bundle_envelope(
                candidate, roots, generation, predecessor,
                "test-trust-domain-vector-01", "witness-vector-01"
            )
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
        {"keyId": key["keyId"], "revokedAt": "2026-02-01T00:00:00Z", "reason": "test A"},
        {"keyId": key["keyId"], "revokedAt": "2026-02-02T00:00:00Z", "reason": "test B"},
    ]
    try:
        validate_trust_bundle_key_semantics(duplicate_revocations)
    except ValueError as error:
        require("revocation" in str(error), "duplicate-revocation rejection had an unexpected reason")
    else:
        raise AssertionError("duplicate trust-bundle revocations were accepted")

    return body


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("timestamp must be UTC")
    return parsed


def verify_receipt_against_trusted_bundle(
    vector_result: dict[str, Any],
    trust_bundle_body: dict[str, Any],
    trusted_receipt_time: datetime,
) -> None:
    """Verify a receipt using only the independently root-verified trust bundle.

    trusted_receipt_time is synthetic independent time evidence supplied by
    this test harness. It is deliberately not derived from receipt.committedAt.
    """
    checkpoint = vector_result["checkpointBody"]
    checkpoint_digest = vector_result["checkpointDigest"]
    receipt = vector_result["receiptBody"]

    require(receipt["profile"] == checkpoint["profile"], "receipt/checkpoint profile mismatch")
    require(receipt["schemaVersion"] == checkpoint["schemaVersion"], "receipt/checkpoint schema version mismatch")
    require(receipt["authorityId"] == checkpoint["authorityId"], "receipt/checkpoint authority mismatch")
    require(receipt["hostId"] == checkpoint["hostId"], "receipt/checkpoint host mismatch")
    require(receipt["generation"] == checkpoint["generation"], "receipt/checkpoint generation mismatch")
    require(receipt["operationId"] == checkpoint["operationId"], "receipt/checkpoint operation mismatch")
    require(receipt["previousCheckpointDigest"] == checkpoint["previousCheckpointDigest"],
            "receipt/checkpoint predecessor mismatch")
    require(receipt["checkpointDigest"] == checkpoint_digest, "receipt/checkpoint digest mismatch")
    require(trust_bundle_body["profile"] == receipt["profile"], "trust-bundle profile mismatch")
    require(trust_bundle_body["witnessId"] == receipt["witnessId"], "receipt witness is not trusted")

    matches = [item for item in trust_bundle_body["keys"] if item["keyId"] == receipt["keyId"]]
    if len(matches) != 1:
        raise ValueError("receipt key ID is missing or ambiguous in trusted bundle")
    key = matches[0]
    if key["purpose"] != "WITNESS_RECEIPT_SIGNING":
        raise ValueError("trusted key has the wrong purpose")
    if key["witnessId"] != receipt["witnessId"]:
        raise ValueError("trusted key witness scope mismatch")
    if receipt["authorityId"] not in key["authorityIds"]:
        raise ValueError("receipt authority is outside trusted key scope")

    not_before = parse_utc(key["notBefore"])
    not_after = parse_utc(key["notAfter"])
    if not_before > trusted_receipt_time or trusted_receipt_time >= not_after:
        raise ValueError("trusted receipt time is outside key validity interval")
    if "retiredAt" in key and trusted_receipt_time >= parse_utc(key["retiredAt"]):
        raise ValueError("trusted key was retired at receipt time")

    if any(item["keyId"] == receipt["keyId"] for item in trust_bundle_body["revocations"]):
        raise ValueError("receipt signing key is revoked")

    raw_public_key = decode_canonical_base64url(key["publicKeyBase64Url"])
    if len(raw_public_key) != 32:
        raise ValueError("trusted Ed25519 public key must be 32 bytes")
    if hashlib.sha256(raw_public_key).hexdigest() != key["keyId"]:
        raise ValueError("trusted key fingerprint mismatch")
    signature = decode_canonical_base64url(vector_result["signatureBase64Url"])
    if len(signature) != 64:
        raise ValueError("receipt signature must be 64 bytes")
    receipt_bytes = rfc8785.dumps(receipt)
    Ed25519PublicKey.from_public_bytes(raw_public_key).verify(
        signature, RECEIPT_PREFIX + receipt_bytes
    )


def expect_receipt_rejection(
    vector_result: dict[str, Any],
    trust_bundle_body: dict[str, Any],
    trusted_receipt_time: datetime,
    label: str,
) -> None:
    try:
        verify_receipt_against_trusted_bundle(
            vector_result, trust_bundle_body, trusted_receipt_time
        )
    except (ValueError, InvalidSignature):
        return
    raise AssertionError(f"invalid receipt trust binding was accepted: {label}")


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
    vector_results = [
        verify_vector(vector, validator, path, test_seed)
        for vector, path in zip(vectors, VECTOR_PATHS, strict=True)
    ]
    key_material = vector_results[0]
    trust_vector = strict_json_load(TRUST_VECTOR_PATH)
    trusted_bundle_body = verify_trust_bundle_schema(validator, key_material, trust_vector)

    # Independent synthetic trusted-time evidence is supplied by the harness;
    # receipt.committedAt is not accepted as its own trust source.
    trusted_times = (
        datetime(2026, 1, 2, 3, 4, 6, tzinfo=timezone.utc),
        datetime(2026, 1, 2, 3, 5, 7, tzinfo=timezone.utc),
    )
    for vector_result, trusted_time in zip(vector_results, trusted_times, strict=True):
        verify_receipt_against_trusted_bundle(
            vector_result, trusted_bundle_body, trusted_time
        )

    first_receipt = vector_results[0]
    second_receipt = vector_results[1]
    expect_receipt_rejection(
        second_receipt,
        {**trusted_bundle_body, "keys": [
            {**trusted_bundle_body["keys"][0], "authorityIds": ["authority-vector-01"]}
        ]},
        trusted_times[1],
        "authority outside key scope",
    )
    expect_receipt_rejection(
        first_receipt,
        {**trusted_bundle_body, "witnessId": "substituted-witness"},
        trusted_times[0],
        "wrong witness",
    )
    expect_receipt_rejection(
        first_receipt,
        {**trusted_bundle_body, "keys": [
            {**trusted_bundle_body["keys"][0], "notBefore": "2027-01-01T00:00:00Z"}
        ]},
        trusted_times[0],
        "key not yet active",
    )
    expect_receipt_rejection(
        first_receipt,
        {**trusted_bundle_body, "keys": [
            {**trusted_bundle_body["keys"][0], "notAfter": "2026-01-01T00:00:00Z"}
        ]},
        trusted_times[0],
        "key expired",
    )
    expect_receipt_rejection(
        first_receipt,
        {**trusted_bundle_body, "keys": [
            {**trusted_bundle_body["keys"][0], "retiredAt": "2026-01-02T03:04:04Z"}
        ]},
        trusted_times[0],
        "key retired",
    )
    expect_receipt_rejection(
        first_receipt,
        {**trusted_bundle_body, "revocations": [
            {"keyId": first_receipt["keyId"], "revokedAt": "2026-01-02T03:04:04Z", "reason": "fixture compromise"}
        ]},
        trusted_times[0],
        "key revoked",
    )
    expect_receipt_rejection(
        first_receipt,
        {**trusted_bundle_body, "keys": [
            {**trusted_bundle_body["keys"][0], "keyId": "f" * 64}
        ]},
        trusted_times[0],
        "unknown key",
    )

    duplicate_json = '{"body":{"x":1,"x":2},"signature":"x"}'
    try:
        json.loads(duplicate_json, object_pairs_hook=strict_object)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate JSON object member was not rejected")

    print("FENCE-001 witness profile conformance: PASS")
    print("- Draft 2020-12 schema self-validation and format checks")
    print("- checkpoint, receipt and published root-signed trust-bundle structural fixtures")
    print("- strict duplicate-member JSON parsing")
    print("- independent RFC 8785 canonical-byte reproduction for ASCII and Unicode vectors")
    print("- SHA-256 checkpoint digest and Ed25519 receipt signature verification")
    print("- independent RFC 8785, SHA-256 and Ed25519 verification for both trust-bundle generations")
    print("- pinned-root trust-bundle digest/signature and monotonic succession checks")
    print("- receipt-to-checkpoint and trusted-key scope/validity/retirement/revocation binding")
    print("- negative trust-bundle root, signature, digest, generation, predecessor and scope cases")
    print("- negative schema, timestamp, signature, duplicate-key and fingerprint cases")
    print("Boundary: no provider consistency, durable storage, anti-equivocation or production trust is proven")


if __name__ == "__main__":
    main()
