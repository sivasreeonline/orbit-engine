#!/usr/bin/env python3
"""Verify FENCE-001 evidence manifest integrity and dual Ed25519 attestations.

Fixture keys are test-only. Real qualification must supply trusted keys through
an independently governed file and must use testOnly=false manifests.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
import rfc8785

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-fence-evidence-manifest-v1.schema.json"
VECTOR_PATH = ROOT / "docs/test-vectors/fence-evidence-manifest-v1.json"
SIGNATURE_PREFIX = b"SKYHIGH-FENCE-001-EVIDENCE-MANIFEST-V1\x00"


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def decode_b64url(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("base64url value must be non-empty and unpadded")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("non-canonical base64url encoding")
    return decoded


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_manifest(
    envelope: dict[str, Any],
    trusted_keys: list[dict[str, str]],
    *,
    allow_test_only: bool = False,
) -> str:
    schema = load_json(SCHEMA_PATH)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = list(validator.iter_errors(envelope))
    require(not errors, f"manifest schema failure: {errors[0].message if errors else ''}")

    body = envelope["manifestBody"]
    require(body["testOnly"] is False or allow_test_only, "test-only manifest cannot qualify external evidence")
    canonical_body = rfc8785.dumps(body)
    digest = hashlib.sha256(canonical_body).hexdigest()
    require(digest == envelope["manifestDigest"], "manifest digest mismatch")

    key_map: dict[str, dict[str, str]] = {}
    for item in trusted_keys:
        key_id = item["keyId"]
        require(key_id not in key_map, "duplicate trusted key ID")
        public_key = decode_b64url(item["publicKeyBase64Url"])
        require(len(public_key) == 32, "Ed25519 public key must be exactly 32 bytes")
        require(hashlib.sha256(public_key).hexdigest() == key_id, "trusted key fingerprint mismatch")
        key_map[key_id] = {**item, "rawPublicKey": public_key.hex()}

    attestations = envelope["attestations"]
    roles = [item["role"] for item in attestations]
    require(sorted(roles) == ["COLLECTOR", "INDEPENDENT_VERIFIER"], "exactly one collector and one independent verifier attestation are required")
    identities = [item["signerIdentity"] for item in attestations]
    key_ids = [item["keyId"] for item in attestations]
    require(len(set(identities)) == 2, "collector and independent verifier identities must differ")
    require(len(set(key_ids)) == 2, "collector and independent verifier keys must differ")

    role_identity: dict[str, str] = {}
    for attestation in attestations:
        key = key_map.get(attestation["keyId"])
        require(key is not None, "attestation key is not in independently supplied trust configuration")
        require(key["identity"] == attestation["signerIdentity"], "attestation signer identity does not match trusted key")
        require(key["role"] == attestation["role"], "attestation role does not match trusted key authorization")
        payload = {
            "manifestDigest": digest,
            "role": attestation["role"],
            "signerIdentity": attestation["signerIdentity"],
            "keyId": attestation["keyId"],
        }
        signature = decode_b64url(attestation["signatureBase64Url"])
        require(len(signature) == 64, "Ed25519 signature must be exactly 64 bytes")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["rawPublicKey"])).verify(
                signature, SIGNATURE_PREFIX + rfc8785.dumps(payload)
            )
        except InvalidSignature as error:
            raise ValueError("manifest attestation signature verification failed") from error
        role_identity[attestation["role"]] = attestation["signerIdentity"]

    artifacts = body["artifacts"]
    artifact_ids = [item["artifactId"] for item in artifacts]
    require(len(artifact_ids) == len(set(artifact_ids)), "artifact IDs must be unique")
    provider = body["providerScope"]
    adapter = body["adapter"]
    require(bool(provider["name"] and provider["account"] and provider["region"] and provider["service"]), "provider scope must be complete")
    require(len(adapter["commit"]) == 40 and len(adapter["configurationDigest"]) == 64, "adapter source/configuration must be pinned")

    for artifact in artifacts:
        require(artifact["collectorIdentity"] == role_identity["COLLECTOR"], "artifact collector identity differs from signed collector")
        require(artifact["independentVerifierIdentity"] == role_identity["INDEPENDENT_VERIFIER"], "artifact verifier identity differs from signed verifier")
        require(artifact["collectorKeyId"] == next(x["keyId"] for x in attestations if x["role"] == "COLLECTOR"), "artifact collector key differs from signed collector key")
        require(artifact["verifierKeyId"] == next(x["keyId"] for x in attestations if x["role"] == "INDEPENDENT_VERIFIER"), "artifact verifier key differs from signed verifier key")
        require(artifact["collectorIdentity"] != artifact["independentVerifierIdentity"], "artifact collector and verifier must be independent")
    return digest


def run_fixture_negative_cases(vector: dict[str, Any]) -> int:
    keys = vector["trustedKeys"]
    validate_manifest({k: vector[k] for k in ("manifestBody", "manifestDigest", "attestations")}, keys, allow_test_only=True)
    cases = 0

    changed_digest = copy.deepcopy(vector)
    changed_digest["manifestBody"]["manifestId"] = "tampered"
    try:
        validate_manifest({k: changed_digest[k] for k in ("manifestBody", "manifestDigest", "attestations")}, keys, allow_test_only=True)
    except ValueError:
        cases += 1
    else:
        raise AssertionError("tampered manifest body was accepted")

    changed_signature = copy.deepcopy(vector)
    changed_signature["attestations"][0]["signatureBase64Url"] = "A" * 86
    try:
        validate_manifest({k: changed_signature[k] for k in ("manifestBody", "manifestDigest", "attestations")}, keys, allow_test_only=True)
    except ValueError:
        cases += 1
    else:
        raise AssertionError("invalid signature was accepted")

    same_identity = copy.deepcopy(vector)
    same_identity["attestations"][1]["signerIdentity"] = same_identity["attestations"][0]["signerIdentity"]
    try:
        validate_manifest({k: same_identity[k] for k in ("manifestBody", "manifestDigest", "attestations")}, keys, allow_test_only=True)
    except ValueError:
        cases += 1
    else:
        raise AssertionError("same collector/verifier identity was accepted")

    wrong_key_role = copy.deepcopy(vector)
    wrong_key_role["trustedKeys"][0]["role"] = "INDEPENDENT_VERIFIER"
    try:
        validate_manifest({k: wrong_key_role[k] for k in ("manifestBody", "manifestDigest", "attestations")}, wrong_key_role["trustedKeys"], allow_test_only=True)
    except ValueError:
        cases += 1
    else:
        raise AssertionError("wrong key role authorization was accepted")

    duplicate_artifact = copy.deepcopy(vector)
    duplicate_artifact["manifestBody"]["artifacts"].append(copy.deepcopy(duplicate_artifact["manifestBody"]["artifacts"][0]))
    duplicate_artifact["manifestDigest"] = hashlib.sha256(rfc8785.dumps(duplicate_artifact["manifestBody"])).hexdigest()
    try:
        validate_manifest({k: duplicate_artifact[k] for k in ("manifestBody", "manifestDigest", "attestations")}, keys, allow_test_only=True)
    except ValueError:
        cases += 1
    else:
        raise AssertionError("duplicate artifact ID was accepted")
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, help="external manifest envelope JSON")
    parser.add_argument("--trusted-keys", type=Path, help="independently governed trusted-key JSON")
    args = parser.parse_args()

    if args.manifest or args.trusted_keys:
        if not args.manifest or not args.trusted_keys:
            parser.error("--manifest and --trusted-keys must be supplied together")
        envelope = load_json(args.manifest)
        trust = load_json(args.trusted_keys)
        digest = validate_manifest(envelope, trust["keys"], allow_test_only=False)
        print(f"External evidence manifest signature and integrity verification: PASS ({digest})")
        print(f"Artifacts: {len(envelope['manifestBody']['artifacts'])}; production qualification is still a separate review")
        return

    vector = load_json(VECTOR_PATH)
    digest = validate_manifest(
        {k: vector[k] for k in ("manifestBody", "manifestDigest", "attestations")},
        vector["trustedKeys"],
        allow_test_only=True,
    )
    negative_cases = run_fixture_negative_cases(vector)
    print("FENCE-001 evidence manifest: PASS")
    print(f"Fixture manifest digest: {digest}")
    print("Dual Ed25519 attestations: collector + independent verifier")
    print(f"Negative cases rejected: {negative_cases}")
    print("Scope: test-only fixture; no provider evidence or production qualification")


if __name__ == "__main__":
    main()
