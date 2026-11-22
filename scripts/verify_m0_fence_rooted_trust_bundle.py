#!/usr/bin/env python3
"""Verify FENCE-001 manifests through a root-pinned, monotonic trust bundle.

Root public keys and the expected bundle generation/predecessor are supplied
out of band. The trust bundle cannot self-authorize its own root or freshness.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
import rfc8785

from validate_m0_fence_evidence_manifest import load_json
from validate_m0_fence_cloudtrail_qualified_manifest import validate_qualified_manifest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-fence-manifest-trust-bundle-v1.schema.json"
PROFILE = "sky-high-fence-manifest-trust-bundle-v1"
SIGNATURE_PREFIX = b"SKYHIGH-FENCE-001-MANIFEST-TRUST-BUNDLE-V1\x00"
ROLES = {"COLLECTOR", "INDEPENDENT_VERIFIER"}


def decode_b64url(value: str, label: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(f"{label} must be non-empty unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as error:
        raise ValueError(f"{label} is not valid base64url") from error
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError(f"{label} is not canonical base64url")
    return raw


def parse_time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return result.astimezone(timezone.utc)


def load_pinned_roots(path: Path) -> dict[str, bytes]:
    document = load_json(path)
    records = document.get("keys")
    if not isinstance(records, list) or not records:
        raise ValueError("pinned root configuration must contain a non-empty keys array")
    roots: dict[str, bytes] = {}
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("pinned root entries must be objects")
        key_id = item.get("keyId")
        raw = decode_b64url(item.get("publicKeyBase64Url"), "pinned root public key")
        if len(raw) != 32 or hashlib.sha256(raw).hexdigest() != key_id:
            raise ValueError("pinned root public key length/fingerprint mismatch")
        if key_id in roots:
            raise ValueError("duplicate pinned root key ID")
        roots[key_id] = raw
    return roots


def verify_trust_bundle(
    envelope: dict[str, Any],
    pinned_roots: dict[str, bytes],
    *,
    expected_generation: int,
    expected_predecessor_digest: str,
    expected_trust_domain_id: str,
    manifest: dict[str, Any],
    verification_time: datetime | None = None,
) -> list[dict[str, str]]:
    schema = load_json(SCHEMA_PATH)
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(envelope))
    if errors:
        raise ValueError(f"manifest trust-bundle schema failure: {errors[0].message}")

    body = envelope["body"]
    canonical_body = rfc8785.dumps(body)
    actual_digest = hashlib.sha256(canonical_body).hexdigest()
    if actual_digest != envelope["bundleDigest"]:
        raise ValueError("manifest trust-bundle digest mismatch")

    root_key_id = envelope["rootKeyId"]
    root_public = pinned_roots.get(root_key_id)
    if root_public is None:
        raise ValueError("manifest trust-bundle root is not pinned out of band")
    if hashlib.sha256(root_public).hexdigest() != root_key_id:
        raise ValueError("pinned manifest trust root fingerprint mismatch")
    signature = decode_b64url(envelope["rootSignature"], "trust-bundle root signature")
    if len(signature) != 64:
        raise ValueError("trust-bundle Ed25519 root signature must be 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(root_public).verify(
            signature, SIGNATURE_PREFIX + canonical_body
        )
    except InvalidSignature as error:
        raise ValueError("manifest trust-bundle root signature verification failed") from error

    if body["profile"] != PROFILE:
        raise ValueError("manifest trust-bundle profile mismatch")
    if body["trustDomainId"] != expected_trust_domain_id:
        raise ValueError("manifest trust-bundle trust-domain substitution")
    if body["generation"] != expected_generation + 1:
        raise ValueError("manifest trust-bundle generation rollback or gap")
    if body["previousBundleDigest"] != expected_predecessor_digest:
        raise ValueError("manifest trust-bundle predecessor fork")

    now = verification_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("verification_time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    bundle_created = parse_time(body["createdAt"], "trust-bundle createdAt")
    if bundle_created > now:
        raise ValueError("trust-bundle creation time is in the future")

    keys_by_id: dict[str, dict[str, Any]] = {}
    for item in body["keys"]:
        key_id = item["keyId"]
        if not item["identity"].strip() or not item["approvedBy"].strip() or not item["approvalReference"].strip():
            raise ValueError("manifest trust-bundle key identity and approval metadata must be non-empty")
        if key_id in keys_by_id:
            raise ValueError("duplicate manifest trust-bundle key ID")
        public_raw = decode_b64url(item["publicKeyBase64Url"], "manifest signing public key")
        if len(public_raw) != 32 or hashlib.sha256(public_raw).hexdigest() != key_id:
            raise ValueError("manifest trust-bundle key fingerprint mismatch")
        not_before = parse_time(item["notBefore"], f"{key_id} notBefore")
        not_after = parse_time(item["notAfter"], f"{key_id} notAfter")
        if not_before >= not_after:
            raise ValueError("manifest trust-bundle key validity interval is reversed")
        if "retiredAt" in item:
            retired_at = parse_time(item["retiredAt"], f"{key_id} retiredAt")
            if retired_at < not_before or retired_at > not_after:
                raise ValueError("manifest trust-bundle key retirement is outside validity interval")
        keys_by_id[key_id] = item

    revoked_ids = [item["keyId"] for item in body["revocations"]]
    if len(revoked_ids) != len(set(revoked_ids)):
        raise ValueError("duplicate manifest trust-bundle revocation")
    for item in body["revocations"]:
        parse_time(item["revokedAt"], f"{item['keyId']} revokedAt")

    manifest_body = manifest.get("manifestBody")
    if not isinstance(manifest_body, dict):
        raise ValueError("manifestBody is missing")
    manifest_created = parse_time(manifest_body.get("createdAt"), "manifest createdAt")
    if bundle_created > manifest_created:
        raise ValueError("manifest predates the trust-bundle generation used to verify it")

    attestations = manifest.get("attestations")
    if not isinstance(attestations, list) or len(attestations) != 2 or {a.get("role") for a in attestations} != ROLES:
        raise ValueError("manifest must contain exactly one collector and one independent-verifier attestation")

    selected: list[dict[str, str]] = []
    selected_ids: set[str] = set()
    selected_identities: set[str] = set()
    for attestation in attestations:
        key_id = attestation.get("keyId")
        key = keys_by_id.get(key_id)
        if key is None:
            raise ValueError(f"manifest signing key {key_id} is absent from root-signed trust bundle")
        if key_id in revoked_ids:
            raise ValueError(f"manifest signing key {key_id} is revoked")
        if key["role"] != attestation.get("role"):
            raise ValueError("manifest signing key role is not authorized by root-signed trust bundle")
        if key["identity"] != attestation.get("signerIdentity"):
            raise ValueError("manifest signer identity differs from root-signed trust bundle")
        not_before = parse_time(key["notBefore"], f"{key_id} notBefore")
        not_after = parse_time(key["notAfter"], f"{key_id} notAfter")
        if not_before > manifest_created or manifest_created >= not_after:
            raise ValueError("manifest creation time is outside root-trusted key validity")
        if "retiredAt" in key and manifest_created >= parse_time(key["retiredAt"], f"{key_id} retiredAt"):
            raise ValueError("manifest was signed after trusted key retirement")
        if key_id in selected_ids or key["identity"] in selected_identities:
            raise ValueError("collector and verifier must use distinct trusted keys and identities")
        selected_ids.add(key_id)
        selected_identities.add(key["identity"])
        selected.append({
            "keyId": key_id,
            "identity": key["identity"],
            "role": key["role"],
            "publicKeyBase64Url": key["publicKeyBase64Url"],
        })
    return selected


def verify_external_package(
    manifest: dict[str, Any],
    trust_bundle: dict[str, Any],
    pinned_roots: dict[str, bytes],
    artifact_root: Path,
    *,
    expected_generation: int,
    expected_predecessor_digest: str,
    expected_trust_domain_id: str,
    allow_test_only: bool = False,
) -> dict[str, Any]:
    trusted_keys = verify_trust_bundle(
        trust_bundle, pinned_roots,
        expected_generation=expected_generation,
        expected_predecessor_digest=expected_predecessor_digest,
        expected_trust_domain_id=expected_trust_domain_id,
        manifest=manifest,
    )
    return validate_qualified_manifest(
        manifest, trusted_keys, artifact_root, allow_test_only=allow_test_only
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--trust-bundle", type=Path, required=True)
    parser.add_argument("--pinned-roots", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--expected-generation", type=int, required=True)
    parser.add_argument("--expected-predecessor-digest", required=True)
    parser.add_argument("--expected-trust-domain-id", required=True)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    bundle = load_json(args.trust_bundle)
    roots = load_pinned_roots(args.pinned_roots)
    result = verify_external_package(
        manifest, bundle, roots, args.artifact_root,
        expected_generation=args.expected_generation,
        expected_predecessor_digest=args.expected_predecessor_digest,
        expected_trust_domain_id=args.expected_trust_domain_id,
    )
    print(f"Root-pinned trust-bundle verification: PASS ({result['manifestDigest']})")
    print(f"Evidence gate: {result['evidenceGateStatus']}")
    print(f"Inventory status: {result['inventoryStatus']}")
    print(f"External qualification: {result['externalQualificationStatus']}")
    print(f"Production qualification ready: {result['productionQualificationReady']}")


if __name__ == "__main__":
    main()
