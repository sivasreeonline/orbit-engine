#!/usr/bin/env python3
"""Synthetic root-signature, anti-rollback and manifest-key lifecycle tests."""
from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rfc8785

from validate_m0_fence_evidence_manifest import load_json, validate_manifest
from verify_m0_fence_rooted_trust_bundle import (
    SIGNATURE_PREFIX,
    verify_trust_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
VERIFY_AT = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
ZERO_DIGEST = "0" * 64


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sign_bundle(body: dict, root_key: Ed25519PrivateKey) -> dict:
    canonical = rfc8785.dumps(body)
    public = root_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = root_key.sign(SIGNATURE_PREFIX + canonical)
    import base64
    return {
        "body": body,
        "bundleDigest": sha(canonical),
        "rootKeyId": sha(public),
        "rootSignature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def build_body(keys: list[dict]) -> dict:
    return {
        "profile": "sky-high-fence-manifest-trust-bundle-v1",
        "schemaVersion": 1,
        "trustDomainId": "sky-high-cloudtrail-production",
        "generation": 1,
        "previousBundleDigest": ZERO_DIGEST,
        "createdAt": "2026-11-01T00:00:00Z",
        "keys": keys,
        "revocations": [],
    }


def main() -> None:
    vector = load_json(ROOT / "docs/test-vectors/fence-evidence-manifest-v1.json")
    manifest = {k: vector[k] for k in ("manifestBody", "manifestDigest", "attestations")}
    keys = [
        {
            **item,
            "notBefore": "2026-01-01T00:00:00Z",
            "notAfter": "2027-01-01T00:00:00Z",
            "approvedBy": "synthetic-root-governance",
            "approvalReference": "FIXTURE-ROOT-APPROVAL",
        }
        for item in vector["trustedKeys"]
    ]
    root_key = Ed25519PrivateKey.generate()
    root_public = root_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    roots = {sha(root_public): root_public}
    bundle = sign_bundle(build_body(keys), root_key)

    trusted = verify_trust_bundle(
        bundle, roots, expected_generation=0, expected_predecessor_digest=ZERO_DIGEST,
        expected_trust_domain_id="sky-high-cloudtrail-production",
        manifest=manifest, verification_time=VERIFY_AT,
    )
    assert validate_manifest(manifest, trusted, allow_test_only=True) == manifest["manifestDigest"]
    print("PASS root-pinned trust bundle authorizes the exact manifest collector/verifier keys")

    try:
        verify_trust_bundle(
            bundle, {}, expected_generation=0, expected_predecessor_digest=ZERO_DIGEST,
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "not pinned" in str(error)
    else:
        raise AssertionError("un-pinned root was accepted")
    print("PASS trust bundle cannot introduce its own root")

    try:
        verify_trust_bundle(
            bundle, roots, expected_generation=1, expected_predecessor_digest=bundle["bundleDigest"],
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "generation rollback or gap" in str(error)
    else:
        raise AssertionError("stale trust-bundle generation was accepted")
    print("PASS generation rollback is rejected")

    try:
        verify_trust_bundle(
            bundle, roots, expected_generation=0, expected_predecessor_digest="f" * 64,
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "predecessor fork" in str(error)
    else:
        raise AssertionError("trust-bundle predecessor fork was accepted")
    print("PASS predecessor fork is rejected")

    bad_signature = copy.deepcopy(bundle)
    bad_signature["rootSignature"] = "A" * 86
    try:
        verify_trust_bundle(
            bad_signature, roots, expected_generation=0, expected_predecessor_digest=ZERO_DIGEST,
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "root signature" in str(error)
    else:
        raise AssertionError("invalid root signature was accepted")
    print("PASS invalid root signatures are rejected")

    tampered = copy.deepcopy(bundle)
    tampered["body"]["trustDomainId"] = "attacker-domain"
    try:
        verify_trust_bundle(
            tampered, roots, expected_generation=0, expected_predecessor_digest=ZERO_DIGEST,
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "digest mismatch" in str(error)
    else:
        raise AssertionError("tampered root-signed trust bundle was accepted")
    print("PASS root signature binds the entire trust-bundle body")

    revoked_body = build_body(keys)
    revoked_body["revocations"] = [{
        "keyId": keys[0]["keyId"], "revokedAt": "2026-11-10T00:00:00Z",
        "reason": "synthetic compromised-key fixture",
    }]
    try:
        verify_trust_bundle(
            sign_bundle(revoked_body, root_key), roots,
            expected_generation=0, expected_predecessor_digest=ZERO_DIGEST,
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "is revoked" in str(error)
    else:
        raise AssertionError("revoked manifest signing key was accepted")
    print("PASS root-signed revocation list is enforced")

    expired_keys = copy.deepcopy(keys)
    expired_keys[0]["notAfter"] = "2026-11-01T00:00:00Z"
    try:
        verify_trust_bundle(
            sign_bundle(build_body(expired_keys), root_key), roots,
            expected_generation=0, expected_predecessor_digest=ZERO_DIGEST,
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "outside root-trusted key validity" in str(error)
    else:
        raise AssertionError("manifest signed outside key validity was accepted")
    print("PASS signer validity window is enforced")

    wrong_role = copy.deepcopy(keys)
    wrong_role[0]["role"] = "INDEPENDENT_VERIFIER"
    try:
        verify_trust_bundle(
            sign_bundle(build_body(wrong_role), root_key), roots,
            expected_generation=0, expected_predecessor_digest=ZERO_DIGEST,
            expected_trust_domain_id="sky-high-cloudtrail-production",
            manifest=manifest, verification_time=VERIFY_AT,
        )
    except ValueError as error:
        assert "role is not authorized" in str(error)
    else:
        raise AssertionError("role-substituted signing key was accepted")
    print("PASS role substitution is rejected")

    print("Root-signed manifest trust-bundle tests passed; root and signing keys were synthetic.")


if __name__ == "__main__":
    main()
