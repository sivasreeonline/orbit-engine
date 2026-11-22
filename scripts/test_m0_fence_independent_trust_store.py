#!/usr/bin/env python3
"""Synthetic trust-store policy tests using the checked-in FENCE-001 vector."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

from validate_m0_fence_evidence_manifest import load_json
from verify_m0_fence_independent_trust_store import (
    PROFILE,
    verify_manifest_with_trust_store,
)

ROOT = Path(__file__).resolve().parents[1]
VERIFY_AT = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)


def trust_store(keys: list[dict[str, str]]) -> dict:
    return {
        "profile": PROFILE,
        "schemaVersion": 1,
        "storeId": "fixture-independent-trust-store",
        "status": "ACTIVE",
        "approvedBy": "synthetic-trust-governance-test",
        "approvalReference": "FIXTURE-APPROVAL-001",
        "keys": [
            {
                **key,
                "status": "ACTIVE",
                "notBefore": "2026-01-01T00:00:00Z",
                "notAfter": "2027-01-01T00:00:00Z",
                "approvedBy": "synthetic-key-governance-test",
                "approvalReference": f"FIXTURE-KEY-APPROVAL-{index:03d}",
            }
            for index, key in enumerate(keys, start=1)
        ],
    }


def main() -> None:
    vector = load_json(ROOT / "docs/test-vectors/fence-evidence-manifest-v1.json")
    envelope = {k: vector[k] for k in ("manifestBody", "manifestDigest", "attestations")}
    store = trust_store(vector["trustedKeys"])
    digest = verify_manifest_with_trust_store(
        envelope, store, verification_time=VERIFY_AT, allow_test_only=True,
    )
    assert digest == envelope["manifestDigest"]
    print("PASS manifest signatures verify only against separately supplied trust-store keys")

    revoked = copy.deepcopy(store)
    revoked["keys"][0]["status"] = "REVOKED"
    revoked["keys"][0]["revokedAt"] = "2026-11-21T00:00:00Z"
    try:
        verify_manifest_with_trust_store(envelope, revoked, verification_time=VERIFY_AT, allow_test_only=True)
    except ValueError as error:
        assert "revoked" in str(error)
    else:
        raise AssertionError("revoked signing key was accepted")
    print("PASS revoked keys fail closed")

    expired = copy.deepcopy(store)
    expired["keys"][0]["notAfter"] = "2026-01-01T00:00:00Z"
    try:
        verify_manifest_with_trust_store(envelope, expired, verification_time=VERIFY_AT, allow_test_only=True)
    except ValueError as error:
        assert "validity" in str(error)
    else:
        raise AssertionError("signature outside key validity was accepted")
    print("PASS key validity windows are enforced at manifest creation time")

    wrong_role = copy.deepcopy(store)
    wrong_role["keys"][0]["role"] = "INDEPENDENT_VERIFIER"
    try:
        verify_manifest_with_trust_store(envelope, wrong_role, verification_time=VERIFY_AT, allow_test_only=True)
    except ValueError as error:
        assert "role" in str(error)
    else:
        raise AssertionError("wrong-role key authorization was accepted")
    print("PASS role substitution is rejected")

    unapproved = copy.deepcopy(store)
    unapproved["approvalReference"] = ""
    try:
        verify_manifest_with_trust_store(envelope, unapproved, verification_time=VERIFY_AT, allow_test_only=True)
    except ValueError as error:
        assert "approval reference" in str(error)
    else:
        raise AssertionError("trust store without approval reference was accepted")
    print("PASS trust store without accountable approval is rejected")

    tampered = copy.deepcopy(envelope)
    tampered["manifestBody"]["manifestId"] = "modified-after-signing"
    try:
        verify_manifest_with_trust_store(tampered, store, verification_time=VERIFY_AT, allow_test_only=True)
    except ValueError as error:
        assert "digest mismatch" in str(error)
    else:
        raise AssertionError("modified manifest was accepted")

    print("Independent trust-store tests passed; fixture keys are public test vectors only.")


if __name__ == "__main__":
    main()
