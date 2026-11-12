#!/usr/bin/env python3
"""Cryptographically reconcile one externally executed FENCE-001 qualification run."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator, FormatChecker

PROFILE = "sky-high-fence-external-qualification-plan-v2"
TRUST_KEY_PROFILE = "sky-high-fence-external-qualification-trust-keys-v1"
ATTESTATION_PROFILE = "sky-high-fence-external-qualification-attestation-v1"
ATTESTATION_DOMAIN = b"SKYHIGH-FENCE-001-EXTERNAL-QUALIFICATION-ATTESTATION-V1\x00"
STAGES = ("witness", "evidence_object_store", "privileged_bypass", "restore_recovery", "audit_provenance")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"
PLAN_SCHEMA_PATH = SCHEMA_ROOT / "fence-001-external-qualification-plan-v2.schema.json"
TRUST_SCHEMA_PATH = SCHEMA_ROOT / "fence-001-external-qualification-trust-keys-v1.schema.json"
EXPECTED_ATTESTATIONS = {
    "providerApproval": ("PROVIDER_APPROVAL_AUTHORITY", "PROVIDER_APPROVAL"),
    "independentVerifier": ("INDEPENDENT_VERIFIER", "INDEPENDENT_VERIFIER"),
    "evidenceStoreRetention": ("EVIDENCE_RETENTION_AUTHORITY", "EVIDENCE_STORE_RETENTION"),
}
MAX_ISSUED_AT_FUTURE_SKEW = timedelta(minutes=2)


class PlanError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise PlanError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot load JSON input {path}: {exc}") from exc
    require(isinstance(data, dict), "JSON input root must be an object")
    return data


def validate_document_schema(document: dict[str, Any], schema_path: Path, label: str) -> None:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot load {label} schema: {exc}") from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise PlanError(f"{label} schema violation at {location}: {error.message}")


def parse_timestamp(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and value.strip(), f"{label} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanError(f"{label} must be ISO-8601 with timezone") from exc
    require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical_json(value: Any, label: str) -> bytes:
    try:
        return rfc8785.dumps(value)
    except Exception as exc:
        raise PlanError(f"{label} cannot be canonicalized as RFC 8785 JSON") from exc


def decode_base64url(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None,
            f"{label} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise PlanError(f"{label} is malformed base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    require(canonical == value, f"{label} is not canonical base64url")
    return decoded


def validate_trust_keys(trust_document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate_document_schema(trust_document, TRUST_SCHEMA_PATH, "qualification trust-key inventory")
    require(trust_document.get("profile") == TRUST_KEY_PROFILE, "unsupported trust-key inventory profile")
    records = trust_document.get("keys")
    require(isinstance(records, list) and len(records) == len(EXPECTED_ATTESTATIONS),
            "trust-key inventory must contain exactly three role keys")
    trusted: dict[str, dict[str, Any]] = {}
    signer_ids: set[str] = set()
    key_ids: set[str] = set()
    public_key_bytes: set[bytes] = set()
    for record in records:
        role = record["role"]
        require(role in EXPECTED_ATTESTATIONS.values()[0] if False else role in {
            item[0] for item in EXPECTED_ATTESTATIONS.values()
        }, "trust-key role is not authorized")
        require(role not in trusted, "duplicate trust-key role")
        signer = record["signerIdentity"]
        key_id = record["keyId"]
        require(signer not in signer_ids, "attestation trust roles must have distinct signer identities")
        require(key_id not in key_ids, "attestation trust roles must have distinct key IDs")
        raw_public = decode_base64url(record["publicKeyBase64Url"], "Ed25519 public key")
        require(len(raw_public) == 32, "Ed25519 public key must be exactly 32 bytes")
        require(hashlib.sha256(raw_public).hexdigest() == record["publicKeySha256"],
                "trust-key public-key fingerprint mismatch")
        require(raw_public not in public_key_bytes, "attestation trust roles must use distinct public keys")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(raw_public)
        except ValueError as exc:
            raise PlanError("invalid Ed25519 public key") from exc
        trusted[role] = {"record": record, "publicKey": public_key, "publicBytes": raw_public}
        signer_ids.add(signer)
        key_ids.add(key_id)
        public_key_bytes.add(raw_public)
    require(set(trusted) == {item[0] for item in EXPECTED_ATTESTATIONS.values()},
            "trust-key inventory does not cover every mandatory attestation role")
    return trusted


def qualification_scope_digest(plan: dict[str, Any]) -> str:
    scope = {
        "run": plan["run"],
        "identities": plan["identities"],
        "providerPins": plan["providerPins"],
    }
    return hashlib.sha256(canonical_json(scope, "qualification scope")).hexdigest()


def verify_external_attestations(
    plan: dict[str, Any],
    evidence_root: Path,
    trusted_keys: dict[str, dict[str, Any]],
    now: datetime,
    used_paths: set[Path],
) -> dict[str, str]:
    run = plan["run"]
    approval_expiry = parse_timestamp(run["approvalExpiresAt"], "qualification approval expiry")
    expected_scope_digest = qualification_scope_digest(plan)
    signers: dict[str, str] = {}
    evidence_root = evidence_root.resolve()

    for name, (expected_role, expected_type) in EXPECTED_ATTESTATIONS.items():
        item = plan["externalAttestations"][name]
        envelope = item["envelope"]
        require(envelope["profile"] == ATTESTATION_PROFILE, f"{name} attestation profile is unsupported")
        require(envelope["role"] == expected_role, f"{name} attestation role mismatch")
        trusted = trusted_keys[expected_role]
        key_record = trusted["record"]
        require(envelope["signerIdentity"] == key_record["signerIdentity"],
                f"{name} signer identity is not independently pinned")
        require(envelope["keyId"] == key_record["keyId"], f"{name} signing key ID is not pinned")
        if name == "independentVerifier":
            require(envelope["signerIdentity"] == plan["identities"]["independentVerifier"],
                    "independent-verifier attestation signer differs from the pinned verifier principal")

        body = envelope["body"]
        require(body["attestationType"] == expected_type, f"{name} attestation type mismatch")
        require(body["runId"] == run["runId"], f"{name} attestation belongs to another run")
        require(body["accountId"] == run["accountId"], f"{name} attestation belongs to another account")
        require(body["approvalId"] == run["approvalId"], f"{name} attestation approval ID mismatch")
        require(body["scopeSha256"] == expected_scope_digest, f"{name} attestation qualification scope digest mismatch")

        issued_at = parse_timestamp(body["issuedAt"], f"{name} issuedAt")
        expires_at = parse_timestamp(body["expiresAt"], f"{name} expiresAt")
        require(issued_at <= now + MAX_ISSUED_AT_FUTURE_SKEW, f"{name} attestation issue time is in the future")
        require(expires_at > now, f"{name} attestation has expired")
        require(expires_at <= approval_expiry, f"{name} attestation outlives the qualification approval")
        if name == "providerApproval":
            require(expires_at == approval_expiry,
                    "provider approval attestation expiry must equal the qualification approval expiry")

        artifact = body["evidenceArtifact"]
        digest = body["evidenceSha256"]
        byte_count = body["evidenceByteCount"]
        require(SHA256.fullmatch(digest) is not None, f"{name} evidence digest is malformed")
        require(type(byte_count) is int and byte_count > 0, f"{name} evidence byte count is invalid")
        path = (evidence_root / artifact).resolve()
        require(path.parent == evidence_root, f"{name} evidence path escapes evidence root")
        require(path not in used_paths, f"{name} reuses another evidence artifact")
        used_paths.add(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PlanError(f"{name} signed evidence artifact is missing") from exc
        require(len(raw) == byte_count, f"{name} signed evidence byte count mismatch")
        require(hashlib.sha256(raw).hexdigest() == digest, f"{name} signed evidence digest mismatch")

        signature = decode_base64url(envelope["signatureBase64Url"], f"{name} Ed25519 signature")
        require(len(signature) == 64, f"{name} Ed25519 signature must be exactly 64 bytes")
        signed_bytes = ATTESTATION_DOMAIN + canonical_json(body, f"{name} attestation body")
        try:
            trusted["publicKey"].verify(signature, signed_bytes)
        except InvalidSignature as exc:
            raise PlanError(f"{name} Ed25519 attestation signature verification failed") from exc
        signers[name] = envelope["signerIdentity"]

    return signers


def validate_plan_schema(plan: dict[str, Any]) -> None:
    validate_document_schema(plan, PLAN_SCHEMA_PATH, "qualification plan")


def validate_plan(
    plan: dict[str, Any],
    evidence_root: Path,
    trust_document: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    validate_plan_schema(plan)
    trusted_keys = validate_trust_keys(trust_document)
    now = now or datetime.now(timezone.utc)
    require(plan.get("profile") == PROFILE, "unsupported qualification plan profile")
    require(plan.get("testOnly") is False, "test-only plan cannot qualify external evidence")
    require(plan.get("productionApproval") is False, "productionApproval must remain explicitly false")

    run = plan.get("run")
    require(isinstance(run, dict), "run scope is missing")
    run_id, account_id = run.get("runId"), run.get("accountId")
    require(isinstance(run_id, str) and ID.fullmatch(run_id), "runId missing or unsafe")
    require(isinstance(account_id, str) and ID.fullmatch(account_id), "accountId missing or unsafe")
    require(isinstance(run.get("approvalId"), str) and ID.fullmatch(run["approvalId"]), "approvalId missing")
    require(parse_timestamp(run.get("approvalExpiresAt"), "qualification approval expiry") > now,
            "qualification approval is expired")
    require(run.get("environment") == "QUALIFICATION", "environment must be QUALIFICATION")
    require(run.get("production") is False, "production scope is forbidden")
    require(run.get("disposable") is True, "account must be explicitly disposable")
    require(run.get("sourceReadOnly") is True, "source boundary must be read-only")
    require(run.get("approvalRunId") == run_id, "approval is not bound to this run")
    require(run.get("operatorPinned") is True, "provider/account scope is not operator-pinned")
    require(run.get("admissionEnabled") is False, "host admission must remain disabled")

    roles = (
        "storageAdministrator", "accountOwner", "organizationAdministrator",
        "recoveryAdministrator", "sourceReader", "restoreOperator",
        "witnessReader", "collector", "independentVerifier",
    )
    identities = plan.get("identities")
    require(isinstance(identities, dict), "identity inventory missing")
    for role in roles:
        value = identities.get(role)
        require(isinstance(value, str) and ID.fullmatch(value), f"{role} identity missing or malformed")
    require(len({identities[role] for role in roles}) == len(roles),
            "privileged and independent roles must use distinct principals")

    pins = plan.get("providerPins")
    require(isinstance(pins, dict), "provider pins missing")
    for name in ("witness", "evidenceStore", "compute"):
        pin = pins.get(name)
        require(isinstance(pin, dict), f"{name} provider pin missing")
        for field in ("provider", "accountId", "region", "service", "adapterDigest"):
            require(isinstance(pin.get(field), str) and pin[field].strip(), f"{name}.{field} missing")
        require(pin["accountId"] == account_id, f"{name} account differs from qualification account")
        require(SHA256.fullmatch(pin["adapterDigest"]) is not None,
                f"{name} adapterDigest must be lowercase SHA-256")
    require(run.get("computeProvider") == pins["compute"]["provider"],
            "compute provider differs from run scope")

    stage_pin = {
        "witness": "witness",
        "evidence_object_store": "evidenceStore",
        "privileged_bypass": "compute",
        "restore_recovery": "compute",
        "audit_provenance": "compute",
    }
    evidence = plan.get("stages")
    require(isinstance(evidence, dict), "stage evidence map missing")
    checked: dict[str, Any] = {}
    root = evidence_root.resolve()
    used_paths: set[Path] = set()
    for stage in STAGES:
        record = evidence.get(stage)
        require(isinstance(record, dict), f"required stage {stage} missing")
        require(record.get("status") == "PASS", f"stage {stage} did not PASS")
        require(record.get("runId") == run_id, f"stage {stage} belongs to another run")
        require(record.get("accountId") == account_id, f"stage {stage} belongs to another account")
        pin_name = stage_pin[stage]
        require(record.get("provider") == pins[pin_name]["provider"],
                f"stage {stage} provider differs from pinned provider")
        artifact, digest, count = record.get("artifact"), record.get("sha256"), record.get("byteCount")
        require(isinstance(artifact, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,200}", artifact),
                f"stage {stage} artifact name unsafe")
        require(SHA256.fullmatch(digest or "") is not None, f"stage {stage} digest malformed")
        require(type(count) is int and count > 0, f"stage {stage} byte count invalid")
        path = (root / artifact).resolve()
        require(path.parent == root, f"stage {stage} artifact escapes evidence root")
        require(path not in used_paths, f"stage {stage} reuses another stage evidence artifact")
        used_paths.add(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PlanError(f"stage {stage} artifact missing: {artifact}") from exc
        require(len(raw) == count, f"stage {stage} byte count mismatch")
        require(hashlib.sha256(raw).hexdigest() == digest, f"stage {stage} digest mismatch")
        checked[stage] = {"status": "PASS", "artifact": artifact, "sha256": digest, "byteCount": count}

    attestation_signers = verify_external_attestations(plan, root, trusted_keys, now, used_paths)

    require(isinstance(plan.get("limitations"), list) and plan["limitations"],
            "qualification limitations must be explicit")
    review = plan.get("independentReviewStatus")
    require(review in {"NOT_STARTED", "PENDING"}, "orchestrator cannot complete independent review")

    return {
        "profile": PROFILE, "runId": run_id, "accountId": account_id,
        "stageCount": len(STAGES), "stages": checked,
        "attestationSigners": attestation_signers,
        "result": "READY_FOR_INDEPENDENT_REVIEW",
        "independentReviewStatus": review, "productionApproval": False,
        "hostAdmissionEnabled": False, "limitations": plan["limitations"],
    }


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        roles = (
            "storageAdministrator", "accountOwner", "organizationAdministrator",
            "recoveryAdministrator", "sourceReader", "restoreOperator",
            "witnessReader", "collector", "independentVerifier",
        )
        stages: dict[str, Any] = {}
        for name in STAGES:
            raw = f"synthetic-stage:{name}".encode()
            filename = f"{name}.evidence"
            (root / filename).write_bytes(raw)
            stages[name] = {
                "status": "PASS", "runId": "run-fixture-001", "accountId": "account-fixture",
                "provider": "provider-fixture", "artifact": filename,
                "sha256": hashlib.sha256(raw).hexdigest(), "byteCount": len(raw),
            }

        plan: dict[str, Any] = {
            "profile": PROFILE, "testOnly": False, "productionApproval": False,
            "run": {
                "runId": "run-fixture-001", "accountId": "account-fixture",
                "approvalId": "approval-fixture", "approvalExpiresAt": "2099-01-01T00:00:00Z",
                "environment": "QUALIFICATION", "production": False, "disposable": True,
                "sourceReadOnly": True, "approvalRunId": "run-fixture-001",
                "operatorPinned": True, "admissionEnabled": False, "computeProvider": "provider-fixture",
            },
            "identities": {role: f"principal-{i}" for i, role in enumerate(roles)},
            "providerPins": {
                key: {"provider": "provider-fixture", "accountId": "account-fixture",
                      "region": "region-fixture", "service": f"{key}-service",
                      "adapterDigest": hashlib.sha256(key.encode()).hexdigest()}
                for key in ("witness", "evidenceStore", "compute")
            },
            "stages": stages,
            "externalAttestations": {},
            "limitations": ["Synthetic fixtures only; no provider truth is asserted."],
            "independentReviewStatus": "PENDING",
        }
        fixed_now = datetime(2026, 1, 1, tzinfo=timezone.utc)

        role_specs = (
            ("PROVIDER_APPROVAL_AUTHORITY", "provider-approval-authority", "provider-approval-key-01"),
            ("INDEPENDENT_VERIFIER", plan["identities"]["independentVerifier"], "independent-verifier-key-01"),
            ("EVIDENCE_RETENTION_AUTHORITY", "evidence-retention-authority", "evidence-retention-key-01"),
        )
        private_by_role: dict[str, Ed25519PrivateKey] = {}
        trust_keys: dict[str, Any] = {"profile": TRUST_KEY_PROFILE, "keys": []}
        for role, signer, key_id in role_specs:
            private = Ed25519PrivateKey.generate()
            public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            private_by_role[role] = private
            trust_keys["keys"].append({
                "role": role, "signerIdentity": signer, "keyId": key_id,
                "publicKeyBase64Url": base64.urlsafe_b64encode(public_raw).decode("ascii").rstrip("="),
                "publicKeySha256": hashlib.sha256(public_raw).hexdigest(), "status": "ACTIVE",
            })

        scope_digest = qualification_scope_digest(plan)
        attestation_specs = (
            ("providerApproval", "PROVIDER_APPROVAL_AUTHORITY", "PROVIDER_APPROVAL"),
            ("independentVerifier", "INDEPENDENT_VERIFIER", "INDEPENDENT_VERIFIER"),
            ("evidenceStoreRetention", "EVIDENCE_RETENTION_AUTHORITY", "EVIDENCE_STORE_RETENTION"),
        )
        for name, role, attestation_type in attestation_specs:
            raw = f"synthetic-attestation:{name}".encode()
            filename = f"{name}.attestation"
            (root / filename).write_bytes(raw)
            body = {
                "attestationType": attestation_type,
                "runId": plan["run"]["runId"],
                "accountId": plan["run"]["accountId"],
                "approvalId": plan["run"]["approvalId"],
                "issuedAt": "2025-12-31T23:59:00Z",
                "expiresAt": plan["run"]["approvalExpiresAt"],
                "evidenceArtifact": filename,
                "evidenceSha256": hashlib.sha256(raw).hexdigest(),
                "evidenceByteCount": len(raw),
                "scopeSha256": scope_digest,
            }
            signature = private_by_role[role].sign(
                ATTESTATION_DOMAIN + canonical_json(body, f"{name} fixture body")
            )
            signer = next(item["signerIdentity"] for item in trust_keys["keys"] if item["role"] == role)
            key_id = next(item["keyId"] for item in trust_keys["keys"] if item["role"] == role)
            envelope = {
                "profile": ATTESTATION_PROFILE, "role": role,
                "signerIdentity": signer, "keyId": key_id, "body": body,
                "signatureBase64Url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            }
            plan["externalAttestations"][name] = {"envelope": envelope}

        result = validate_plan(plan, root, trust_keys, now=fixed_now)
        require(result["result"] == "READY_FOR_INDEPENDENT_REVIEW", "valid signed plan rejected")
        require(result["productionApproval"] is False, "approval state changed")
        require(set(result["attestationSigners"]) == set(EXPECTED_ATTESTATIONS),
                "not all independent attestation roles were verified")

        negative = (
            ("missing stage", lambda p: p["stages"].pop("audit_provenance")),
            ("cross-run", lambda p: p["stages"]["witness"].update({"runId": "other-run"})),
            ("cross-account", lambda p: p["stages"]["restore_recovery"].update({"accountId": "other-account"})),
            ("production scope", lambda p: p["run"].update({"production": True})),
            ("admission enabled", lambda p: p["run"].update({"admissionEnabled": True})),
            ("identity collision", lambda p: p["identities"].update({"independentVerifier": p["identities"]["collector"]})),
            ("approval substitution", lambda p: p["run"].update({"approvalRunId": "other-run"})),
            ("missing attestation", lambda p: p["externalAttestations"].pop("providerApproval")),
            ("expired approval", lambda p: p["run"].update({"approvalExpiresAt": "2000-01-01T00:00:00Z"})),
            ("provider mismatch", lambda p: p["stages"]["witness"].update({"provider": "other-provider"})),
            ("audit provider mismatch", lambda p: p["stages"]["audit_provenance"].update({"provider": "other-provider"})),
            ("malformed approval expiry", lambda p: p["run"].update({"approvalExpiresAt": "not-a-date"})),
            ("unknown plan property", lambda p: p.update({"unrecognized": True})),
        )
        for label, mutate in negative:
            candidate = copy.deepcopy(plan)
            mutate(candidate)
            try:
                validate_plan(candidate, root, trust_keys, now=fixed_now)
            except PlanError:
                continue
            raise AssertionError(f"fail-closed test accepted: {label}")

        crypto_negative = (
            ("signature tampering", lambda p: p["externalAttestations"]["providerApproval"]["envelope"].update({"signatureBase64Url": "A" * 86})),
            ("untrusted key ID", lambda p: p["externalAttestations"]["providerApproval"]["envelope"].update({"keyId": "untrusted-key"})),
            ("scope substitution", lambda p: p["externalAttestations"]["providerApproval"]["envelope"]["body"].update({"scopeSha256": "0" * 64})),
        )
        for label, mutate in crypto_negative:
            candidate = copy.deepcopy(plan)
            mutate(candidate)
            try:
                validate_plan(candidate, root, trust_keys, now=fixed_now)
            except PlanError:
                continue
            raise AssertionError(f"cryptographic fail-closed test accepted: {label}")

        expired_attestation = copy.deepcopy(plan)
        expired_body = expired_attestation["externalAttestations"]["providerApproval"]["envelope"]["body"]
        expired_body["expiresAt"] = "2000-01-01T00:00:00Z"
        expired_signature = private_by_role["PROVIDER_APPROVAL_AUTHORITY"].sign(
            ATTESTATION_DOMAIN + canonical_json(expired_body, "expired attestation test body")
        )
        expired_attestation["externalAttestations"]["providerApproval"]["envelope"]["signatureBase64Url"] = (
            base64.urlsafe_b64encode(expired_signature).decode("ascii").rstrip("=")
        )
        try:
            validate_plan(expired_attestation, root, trust_keys, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("expired signed attestation accepted")

        bad_fingerprint = copy.deepcopy(trust_keys)
        bad_fingerprint["keys"][0]["publicKeySha256"] = "0" * 64
        try:
            validate_plan(plan, root, bad_fingerprint, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("trust-key fingerprint substitution accepted")

        duplicate_signer = copy.deepcopy(trust_keys)
        duplicate_signer["keys"][1]["signerIdentity"] = duplicate_signer["keys"][0]["signerIdentity"]
        try:
            validate_plan(plan, root, duplicate_signer, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("duplicate attestation signer identity accepted")

        candidate = copy.deepcopy(plan)
        candidate["stages"]["evidence_object_store"]["sha256"] = "0" * 64
        try:
            validate_plan(candidate, root, trust_keys, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("tampered stage evidence digest accepted")

        (root / "witness.evidence").write_bytes(b"tampered-stage")
        try:
            validate_plan(plan, root, trust_keys, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("tampered materialized stage evidence bytes accepted")

        # Restore the stage bytes, then alter the separately signed attestation artifact.
        (root / "witness.evidence").write_bytes(f"synthetic-stage:witness".encode())
        (root / "providerApproval.attestation").write_bytes(b"tampered-attestation")
        try:
            validate_plan(plan, root, trust_keys, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("tampered signed attestation evidence bytes accepted")

        print("FENCE-001 external qualification orchestrator: PASS (1 positive + 22 fail-closed checks)")
        print("Ed25519 signatures verified against an independent trust-key inventory.")
        print("Synthetic only: no provider calls, production keys, destructive tests or production approval.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--trust-keys", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.plan or not args.evidence_root or not args.trust_keys or not args.output:
        parser.error("--plan, --evidence-root, --trust-keys and --output are required outside --self-test")
    trust_document = load_json(args.trust_keys)
    result = validate_plan(load_json(args.plan), args.evidence_root, trust_document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise SystemExit("refusing to overwrite existing qualification summary")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    print("This is cryptographic evidence reconciliation, not provider qualification or production approval.")


if __name__ == "__main__":
    main()
