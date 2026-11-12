#!/usr/bin/env python3
"""Fail-closed reconciliation of one externally executed FENCE-001 qualification run."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROFILE = "sky-high-fence-external-qualification-plan-v1"
STAGES = ("witness", "evidence_object_store", "privileged_bypass", "restore_recovery", "audit_provenance")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class PlanError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise PlanError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot load plan: {exc}") from exc
    require(isinstance(data, dict), "plan root must be an object")
    return data


def parse_expiry(value: Any) -> datetime:
    require(isinstance(value, str) and value.strip(), "approval expiry missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanError("approval expiry must be ISO-8601 with timezone") from exc
    require(parsed.tzinfo is not None, "approval expiry must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_plan(plan: dict[str, Any], evidence_root: Path, *, now: datetime | None = None) -> dict[str, Any]:
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
    require(parse_expiry(run.get("approvalExpiresAt")) > now, "qualification approval is expired")
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
        pin_name = stage_pin.get(stage)
        if pin_name:
            require(record.get("provider") == pins[pin_name]["provider"],
                    f"stage {stage} provider differs from pinned provider")
        else:
            require(isinstance(record.get("provider"), str) and record["provider"].strip(),
                    "audit provenance provider identity missing")
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

    external = plan.get("externalAttestations")
    require(isinstance(external, dict), "external attestation inventory missing")
    for name in ("providerApproval", "independentVerifier", "evidenceStoreRetention"):
        item = external.get(name)
        require(isinstance(item, dict) and item.get("verified") is True, f"{name} is not independently verified")
        require(item.get("runId") == run_id and item.get("accountId") == account_id,
                f"{name} is not bound to this run and account")
        artifact, digest, count = item.get("evidenceArtifact"), item.get("sha256"), item.get("byteCount")
        require(isinstance(artifact, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,200}", artifact),
                f"{name} evidence reference missing or unsafe")
        require(SHA256.fullmatch(digest or "") is not None, f"{name} evidence digest malformed")
        require(type(count) is int and count > 0, f"{name} evidence byte count invalid")
        path = (root / artifact).resolve()
        require(path.parent == root, f"{name} evidence path escapes evidence root")
        require(path not in used_paths, f"{name} reuses another evidence artifact")
        used_paths.add(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PlanError(f"{name} attestation evidence missing") from exc
        require(len(raw) == count and hashlib.sha256(raw).hexdigest() == digest,
                f"{name} attestation evidence byte binding mismatch")

    require(isinstance(plan.get("limitations"), list) and plan["limitations"],
            "qualification limitations must be explicit")
    review = plan.get("independentReviewStatus")
    require(review in {"NOT_STARTED", "PENDING"}, "orchestrator cannot complete independent review")

    return {
        "profile": PROFILE, "runId": run_id, "accountId": account_id,
        "stageCount": len(STAGES), "stages": checked,
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
        attestations: dict[str, Any] = {}
        for name in STAGES + ("providerApproval", "independentVerifierAttestation", "evidenceStoreRetention"):
            raw = f"synthetic:{name}".encode()
            filename = f"{name}.evidence"
            (root / filename).write_bytes(raw)
            bound = {"artifact": filename, "sha256": hashlib.sha256(raw).hexdigest(), "byteCount": len(raw)}
            if name in STAGES:
                stages[name] = {
                    **bound, "status": "PASS", "runId": "run-fixture-001",
                    "accountId": "account-fixture", "provider": "provider-fixture",
                }
            else:
                attestations[{
                    "providerApproval": "providerApproval",
                    "independentVerifierAttestation": "independentVerifier",
                    "evidenceStoreRetention": "evidenceStoreRetention",
                }[name]] = {
                    **bound, "verified": True, "runId": "run-fixture-001", "accountId": "account-fixture",
                }
        plan = {
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
            "stages": stages, "externalAttestations": attestations,
            "limitations": ["Synthetic fixtures only; no provider truth is asserted."],
            "independentReviewStatus": "PENDING",
        }
        fixed_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        result = validate_plan(plan, root, now=fixed_now)
        require(result["result"] == "READY_FOR_INDEPENDENT_REVIEW", "valid plan rejected")
        require(result["productionApproval"] is False, "approval state changed")
        negative = (
            ("missing stage", lambda p: p["stages"].pop("audit_provenance")),
            ("cross-run", lambda p: p["stages"]["witness"].update({"runId": "other-run"})),
            ("cross-account", lambda p: p["stages"]["restore_recovery"].update({"accountId": "other-account"})),
            ("production scope", lambda p: p["run"].update({"production": True})),
            ("admission enabled", lambda p: p["run"].update({"admissionEnabled": True})),
            ("identity collision", lambda p: p["identities"].update({"independentVerifier": p["identities"]["collector"]})),
            ("approval substitution", lambda p: p["run"].update({"approvalRunId": "other-run"})),
            ("missing attestation", lambda p: p["externalAttestations"].update({"providerApproval": {"verified": False}})),
            ("expired approval", lambda p: p["run"].update({"approvalExpiresAt": "2000-01-01T00:00:00Z"})),
            ("provider mismatch", lambda p: p["stages"]["witness"].update({"provider": "other-provider"})),
        )
        for label, mutate in negative:
            candidate = copy.deepcopy(plan)
            mutate(candidate)
            try:
                validate_plan(candidate, root, now=fixed_now)
            except PlanError:
                continue
            raise AssertionError(f"fail-closed test accepted: {label}")
        candidate = copy.deepcopy(plan)
        candidate["stages"]["evidence_object_store"]["sha256"] = "0" * 64
        try:
            validate_plan(candidate, root, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("tampered evidence digest accepted")
        (root / "witness.evidence").write_bytes(b"tampered")
        try:
            validate_plan(plan, root, now=fixed_now)
        except PlanError:
            pass
        else:
            raise AssertionError("tampered materialized evidence bytes accepted")
        print("FENCE-001 external qualification orchestrator: PASS (1 positive + 12 fail-closed checks)")
        print("Synthetic only: no provider calls, credentials, destructive tests or production approval.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.plan or not args.evidence_root or not args.output:
        parser.error("--plan, --evidence-root and --output are required outside --self-test")
    result = validate_plan(load_json(args.plan), args.evidence_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise SystemExit("refusing to overwrite existing qualification summary")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    print("This is local evidence reconciliation, not provider qualification or production approval.")


if __name__ == "__main__":
    main()
