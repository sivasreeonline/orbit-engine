#!/usr/bin/env python3
"""Guarded provider-side FENCE-001 restore/recovery qualification harness.

External mode restores only into a provider-confirmed disposable qualification
target. It never authorizes host admission or execution and never writes the
source authority database.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

OPT_IN = "I_UNDERSTAND_THIS_RUN_RESTORES_A_DISPOSABLE_QUALIFICATION_TARGET"
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class HighWater:
    generation: int
    digest: str


@dataclass(frozen=True)
class Checkpoint:
    generation: int
    digest: str
    previous_digest: str
    artifact_id: str


@dataclass(frozen=True)
class MonitorHead:
    monitor_id: str
    operator_id: str
    account_id: str
    failure_domain: str
    generation: int
    digest: str


@dataclass(frozen=True)
class SourceSnapshot:
    snapshot_id: str
    source_environment: str
    immutable: bool
    generation: int
    digest: str
    state_bytes: bytes


@dataclass(frozen=True)
class RestoreTarget:
    target_id: str
    account_id: str
    qualification_run_id: str
    disposable: bool
    isolated_from_source: bool


@dataclass(frozen=True)
class RecoveryBundle:
    witness: HighWater
    checkpoints: tuple[Checkpoint, ...]
    latest_read_status: str
    consistency_proof_status: str
    checkpoint_chain_verified: bool
    trust_generation: int
    protected_trust_generation: int
    trust_chain_verified: bool
    revocation_generation: int
    protected_revocation_generation: int
    revocation_state_available: bool
    revocation_chain_status: str
    monitors: tuple[MonitorHead, ...]


@dataclass(frozen=True)
class RestoreResult:
    target_id: str
    source_snapshot_id: str
    applied_generations: tuple[int, ...]
    restored_generation: int
    restored_digest: str
    admission_enabled: bool


class ProviderRestoreAdapter(Protocol):
    def describe_qualification_scope(self) -> dict[str, Any]: ...
    def read_source_snapshot(self, snapshot_id: str, *, reader_principal_id: str) -> SourceSnapshot: ...
    def create_disposable_restore_target(self, run_id: str) -> RestoreTarget: ...
    def fetch_verified_recovery_bundle(
        self, snapshot: SourceSnapshot, *, witness_reader_principal_id: str,
        independent_verifier_principal_id: str
    ) -> RecoveryBundle: ...
    def restore_and_replay(
        self, target: RestoreTarget, snapshot: SourceSnapshot,
        bundle: RecoveryBundle, *, restore_operator_principal_id: str
    ) -> RestoreResult: ...
    def read_restored_high_water(
        self, target: RestoreTarget, *, independent_verifier_principal_id: str
    ) -> HighWater: ...
    def read_latest_witness(
        self, *, witness_reader_principal_id: str
    ) -> tuple[HighWater, str]: ...
    def read_monitor_heads(
        self, *, independent_verifier_principal_id: str
    ) -> tuple[MonitorHead, ...]: ...


def valid_digest(value: str) -> bool:
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("approval expiry must include timezone")
    return parsed.astimezone(timezone.utc)


def preflight(scope: dict[str, Any], expected_account: str, run_id: str) -> None:
    required = {
        "account_id", "environment", "production", "disposable_account",
        "source_is_read_only", "restore_approval_id", "approved_run_id",
        "approval_expires_at", "source_reader_principal_id",
        "restore_operator_principal_id", "witness_reader_principal_id",
        "independent_verifier_principal_id",
    }
    missing = required - scope.keys()
    if missing:
        raise ValueError(f"qualification scope missing fields: {', '.join(sorted(missing))}")
    if scope["account_id"] != expected_account:
        raise ValueError("qualification account does not match pinned account ID")
    if scope["environment"] != "QUALIFICATION" or scope["production"] is not False:
        raise ValueError("restore target is not explicitly non-production QUALIFICATION")
    if scope["disposable_account"] is not True or scope["source_is_read_only"] is not True:
        raise ValueError("provider has not confirmed disposable account and read-only source boundary")
    if not isinstance(scope["restore_approval_id"], str) or not scope["restore_approval_id"].strip():
        raise ValueError("provider restore approval ID is missing")
    if scope["approved_run_id"] != run_id:
        raise ValueError("provider restore approval is not bound to this qualification run ID")
    if utc(scope["approval_expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("provider restore approval is expired")
    principals = [
        scope["source_reader_principal_id"], scope["restore_operator_principal_id"],
        scope["witness_reader_principal_id"], scope["independent_verifier_principal_id"],
    ]
    if any(not isinstance(value, str) or not value.strip() for value in principals):
        raise ValueError("all source, restore, witness and verifier principals must be non-empty")
    if len(set(principals)) != len(principals):
        raise ValueError("source reader, restore operator, witness reader and verifier must be distinct")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,79}", run_id):
        raise ValueError("qualification run ID must be 8-80 safe ASCII characters")


def validate_bundle(snapshot: SourceSnapshot, bundle: RecoveryBundle) -> None:
    if bundle.latest_read_status != "VERIFIED":
        raise ValueError("strongly consistent witness latest read is missing, stale or unverified")
    if not valid_digest(bundle.witness.digest) or type(bundle.witness.generation) is not int:
        raise ValueError("witness high-water is malformed")
    if bundle.witness.generation < snapshot.generation:
        raise ValueError("witness is behind source snapshot generation: rollback detected")
    if bundle.witness.generation == snapshot.generation:
        if bundle.witness.digest != snapshot.digest or bundle.checkpoints:
            raise ValueError("same-generation source and witness disagree or unexpected recovery checkpoints exist")
        if bundle.consistency_proof_status not in ("VERIFIED", "NOT_REQUIRED"):
            raise ValueError("same-generation consistency proof state is invalid")
    else:
        if bundle.consistency_proof_status != "VERIFIED":
            raise ValueError("protected source-to-witness consistency proof is not verified")
        expected_generation = snapshot.generation + 1
        predecessor = snapshot.digest
        if len(bundle.checkpoints) != bundle.witness.generation - snapshot.generation:
            raise ValueError("recovery checkpoint chain is incomplete or contains extra entries")
        for checkpoint in bundle.checkpoints:
            if (
                type(checkpoint.generation) is not int
                or checkpoint.generation != expected_generation
                or not valid_digest(checkpoint.digest)
                or not valid_digest(checkpoint.previous_digest)
                or checkpoint.previous_digest != predecessor
                or not checkpoint.artifact_id.strip()
            ):
                raise ValueError("recovery chain has a gap, malformed digest or predecessor fork")
            expected_generation += 1
            predecessor = checkpoint.digest
        if expected_generation - 1 != bundle.witness.generation or predecessor != bundle.witness.digest:
            raise ValueError("recovery chain does not terminate at exact witness high-water")
    if not bundle.checkpoint_chain_verified:
        raise ValueError("checkpoint signatures/artifacts were not independently verified")
    if bundle.trust_generation < bundle.protected_trust_generation:
        raise ValueError("trust-bundle generation rollback detected")
    if bundle.trust_generation > bundle.protected_trust_generation and not bundle.trust_chain_verified:
        raise ValueError("trust-bundle successor chain is not verified")
    if not bundle.revocation_state_available:
        raise ValueError("fresh revocation state is unavailable")
    if bundle.revocation_generation < bundle.protected_revocation_generation:
        raise ValueError("revocation generation rollback detected")
    if bundle.revocation_generation > bundle.protected_revocation_generation:
        if bundle.revocation_chain_status != "VERIFIED":
            raise ValueError("revocation successor chain is missing or invalid")
    elif bundle.revocation_chain_status not in ("VERIFIED", "NOT_REQUIRED"):
        raise ValueError("unexpected revocation-chain state")
    if len(bundle.monitors) < 2:
        raise ValueError("fewer than two independent monitor observations")
    dimensions = (
        [m.monitor_id for m in bundle.monitors],
        [m.operator_id for m in bundle.monitors],
        [m.account_id for m in bundle.monitors],
        [m.failure_domain for m in bundle.monitors],
    )
    if any(len(set(values)) != len(values) for values in dimensions):
        raise ValueError("monitor identities, operators, accounts and failure domains are not independent")
    for monitor in bundle.monitors:
        if (
            not all(isinstance(v, str) and v.strip() for v in
                    (monitor.monitor_id, monitor.operator_id, monitor.account_id, monitor.failure_domain))
            or monitor.generation != bundle.witness.generation
            or monitor.digest != bundle.witness.digest
            or not valid_digest(monitor.digest)
        ):
            raise ValueError("monitor head is malformed, stale, ahead or conflicts with witness high-water")


def run_external(adapter: ProviderRestoreAdapter, expected_account: str, run_id: str, snapshot_id: str) -> dict[str, Any]:
    scope = adapter.describe_qualification_scope()
    preflight(scope, expected_account, run_id)
    source_reader = scope["source_reader_principal_id"]
    restore_operator = scope["restore_operator_principal_id"]
    witness_reader = scope["witness_reader_principal_id"]
    verifier = scope["independent_verifier_principal_id"]

    snapshot = adapter.read_source_snapshot(snapshot_id, reader_principal_id=source_reader)
    if (
        snapshot.snapshot_id != snapshot_id
        or snapshot.source_environment != "QUALIFICATION"
        or snapshot.immutable is not True
        or type(snapshot.generation) is not int
        or snapshot.generation < 0
        or not valid_digest(snapshot.digest)
        or not isinstance(snapshot.state_bytes, bytes)
        or hashlib.sha256(snapshot.state_bytes).hexdigest() != snapshot.digest
    ):
        raise ValueError("source snapshot is not an immutable, digest-verified qualification snapshot")

    target = adapter.create_disposable_restore_target(run_id)
    if (
        target.account_id != expected_account
        or target.qualification_run_id != run_id
        or target.disposable is not True
        or target.isolated_from_source is not True
        or not target.target_id
    ):
        raise ValueError("provider restore target is not disposable, isolated and run-bound")

    bundle = adapter.fetch_verified_recovery_bundle(
        snapshot, witness_reader_principal_id=witness_reader,
        independent_verifier_principal_id=verifier
    )
    validate_bundle(snapshot, bundle)

    result = adapter.restore_and_replay(
        target, snapshot, bundle, restore_operator_principal_id=restore_operator
    )
    if (
        result.target_id != target.target_id
        or result.source_snapshot_id != snapshot.snapshot_id
        or result.restored_generation != bundle.witness.generation
        or result.restored_digest != bundle.witness.digest
        or result.admission_enabled is not False
    ):
        raise ValueError("restore receipt does not match target, source, witness or admission-closed requirement")
    expected_applied = tuple(c.generation for c in bundle.checkpoints)
    if result.applied_generations != expected_applied:
        raise ValueError("restore receipt applied generation list does not match exact verified chain")

    restored = adapter.read_restored_high_water(target, independent_verifier_principal_id=verifier)
    if restored != bundle.witness:
        raise ValueError("independent restored-target readback does not match witness high-water")
    latest, latest_status = adapter.read_latest_witness(witness_reader_principal_id=witness_reader)
    if latest_status != "VERIFIED" or latest != bundle.witness:
        raise ValueError("post-restore strong witness readback is stale, unavailable or changed")
    monitors = adapter.read_monitor_heads(independent_verifier_principal_id=verifier)
    if monitors != bundle.monitors:
        raise ValueError("post-restore independent monitor observations changed or are inconsistent")

    return {
        "profile": "sky-high-fence-provider-restore-recovery-run-v1",
        "qualificationRunId": run_id,
        "providerAccountId": expected_account,
        "sourceSnapshot": {
            "snapshotId": snapshot.snapshot_id,
            "generation": snapshot.generation,
            "digest": snapshot.digest,
            "immutable": snapshot.immutable,
        },
        "restoreTarget": asdict(target),
        "witnessHighWater": asdict(bundle.witness),
        "appliedGenerations": list(result.applied_generations),
        "independentRestoredReadback": asdict(restored),
        "postRestoreWitnessReadback": asdict(latest),
        "monitorHeads": [asdict(m) for m in monitors],
        "admissionEnabled": False,
        "qualificationStatus": "RESTORE_REPLAY_AND_INDEPENDENT_READBACK_VERIFIED",
        "limitations": [
            "Adapter declarations and reported proof statuses require independent provider-native authentication.",
            "This run does not prove production restore safety, provider durability or monitor administrative independence.",
            "Output is not a dual-signed evidence manifest and does not authorize host admission or execution.",
        ],
    }


class FixtureAdapter:
    def __init__(self, scenario: str = "success") -> None:
        self.scenario = scenario
        self.state = b"fixture-authority-state-generation-5"
        self.digest = hashlib.sha256(self.state).hexdigest()
        self.final_digest = "a" * 64
        self.scope = {
            "account_id": "fixture-qualification-account",
            "environment": "QUALIFICATION",
            "production": False,
            "disposable_account": True,
            "source_is_read_only": True,
            "restore_approval_id": "fixture-restore-approval-001",
            "approved_run_id": "fixture-run-0001",
            "approval_expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "source_reader_principal_id": "fixture-source-reader",
            "restore_operator_principal_id": "fixture-restore-operator",
            "witness_reader_principal_id": "fixture-witness-reader",
            "independent_verifier_principal_id": "fixture-verifier",
        }
        self.target = RestoreTarget("fixture-target-001", self.scope["account_id"],
                                    "fixture-run-0001", True, True)
        self.witness = HighWater(7, self.final_digest)
        self.monitors = (
            MonitorHead("monitor-a", "operator-a", "account-a", "domain-a", 7, self.final_digest),
            MonitorHead("monitor-b", "operator-b", "account-b", "domain-b", 7, self.final_digest),
        )
        self.bundle = RecoveryBundle(
            self.witness,
            (Checkpoint(6, "6" * 64, self.digest, "checkpoint-006"),
             Checkpoint(7, self.final_digest, "6" * 64, "checkpoint-007")),
            "VERIFIED", "VERIFIED", True, 4, 4, True, 8, 8, True, "NOT_REQUIRED", self.monitors
        )

    def describe_qualification_scope(self):
        return self.scope

    def read_source_snapshot(self, snapshot_id: str, *, reader_principal_id: str):
        return SourceSnapshot(snapshot_id, "QUALIFICATION", True, 5, self.digest, self.state)

    def create_disposable_restore_target(self, run_id: str):
        return self.target

    def fetch_verified_recovery_bundle(self, snapshot, *, witness_reader_principal_id, independent_verifier_principal_id):
        if self.scenario == "stale":
            return replace(self.bundle, latest_read_status="STALE")
        if self.scenario == "rollback":
            return replace(self.bundle, witness=HighWater(4, "4" * 64))
        if self.scenario == "fork":
            bad = (self.bundle.checkpoints[0], Checkpoint(7, self.final_digest, "f" * 64, "checkpoint-007"))
            return replace(self.bundle, checkpoints=bad)
        if self.scenario == "monitor-lag":
            stale = (self.monitors[0], MonitorHead("monitor-b", "operator-b", "account-b", "domain-b", 6, "6" * 64))
            return replace(self.bundle, monitors=stale)
        return self.bundle

    def restore_and_replay(self, target, snapshot, bundle, *, restore_operator_principal_id):
        return RestoreResult(target.target_id, snapshot.snapshot_id, (6, 7), 7, self.final_digest, False)

    def read_restored_high_water(self, target, *, independent_verifier_principal_id):
        return self.witness

    def read_latest_witness(self, *, witness_reader_principal_id):
        return self.witness, "VERIFIED"

    def read_monitor_heads(self, *, independent_verifier_principal_id):
        return self.monitors


def self_test() -> None:
    adapter = FixtureAdapter()
    preflight(adapter.scope, adapter.scope["account_id"], "fixture-run-0001")
    report = run_external(adapter, adapter.scope["account_id"], "fixture-run-0001", "fixture-snapshot-005")
    assert report["qualificationStatus"] == "RESTORE_REPLAY_AND_INDEPENDENT_READBACK_VERIFIED"
    assert report["admissionEnabled"] is False
    for scenario, fragment in (
        ("stale", "stale or unverified"),
        ("rollback", "behind source snapshot"),
        ("fork", "predecessor fork"),
        ("monitor-lag", "stale, ahead or conflicts"),
    ):
        try:
            bad = FixtureAdapter(scenario)
            run_external(bad, bad.scope["account_id"], "fixture-run-0001", "fixture-snapshot-005")
        except ValueError as error:
            if fragment not in str(error):
                raise AssertionError(f"{scenario}: unexpected rejection: {error}") from error
        else:
            raise AssertionError(f"{scenario}: unsafe recovery bundle was accepted")

    for changes, fragment in (
        ({"production": True}, "non-production"),
        ({"source_is_read_only": False}, "read-only source"),
        ({"approved_run_id": "different-run-0001"}, "not bound"),
    ):
        bad = FixtureAdapter()
        bad.scope.update(changes)
        try:
            preflight(bad.scope, bad.scope["account_id"], "fixture-run-0001")
        except ValueError as error:
            if fragment not in str(error):
                raise AssertionError(f"preflight: unexpected rejection: {error}") from error
        else:
            raise AssertionError("unsafe restore preflight was accepted")
    print("FENCE-001 provider restore/recovery harness: PASS")
    print("Scenarios: successful isolated replay plus stale read, rollback, chain fork, monitor lag and unsafe preflight")
    print("Synthetic only: no provider restore or production database operation was performed")


def factory(target: str):
    module, separator, attribute = target.partition(":")
    if not separator:
        raise SystemExit("FENCE_PROVIDER_RESTORE_FACTORY must use module.path:factory_name")
    value = getattr(importlib.import_module(module), attribute, None)
    if not callable(value):
        raise SystemExit("configured provider restore factory is not callable")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--snapshot-id")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if os.environ.get("FENCE_ENABLE_PROVIDER_RESTORE_TESTS") != OPT_IN:
        raise SystemExit("refusing provider restore: explicit disposable-target opt-in is required")
    account = os.environ.get("FENCE_EXPECTED_QUALIFICATION_ACCOUNT_ID", "")
    run_id = os.environ.get("FENCE_QUALIFICATION_RUN_ID", "")
    factory_name = os.environ.get("FENCE_PROVIDER_RESTORE_FACTORY", "")
    if not account or not run_id or not factory_name or not args.snapshot_id:
        raise SystemExit("external mode requires pinned account, run ID, provider factory and --snapshot-id")
    adapter = factory(factory_name)()
    report = run_external(adapter, account, run_id, args.snapshot_id)
    output = Path(os.environ.get("FENCE_RESTORE_REPORT_PATH", "fence-restore-recovery-run.json"))
    if output.exists():
        raise SystemExit("refusing to overwrite an existing restore report")
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS isolated restore/replay, independent target readback and post-restore witness/monitor checks")
    print(f"Report: {output.resolve()}")
    print("Admission remains disabled; independent evidence packaging and review remain mandatory")


if __name__ == "__main__":
    main()
