#!/usr/bin/env python3
"""Guarded provider-side FENCE-001 privileged-bypass qualification harness.

External mode is intentionally destructive in the sense that it submits privileged
mutation requests. It MUST only target a provider-confirmed disposable qualification
resource in an explicitly approved, isolated account. Never point it at production.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

ACTIONS = {
    "DELETE_AS_OBJECT_OWNER": "storageAdmin",
    "SHORTEN_RETENTION_AS_OBJECT_OWNER": "storageAdmin",
    "DELETE_AS_ACCOUNT_OWNER": "accountOwner",
    "DISABLE_OBJECT_LOCK_AS_ORG_ADMIN": "organizationAdmin",
    "DELETE_VIA_RECOVERY_ADMIN": "recoveryAdmin",
    "OVERWRITE_EXACT_VERSION": "storageAdmin",
    "REPLACE_VERSION_MAPPING": "recoveryAdmin",
}
OPT_IN = "I_UNDERSTAND_THIS_RUN_SUBMITS_PRIVILEGED_MUTATION_REQUESTS"


@dataclass(frozen=True)
class Target:
    account_id: str
    qualification_run_id: str
    disposable: bool
    object_ref: str
    version_id: str
    retention_mode: str
    retention_until: int


@dataclass(frozen=True)
class MutationResult:
    action: str
    outcome: str
    actor_principal_id: str
    provider_request_id: str
    audit_event_id: str
    occurred_at: str
    object_ref: str
    version_id: str


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    provider_request_id: str
    actor_principal_id: str
    outcome: str
    object_ref: str
    version_id: str
    occurred_at: str
    raw_bytes: bytes


class PrivilegedBypassAdapter(Protocol):
    """Provider adapter; credentials must be separately provisioned per role."""

    def describe_qualification_scope(self) -> dict[str, Any]: ...
    def create_disposable_retained_target(self, run_id: str, retention_until: int) -> Target: ...
    def read_exact_version(self, target: Target, *, reader_principal_id: str) -> bytes: ...
    def attempt_privileged_bypass(
        self, action: str, target: Target, *, attempt_id: str
    ) -> MutationResult: ...
    def read_audit_event(self, event_id: str, *, reader_principal_id: str) -> AuditEvent: ...


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include an explicit timezone")
    return parsed.astimezone(timezone.utc)


def validate_preflight(scope: dict[str, Any], expected_account: str, run_id: str) -> None:
    required = {
        "account_id", "environment", "disposable_account", "production",
        "destructive_tests_approved", "approval_id", "approved_run_id", "approval_expires_at", "storage_admin_principal_id",
        "account_owner_principal_id", "organization_admin_principal_id",
        "recovery_admin_principal_id", "independent_verifier_principal_id",
    }
    missing = required - scope.keys()
    if missing:
        raise ValueError(f"preflight scope missing fields: {', '.join(sorted(missing))}")
    if scope["account_id"] != expected_account:
        raise ValueError("provider account does not match FENCE_EXPECTED_QUALIFICATION_ACCOUNT_ID")
    if scope["environment"] != "QUALIFICATION" or scope["production"] is not False:
        raise ValueError("provider environment is not explicitly non-production QUALIFICATION")
    if scope["disposable_account"] is not True:
        raise ValueError("provider has not confirmed a disposable qualification account")
    if scope["destructive_tests_approved"] is not True:
        raise ValueError("provider has not approved privileged mutation qualification tests")
    if parse_time(scope["approval_expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("provider destructive-test approval is expired")
    principals = [
        scope["storage_admin_principal_id"], scope["account_owner_principal_id"],
        scope["organization_admin_principal_id"], scope["recovery_admin_principal_id"],
        scope["independent_verifier_principal_id"],
    ]
    if any(not isinstance(value, str) or not value.strip() for value in principals):
        raise ValueError("all privileged and verifier principal IDs must be non-empty")
    if len(principals) != len(set(principals)):
        raise ValueError("privileged actors and independent verifier must use distinct principals")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,79}", run_id):
        raise ValueError("qualification run ID must be 8-80 safe ASCII characters")


def role_principal(scope: dict[str, Any], role: str) -> str:
    return {
        "storageAdmin": scope["storage_admin_principal_id"],
        "accountOwner": scope["account_owner_principal_id"],
        "organizationAdmin": scope["organization_admin_principal_id"],
        "recoveryAdmin": scope["recovery_admin_principal_id"],
    }[role]


def run_external(adapter: PrivilegedBypassAdapter, expected_account: str, run_id: str, output_dir: Path) -> dict[str, Any]:
    scope = adapter.describe_qualification_scope()
    validate_preflight(scope, expected_account, run_id)
    verifier = scope["independent_verifier_principal_id"]

    # The adapter must create a uniquely labelled, disposable artifact with a
    # retention window long enough to cover the approved qualification session.
    retention_until = int(datetime.now(timezone.utc).timestamp()) + 7 * 24 * 60 * 60
    target = adapter.create_disposable_retained_target(run_id, retention_until)
    if (
        target.account_id != expected_account
        or target.qualification_run_id != run_id
        or target.disposable is not True
        or target.retention_mode != "COMPLIANCE"
        or target.retention_until < retention_until
        or not target.object_ref
        or not target.version_id
    ):
        raise ValueError("adapter-created target failed disposable-account, run-binding or retention preflight")

    before = adapter.read_exact_version(target, reader_principal_id=verifier)
    if not isinstance(before, bytes) or not before:
        raise ValueError("independent verifier could not read non-empty exact-version bytes")
    before_digest = hashlib.sha256(before).hexdigest()
    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []

    for index, (action, role) in enumerate(ACTIONS.items(), start=1):
        attempt_id = f"{run_id}-{index:02d}-{action.lower()}"
        mutation = adapter.attempt_privileged_bypass(action, target, attempt_id=attempt_id)
        expected_actor = role_principal(scope, role)
        if mutation.action != action or mutation.actor_principal_id != expected_actor:
            raise ValueError(f"{action}: provider adapter used the wrong privileged actor or action")
        if mutation.outcome != "DENIED":
            raise ValueError(f"{action}: provider did not deny privileged mutation (outcome={mutation.outcome!r})")
        if not mutation.provider_request_id or not mutation.audit_event_id:
            raise ValueError(f"{action}: provider request ID or audit event ID is missing")
        if mutation.object_ref != target.object_ref or mutation.version_id != target.version_id:
            raise ValueError(f"{action}: mutation response does not bind to the exact retained version")

        event = adapter.read_audit_event(mutation.audit_event_id, reader_principal_id=verifier)
        if event.event_id != mutation.audit_event_id or event.provider_request_id != mutation.provider_request_id:
            raise ValueError(f"{action}: independently read audit event does not bind to provider request")
        if (
            event.actor_principal_id != expected_actor or event.outcome != "DENIED"
            or event.object_ref != target.object_ref or event.version_id != target.version_id
            or event.occurred_at != mutation.occurred_at
        ):
            raise ValueError(f"{action}: independently read audit event fields do not match mutation response")
        if not isinstance(event.raw_bytes, bytes) or not event.raw_bytes:
            raise ValueError(f"{action}: raw provider audit event bytes are missing")
        digest = hashlib.sha256(event.raw_bytes).hexdigest()
        artifact_id = f"audit-{index:02d}-{action.lower()}.bin"
        artifact_path = output_dir / artifact_id
        artifact_path.write_bytes(event.raw_bytes)
        records.append({
            "action": action,
            "actorPrincipalId": expected_actor,
            "result": "DENIED",
            "providerRequestId": mutation.provider_request_id,
            "auditEventId": event.event_id,
            "auditEventSha256": digest,
            "auditAcquiredByPrincipalId": verifier,
            "occurredAt": mutation.occurred_at,
            "objectRef": target.object_ref,
            "versionId": target.version_id,
            "auditArtifactId": artifact_id,
            "artifactPath": str(artifact_path),
            "artifactByteCount": len(event.raw_bytes),
        })

    after = adapter.read_exact_version(target, reader_principal_id=verifier)
    after_digest = hashlib.sha256(after).hexdigest()
    if before_digest != after_digest or before != after:
        raise ValueError("retained exact-version bytes changed during privileged bypass attempts")

    report = {
        "profile": "sky-high-fence-provider-privileged-bypass-run-v1",
        "qualificationRunId": run_id,
        "providerAccountId": expected_account,
        "targetObject": asdict(target),
        "independentVerifierPrincipalId": verifier,
        "beforeSha256": before_digest,
        "afterSha256": after_digest,
        "attempts": records,
        "testOnly": False,
        "qualificationStatus": "PROVIDER_DENIED_ALL_SEVEN_AND_AUDIT_READBACK_VERIFIED",
        "limitations": [
            "This report is raw qualification output, not a dual-signed evidence manifest.",
            "Provider account ownership, role assignment, audit authenticity and independence still require external review.",
            "The adapter's preflight declarations are not themselves proof of provider enforcement.",
        ],
    }
    (output_dir / "provider-privileged-bypass-run.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


class FixtureAdapter:
    """Synthetic adapter used only to test harness control flow; never provider evidence."""

    def __init__(self) -> None:
        self.content = b"synthetic retained evidence"
        self.scope = {
            "account_id": "fixture-qualification-account",
            "environment": "QUALIFICATION",
            "disposable_account": True,
            "production": False,
            "destructive_tests_approved": True,
            "approval_expires_at": "2999-01-01T00:00:00Z",
            "storage_admin_principal_id": "fixture-storage-admin",
            "account_owner_principal_id": "fixture-account-owner",
            "organization_admin_principal_id": "fixture-org-admin",
            "recovery_admin_principal_id": "fixture-recovery-admin",
            "independent_verifier_principal_id": "fixture-independent-verifier",
        }

    def describe_qualification_scope(self) -> dict[str, Any]:
        return self.scope

    def create_disposable_retained_target(self, run_id: str, retention_until: int) -> Target:
        return Target(self.scope["account_id"], run_id, True, f"fixture://{run_id}/object",
                      "fixture-version-001", "COMPLIANCE", retention_until)

    def read_exact_version(self, target: Target, *, reader_principal_id: str) -> bytes:
        assert reader_principal_id == self.scope["independent_verifier_principal_id"]
        return self.content

    def attempt_privileged_bypass(self, action: str, target: Target, *, attempt_id: str) -> MutationResult:
        role = ACTIONS[action]
        actor = role_principal(self.scope, role)
        return MutationResult(action, "DENIED", actor, f"request-{attempt_id}",
                              f"audit-{attempt_id}", "2026-11-12T00:00:00Z",
                              target.object_ref, target.version_id)

    def read_audit_event(self, event_id: str, *, reader_principal_id: str) -> AuditEvent:
        assert reader_principal_id == self.scope["independent_verifier_principal_id"]
        attempt_id = event_id.removeprefix("audit-")
        action = next(action for action in ACTIONS if event_id.endswith(action.lower()))
        role = ACTIONS[action]
        actor = role_principal(self.scope, role)
        request_id = f"request-{attempt_id}"
        target_ref = f"fixture://{attempt_id.split('-')[0]}/object"
        # Fixture matching is verified by the test's custom event builder below.
        raw = json.dumps({"event": event_id, "request": request_id}, sort_keys=True).encode()
        return AuditEvent(event_id, request_id, actor, "DENIED", target_ref,
                          "fixture-version-001", "2026-11-12T00:00:00Z", raw)


def run_fixture_tests() -> None:
    import tempfile

    adapter = FixtureAdapter()
    # Keep the fixture's audit records exactly bound to the created target.
    original_read = adapter.read_audit_event

    def bound_read(event_id: str, *, reader_principal_id: str) -> AuditEvent:
        event = original_read(event_id, reader_principal_id=reader_principal_id)
        target = adapter.create_disposable_retained_target("fixture-run-0001", 1)
        return AuditEvent(event.event_id, event.provider_request_id, event.actor_principal_id,
                          event.outcome, target.object_ref, target.version_id,
                          event.occurred_at, event.raw_bytes)

    adapter.read_audit_event = bound_read  # type: ignore[method-assign]
    validate_preflight(adapter.scope, "fixture-qualification-account", "fixture-run-0001")
    with tempfile.TemporaryDirectory() as temporary:
        report = run_external(adapter, "fixture-qualification-account", "fixture-run-0001", Path(temporary))
        if len(report["attempts"]) != len(ACTIONS) or report["beforeSha256"] != report["afterSha256"]:
            raise AssertionError("fixture did not exercise all seven attempts and byte-preservation check")

    for mutate, expected in (
        ({"production": True}, "non-production"),
        ({"disposable_account": False}, "disposable"),
        ({"destructive_tests_approved": False}, "not approved"),
    ):
        candidate = dict(adapter.scope)
        candidate.update(mutate)
        try:
            validate_preflight(candidate, "fixture-qualification-account", "fixture-run-0001")
        except ValueError as error:
            if expected not in str(error):
                raise AssertionError(f"unexpected preflight rejection: {error}") from error
        else:
            raise AssertionError("unsafe fixture preflight was accepted")


def load_factory(target: str):
    module_name, separator, attribute = target.partition(":")
    if not separator or not module_name or not attribute:
        raise SystemExit("FENCE_PROVIDER_PRIVILEGED_BYPASS_FACTORY must use module.path:factory_name")
    factory = getattr(importlib.import_module(module_name), attribute, None)
    if not callable(factory):
        raise SystemExit("configured provider adapter factory is not callable")
    return factory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run synthetic harness tests only")
    parser.add_argument("--output-dir", type=Path, help="restricted directory for raw provider audit artifacts")
    args = parser.parse_args()

    if args.self_test:
        run_fixture_tests()
        print("PASS provider privileged-bypass harness fixture tests")
        print("SYNTHETIC ONLY: no provider calls or qualification evidence were produced")
        return

    if os.environ.get("FENCE_ENABLE_PRIVILEGED_BYPASS_TESTS") != OPT_IN:
        raise SystemExit("refusing provider calls: explicit FENCE_ENABLE_PRIVILEGED_BYPASS_TESTS opt-in is required")
    expected_account = os.environ.get("FENCE_EXPECTED_QUALIFICATION_ACCOUNT_ID", "")
    run_id = os.environ.get("FENCE_QUALIFICATION_RUN_ID", "")
    factory_target = os.environ.get("FENCE_PROVIDER_PRIVILEGED_BYPASS_FACTORY", "")
    if not expected_account or not run_id or not factory_target or args.output_dir is None:
        raise SystemExit("external mode requires expected account ID, run ID, adapter factory and --output-dir")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit("output directory must be new or empty to prevent evidence overwrite")
    report = run_external(load_factory(factory_target)(), expected_account, run_id, args.output_dir)
    print(f"PASS provider denied all {len(report['attempts'])} privileged mutation attempts")
    print(f"PASS independent audit readback and exact-version byte preservation: {report['afterSha256']}")
    print(f"Evidence output: {args.output_dir.resolve()}")
    print("Independent provider/account/role authentication and dual-signed manifest review remain mandatory")


if __name__ == "__main__":
    main()
