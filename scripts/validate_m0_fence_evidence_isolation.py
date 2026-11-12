#!/usr/bin/env python3
"""Validate FENCE-001 evidence-storage privilege-bypass and independence attestations.

This validator checks a structured attestation. It does not authenticate provider
audit logs or prove that a claimed denial actually occurred; those raw records
must be independently verified and included in the dual-signed evidence manifest.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-fence-evidence-isolation-v1.schema.json"
FIXTURE_PATH = ROOT / "docs/test-vectors/fence-evidence-isolation-v1.json"
ACTIONS = {
    "DELETE_AS_OBJECT_OWNER": "storageAdmin",
    "SHORTEN_RETENTION_AS_OBJECT_OWNER": "storageAdmin",
    "DELETE_AS_ACCOUNT_OWNER": "accountOwner",
    "DISABLE_OBJECT_LOCK_AS_ORG_ADMIN": "organizationAdmin",
    "DELETE_VIA_RECOVERY_ADMIN": "recoveryAdmin",
    "OVERWRITE_EXACT_VERSION": "storageAdmin",
    "REPLACE_VERSION_MAPPING": "recoveryAdmin",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_attestation(document: dict[str, Any]) -> list[str]:
    from jsonschema import Draft202012Validator, FormatChecker

    schema = load_json(SCHEMA_PATH)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ValueError("; ".join(f"{'.'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors))

    if document["testOnly"]:
        raise ValueError("test-only isolation attestation is not eligible for external qualification")

    topology = document["topology"]
    domains = [topology["storage"], topology["collector"], topology["verifier"], *topology["monitors"]]
    for field in ("accountId", "administrativeBoundaryId", "deploymentControlPlaneId", "failureDomainId", "principalId"):
        values = [item[field] for item in domains]
        if len(values) != len(set(values)):
            raise ValueError(f"independence violation: {field} must be distinct across storage, collector, verifier and both monitors")
    if len({item["organizationId"] for item in domains}) != len(domains):
        raise ValueError("independence violation: organizationId must be distinct across all five operating domains")

    if topology["storage"]["accountId"] != document["providerScope"]["storageAccountId"]:
        raise ValueError("provider storage account does not match the topology's storage account")

    privileged = document["privilegedPrincipals"]
    privileged_ids = list(privileged.values())
    if len(privileged_ids) != len(set(privileged_ids)):
        raise ValueError("privileged role principals must be distinct")
    trusted_ids = {item["principalId"] for item in domains}
    if trusted_ids.intersection(privileged_ids):
        raise ValueError("collector, verifier, monitor or storage service principal overlaps a privileged bypass principal")

    verifier_id = topology["verifier"]["principalId"]
    if topology["collector"]["principalId"] == verifier_id:
        raise ValueError("collector and independent verifier must be distinct")
    target = document["targetObject"]
    seen_actions: set[str] = set()
    seen_events: set[str] = set()
    for attempt in document["bypassAttempts"]:
        action = attempt["action"]
        if action in seen_actions:
            raise ValueError(f"duplicate privileged bypass action: {action}")
        seen_actions.add(action)
        expected_role = ACTIONS[action]
        if attempt["actorPrincipalId"] != privileged[expected_role]:
            raise ValueError(f"{action}: attempt was not executed by the designated {expected_role} principal")
        if attempt["auditAcquiredByPrincipalId"] != verifier_id:
            raise ValueError(f"{action}: provider audit event was not acquired by the independent verifier")
        if attempt["auditEventId"] in seen_events:
            raise ValueError(f"{action}: audit event ID is reused")
        seen_events.add(attempt["auditEventId"])
    missing = set(ACTIONS) - seen_actions
    if missing:
        raise ValueError(f"missing privileged bypass attempts: {', '.join(sorted(missing))}")
    return sorted(seen_actions)


def run_fixture_tests() -> tuple[int, int]:
    fixture = load_json(FIXTURE_PATH)
    positive = dict(fixture)
    positive["testOnly"] = False
    validated = validate_attestation(positive)
    negatives = 0

    def reject(mutator, expected: str) -> None:
        nonlocal negatives
        candidate = json.loads(json.dumps(positive))
        mutator(candidate)
        try:
            validate_attestation(candidate)
        except (ValueError, KeyError) as error:
            if expected not in str(error):
                raise AssertionError(f"wrong rejection: {error}") from error
            negatives += 1
        else:
            raise AssertionError(f"invalid attestation accepted; expected {expected}")

    reject(lambda d: d["topology"]["verifier"].update(accountId=d["topology"]["storage"]["accountId"]), "accountId must be distinct")
    reject(lambda d: d["topology"]["monitors"][1].update(failureDomainId=d["topology"]["monitors"][0]["failureDomainId"]), "failureDomainId must be distinct")
    reject(lambda d: d["bypassAttempts"][0].update(result="ALLOWED"), "DENIED")
    reject(lambda d: d["bypassAttempts"][0].update(actorPrincipalId="collector-principal"), "designated storageAdmin")
    reject(lambda d: d["bypassAttempts"][0].update(auditAcquiredByPrincipalId="collector-principal"), "independent verifier")
    reject(lambda d: d["bypassAttempts"].pop(), "missing privileged bypass attempts")
    reject(lambda d: d["privilegedPrincipals"].update(accountOwner=d["topology"]["verifier"]["principalId"]), "overlaps a privileged bypass principal")
    return len(validated), negatives


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", type=Path, help="provider isolation and privileged-bypass attestation JSON")
    args = parser.parse_args()
    if args.attestation:
        document = load_json(args.attestation)
        actions = validate_attestation(document)
        print(f"FENCE-001 external evidence isolation attestation: PASS ({len(actions)} bypass controls)")
        print("Scope: structure and declared topology only; independently verify provider audit records and source identities")
        return

    count, rejected = run_fixture_tests()
    print("FENCE-001 evidence isolation validator: PASS")
    print(f"Privileged bypass actions validated: {count}")
    print(f"Negative cases rejected: {rejected}")
    print("Scope: synthetic fixture only; no provider account, administrator or object-lock behavior is proven")


if __name__ == "__main__":
    main()
