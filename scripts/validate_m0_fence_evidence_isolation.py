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
    seen_audit_artifacts: set[str] = set()
    for attempt in document["bypassAttempts"]:
        action = attempt["action"]
        if action in seen_actions:
            raise ValueError(f"duplicate privileged bypass action: {action}")
        seen_actions.add(action)
        expected_role = ACTIONS[action]
        if attempt["objectRef"] != target["objectRef"] or attempt["versionId"] != target["versionId"]:
            raise ValueError(f"{action}: attempt does not target the exact retained object version")
        if attempt["actorPrincipalId"] != privileged[expected_role]:
            raise ValueError(f"{action}: attempt was not executed by the designated {expected_role} principal")
        if attempt["auditAcquiredByPrincipalId"] != verifier_id:
            raise ValueError(f"{action}: provider audit event was not acquired by the independent verifier")
        if attempt["auditEventId"] in seen_events:
            raise ValueError(f"{action}: audit event ID is reused")
        seen_events.add(attempt["auditEventId"])
        if attempt["auditArtifactId"] in seen_audit_artifacts:
            raise ValueError(f"{action}: audit artifact ID is reused")
        seen_audit_artifacts.add(attempt["auditArtifactId"])
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
    reject(lambda d: d["bypassAttempts"][0].update(objectRef="synthetic://different-object"), "exact retained object version")
    reject(lambda d: d["bypassAttempts"][1].update(auditEventId=d["bypassAttempts"][0]["auditEventId"]), "audit event ID is reused")
    reject(lambda d: d["bypassAttempts"][1].update(auditArtifactId=d["bypassAttempts"][0]["auditArtifactId"]), "audit artifact ID is reused")
    reject(lambda d: d["topology"]["monitors"][0].update(organizationId=d["topology"]["storage"]["organizationId"]), "organizationId must be distinct")
    reject(lambda d: d["bypassAttempts"].pop(), "is too short")
    reject(lambda d: d["privilegedPrincipals"].update(accountOwner=d["topology"]["verifier"]["principalId"]), "overlaps a privileged bypass principal")
    return len(validated), negatives


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", type=Path, help="provider isolation and privileged-bypass attestation JSON")
    parser.add_argument("--manifest", type=Path, help="dual-signed evidence manifest")
    parser.add_argument("--trusted-keys", type=Path, help="independently governed trusted-key configuration")
    parser.add_argument("--artifact-root", type=Path, help="directory containing materialized manifest artifacts")
    args = parser.parse_args()
    supplied = (args.attestation, args.manifest, args.trusted_keys, args.artifact_root)
    if any(supplied) and not all(supplied):
        parser.error("--attestation, --manifest, --trusted-keys and --artifact-root must be supplied together")
    if all(supplied):
        from validate_m0_fence_evidence_manifest import validate_manifest
        from verify_m0_fence_evidence_artifact_bytes import verify_artifact_files

        document = load_json(args.attestation)
        actions = validate_attestation(document)
        envelope = load_json(args.manifest)
        trust = load_json(args.trusted_keys)
        if not isinstance(trust.get("keys"), list):
            raise SystemExit("trusted-key document must contain a keys array")
        validate_manifest(envelope, trust["keys"], allow_test_only=False)
        body = envelope["manifestBody"]
        scope = body["providerScope"]
        attested_scope = document["providerScope"]
        for source, target_field in (("name", "name"), ("service", "service"), ("region", "region"), ("account", "storageAccountId")):
            if scope[source] != attested_scope[target_field]:
                raise ValueError(f"evidence manifest provider scope mismatch: {source}")
        matches = [item for item in body["artifacts"] if item["artifactType"] == "INDEPENDENCE_ATTESTATION" and {"WIT-012", "WIT-014"}.issubset(set(item["testIds"]))]
        if len(matches) != 1:
            raise ValueError("manifest must contain exactly one INDEPENDENCE_ATTESTATION artifact covering WIT-012 and WIT-014")
        artifact = matches[0]
        topology = document["topology"]
        domain_entries = [("storage", topology["storage"]), ("collector", topology["collector"]), ("verifier", topology["verifier"]), ("monitor-a", topology["monitors"][0]), ("monitor-b", topology["monitors"][1])]
        identity_artifact_ids = [entry["identityEvidenceArtifactId"] for _, entry in domain_entries]
        if len(identity_artifact_ids) != len(set(identity_artifact_ids)):
            raise ValueError("each operating domain must have a distinct identity evidence artifact")
        for domain_name, domain_entry in domain_entries:
            identity_artifacts = [item for item in body["artifacts"] if item["artifactId"] == domain_entry["identityEvidenceArtifactId"]]
            if len(identity_artifacts) != 1 or identity_artifacts[0]["artifactType"] != "CONFIGURATION_ATTESTATION":
                raise ValueError(f"{domain_name}: manifest must contain one CONFIGURATION_ATTESTATION for domain identity and boundary proof")
            identity_artifact = identity_artifacts[0]
            if identity_artifact["collectorIdentity"] != topology["collector"]["principalId"] or identity_artifact["independentVerifierIdentity"] != topology["verifier"]["principalId"]:
                raise ValueError(f"{domain_name}: identity evidence collector/verifier does not match the isolation topology")
        if artifact["collectorIdentity"] != document["topology"]["collector"]["principalId"]:
            raise ValueError("manifest collector identity does not match the isolation attestation")
        if artifact["independentVerifierIdentity"] != document["topology"]["verifier"]["principalId"]:
            raise ValueError("manifest independent verifier does not match the isolation attestation")
        request_ids = {attempt["providerRequestId"] for attempt in document["bypassAttempts"]}
        for attempt in document["bypassAttempts"]:
            audit_artifacts = [item for item in body["artifacts"] if item["artifactId"] == attempt["auditArtifactId"]]
            if len(audit_artifacts) != 1:
                raise ValueError("manifest must contain exactly one raw audit artifact per privileged attempt")
            audit_artifact = audit_artifacts[0]
            if audit_artifact["artifactType"] not in ("RAW_PROVIDER_EXCHANGE", "CONTRACT_EVIDENCE"):
                raise ValueError("privileged audit artifact has an invalid artifact type")
            if audit_artifact["collectorIdentity"] != document["topology"]["collector"]["principalId"]:
                raise ValueError("raw audit artifact collector identity does not match the isolation topology")
            if audit_artifact["independentVerifierIdentity"] != document["topology"]["verifier"]["principalId"]:
                raise ValueError("raw audit artifact verifier identity does not match the isolation topology")
            if audit_artifact["artifactId"] == artifact["artifactId"]:
                raise ValueError("raw audit artifact cannot reuse the independence attestation artifact")
            if audit_artifact["sha256"] != attempt["auditEventSha256"]:
                raise ValueError("audit-event digest differs from signed manifest")
            if attempt["providerRequestId"] not in audit_artifact["providerRequestIds"]:
                raise ValueError("raw audit artifact does not bind the provider request ID")
        if not request_ids.issubset(set(artifact["providerRequestIds"])):
            raise ValueError("manifest independence artifact does not bind every privileged bypass provider request ID")
        verify_artifact_files(body, args.artifact_root)
        materialized = args.artifact_root / artifact["artifactId"]
        if materialized.read_bytes() != args.attestation.read_bytes():
            raise ValueError("materialized independence attestation differs from supplied attestation file")
        print(f"FENCE-001 external evidence isolation attestation: PASS ({len(actions)} bypass controls)")
        print("Dual-signed manifest: verified; provider scope, collector/verifier identities and request IDs bound")
        artifact_count = len(body["artifacts"])
        print(f"Materialized manifest artifacts byte-verified: {artifact_count}")
        print("Provider audit-event authenticity and account ownership still require independent review")
        return

    count, rejected = run_fixture_tests()
    print("FENCE-001 evidence isolation validator: PASS")
    print(f"Privileged bypass actions validated: {count}")
    print(f"Negative cases rejected: {rejected}")
    print("Scope: synthetic fixture only; no provider account, administrator or object-lock behavior is proven")


if __name__ == "__main__":
    main()
