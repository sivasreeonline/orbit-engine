#!/usr/bin/env python3
"""Run the FENCE-001 audit custody and final qualification gates as one fail-closed command.

This orchestrates existing independent validators. It does not collect provider
evidence, establish provider truth, approve production, or authorize host admission.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def validate_review_ready_record(record: dict[str, Any]) -> None:
    if record.get("qualificationStatus") != "READY_FOR_INDEPENDENT_REVIEW":
        raise ValueError("final custody gate requires qualificationStatus READY_FOR_INDEPENDENT_REVIEW")
    if record.get("productionApproval") is not False:
        raise ValueError("productionApproval must remain false")
    tests = record.get("tests")
    expected = {f"WIT-{number:03d}" for number in range(1, 15)}
    if not isinstance(tests, list) or {item.get("id") for item in tests} != expected:
        raise ValueError("qualification record must contain WIT-001 through WIT-014 exactly")
    if any(item.get("status") != "PASS" for item in tests):
        raise ValueError("all 14 mandatory qualification controls must be PASS before review readiness")


def run(command: list[str], label: str) -> None:
    print(f"\n== {label} ==")
    subprocess.run(command, cwd=ROOT, check=True)


def self_test() -> None:
    """Run the actual end-to-end command against a fully synthetic signed package."""
    import base64
    import copy
    import hashlib
    import tempfile

    import rfc8785
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    template_path = ROOT / "docs/templates/m0-fence-witness-qualification-record.json"
    template = load_object(template_path)
    try:
        validate_review_ready_record(template)
    except ValueError:
        pass
    else:
        raise AssertionError("NOT_STARTED template unexpectedly passed final review-ready gate")

    ready = json.loads(json.dumps(template))
    ready["qualificationStatus"] = "READY_FOR_INDEPENDENT_REVIEW"
    for item in ready["tests"]:
        item["status"] = "PASS"
    validate_review_ready_record(ready)

    production = json.loads(json.dumps(ready))
    production["productionApproval"] = True
    try:
        validate_review_ready_record(production)
    except ValueError:
        pass
    else:
        raise AssertionError("production approval was accepted by the final custody gate")

    vector = load_object(ROOT / "docs/test-vectors/fence-evidence-manifest-v1.json")
    provider = {
        "name": "fixture-provider", "account": "qualification-account",
        "region": "fixture-region", "service": "audit-service",
        "contractReference": "fixture-contract-only",
    }
    adapter = copy.deepcopy(vector["manifestBody"]["adapter"])
    provider_identity = {
        "provider": provider["name"], "accountId": provider["account"],
        "region": provider["region"], "service": provider["service"],
    }
    provider_scope = "|".join((
        provider["name"], provider["account"], provider["region"],
        provider["service"], adapter["commit"],
    ))
    acquired_at = "2026-11-12T00:00:00Z"

    def make_key(role: str, identity: str):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        key_id = hashlib.sha256(public).hexdigest()
        trusted = {
            "keyId": key_id, "identity": identity, "role": role,
            "publicKeyBase64Url": base64.urlsafe_b64encode(public).decode("ascii").rstrip("="),
        }
        seed = private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        signer = {
            "role": role, "identity": identity, "keyId": key_id,
            "privateKeyBase64Url": base64.urlsafe_b64encode(seed).decode("ascii").rstrip("="),
        }
        return private, trusted, signer

    collector_private, collector_trust, collector_signer = make_key("COLLECTOR", "collector-fixture")
    verifier_private, verifier_trust, verifier_signer = make_key("INDEPENDENT_VERIFIER", "verifier-fixture")
    trusted_keys = [collector_trust, verifier_trust]

    with tempfile.TemporaryDirectory(prefix="fence-e2e-custody-") as temporary:
        root = Path(temporary)
        artifact_root = root / "artifacts"
        artifact_root.mkdir()
        manifest_body = copy.deepcopy(vector["manifestBody"])
        manifest_body["testOnly"] = False
        manifest_body["providerScope"] = {
            "name": provider["name"], "account": provider["account"],
            "region": provider["region"], "service": provider["service"],
        }
        manifest_body["adapter"] = adapter
        manifest_body["artifacts"] = []
        evidence_by_test = {}

        def add_artifact(artifact_id: str, data: bytes, test_ids: list[str], request_ids: list[str]):
            (artifact_root / artifact_id).write_bytes(data)
            artifact = copy.deepcopy(vector["manifestBody"]["artifacts"][0])
            artifact.update({
                "artifactId": artifact_id,
                "testIds": test_ids,
                "artifactType": "RAW_PROVIDER_EXCHANGE",
                "objectRef": f"fixture://evidence/{artifact_id}",
                "objectVersion": "immutable-v1",
                "sha256": hashlib.sha256(data).hexdigest(),
                "byteCount": len(data),
                "acquiredAt": acquired_at,
                "collectorIdentity": "collector-fixture",
                "collectorKeyId": collector_trust["keyId"],
                "independentVerifierIdentity": "verifier-fixture",
                "verifierKeyId": verifier_trust["keyId"],
                "providerRequestIds": request_ids,
                "redaction": "NONE",
            })
            manifest_body["artifacts"].append(artifact)
            return {
                "objectRef": artifact["objectRef"],
                "objectVersion": artifact["objectVersion"],
                "sha256": artifact["sha256"],
                "byteCount": artifact["byteCount"],
                "acquiredAt": artifact["acquiredAt"],
                "acquisitionMethod": "synthetic integration fixture",
                "collectorIdentity": artifact["collectorIdentity"],
                "independentVerifierIdentity": artifact["independentVerifierIdentity"],
                "providerScope": provider_scope,
                "redaction": artifact["redaction"],
            }

        record = load_object(template_path)
        record.update({
            "recordId": "fixture-e2e-custody-001",
            "qualificationStatus": "READY_FOR_INDEPENDENT_REVIEW",
            "provider": provider,
            "adapter": adapter,
            "monitors": {
                "identities": [
                    {"monitorId": "monitor-a", "operator": "operator-a", "account": "account-a", "failureDomain": "domain-a"},
                    {"monitorId": "monitor-b", "operator": "operator-b", "account": "account-b", "failureDomain": "domain-b"},
                ],
                "independenceEvidence": [],
            },
            "independentSecurityReviewer": {
                "identity": "independent-reviewer-fixture",
                "organization": "fixture-security-organization",
            },
            "productionApproval": False,
        })

        for number, item in enumerate(record["tests"], start=1):
            test_id = item["id"]
            evidence = add_artifact(
                f"qualification-{number:03d}.bin",
                f"synthetic evidence bytes for {test_id}\n".encode("utf-8"),
                [test_id],
                [f"request-{test_id.lower()}"],
            )
            item["status"] = "PASS"
            item["evidence"] = [evidence]
            evidence_by_test[test_id] = evidence
        record["monitors"]["independenceEvidence"] = [evidence_by_test["WIT-014"]]

        page_bytes = b"synthetic authenticated audit page"
        auth_bytes = b"synthetic audit authentication evidence"
        event_bytes = b"synthetic audit event for request-001"
        page_evidence = add_artifact("audit-page-0001.bin", page_bytes, ["WIT-012", "WIT-014"], ["request-001"])
        auth_evidence = add_artifact("audit-auth-0001.bin", auth_bytes, ["WIT-012", "WIT-014"], ["request-001"])
        event_evidence = add_artifact("audit-event-0001.bin", event_bytes, ["WIT-012", "WIT-014"], ["request-001"])

        manifest_digest = hashlib.sha256(rfc8785.dumps(manifest_body)).hexdigest()
        manifest_prefix = b"SKYHIGH-FENCE-001-EVIDENCE-MANIFEST-V1\x00"
        attestations = []
        for role, identity, private, trusted in (
            ("COLLECTOR", "collector-fixture", collector_private, collector_trust),
            ("INDEPENDENT_VERIFIER", "verifier-fixture", verifier_private, verifier_trust),
        ):
            payload = manifest_prefix + rfc8785.dumps({
                "manifestDigest": manifest_digest, "role": role,
                "signerIdentity": identity, "keyId": trusted["keyId"],
            })
            attestations.append({
                "role": role, "signerIdentity": identity, "keyId": trusted["keyId"],
                "signatureBase64Url": base64.urlsafe_b64encode(private.sign(payload)).decode("ascii").rstrip("="),
            })
        manifest = {
            "manifestBody": manifest_body,
            "manifestDigest": manifest_digest,
            "attestations": attestations,
        }
        record["evidenceManifest"] = {
            "manifestId": manifest_body["manifestId"],
            "objectRef": "fixture://manifests/e2e-custody",
            "objectVersion": "immutable-v1",
            "sha256": manifest_digest,
        }

        report = {
            "profile": "sky-high-fence-provider-audit-provenance-v1",
            "testOnly": False,
            "providerIdentity": provider_identity,
            "independentVerifierPrincipalId": "verifier-fixture",
            "qualificationStatus": "AUDIT_STREAM_AUTHENTICATED_AND_REQUESTS_CORRELATED",
            "pages": [{
                "rawResponseArtifact": "audit-page-0001.bin",
                "rawResponseSha256": hashlib.sha256(page_bytes).hexdigest(),
                "rawResponseByteCount": len(page_bytes),
                "authenticationEvidenceArtifact": "audit-auth-0001.bin",
                "authenticationEvidenceSha256": hashlib.sha256(auth_bytes).hexdigest(),
                "authenticationEvidenceByteCount": len(auth_bytes),
            }],
            "events": [{
                "artifact": "audit-event-0001.bin",
                "sha256": hashlib.sha256(event_bytes).hexdigest(),
                "byteCount": len(event_bytes),
                "providerRequestId": "request-001",
            }],
        }
        mappings = [
            {"sourceGroup": "pages", "sourceArtifact": "audit-page-0001.bin", "manifestArtifactId": "audit-page-0001"},
            {"sourceGroup": "authenticationEvidence", "sourceArtifact": "audit-auth-0001.bin", "manifestArtifactId": "audit-auth-0001"},
            {"sourceGroup": "events", "sourceArtifact": "audit-event-0001.bin", "manifestArtifactId": "audit-event-0001"},
        ]

        def write_json(path: Path, value: Any) -> None:
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        manifest_path = root / "manifest.json"
        manifest_keys_path = root / "manifest-trusted-keys.json"
        report_path = root / "audit-report.json"
        mapping_path = root / "audit-mapping.json"
        binding_keys_path = root / "binding-trusted-keys.json"
        collector_key_path = root / "collector-key.json"
        verifier_key_path = root / "verifier-key.json"
        binding_path = root / "audit-binding.json"
        record_path = root / "qualification-record.json"
        write_json(manifest_path, manifest)
        write_json(manifest_keys_path, {"keys": trusted_keys})
        write_json(report_path, report)
        write_json(mapping_path, mappings)
        write_json(binding_keys_path, {"keys": trusted_keys})
        write_json(collector_key_path, collector_signer)
        write_json(verifier_key_path, verifier_signer)
        write_json(record_path, record)

        run([
            sys.executable, str(SCRIPTS / "create_m0_fence_audit_provenance_binding.py"),
            "--manifest", str(manifest_path),
            "--manifest-trusted-keys", str(manifest_keys_path),
            "--audit-report", str(report_path),
            "--mapping-file", str(mapping_path),
            "--binding-trusted-keys", str(binding_keys_path),
            "--collector-signing-key", str(collector_key_path),
            "--verifier-signing-key", str(verifier_key_path),
            "--output", str(binding_path),
        ], "Generate ephemeral dual-attested audit provenance binding")

        command = [
            sys.executable, str(Path(__file__).resolve()),
            "--record", str(record_path),
            "--manifest", str(manifest_path),
            "--manifest-trusted-keys", str(manifest_keys_path),
            "--audit-report", str(report_path),
            "--audit-binding", str(binding_path),
            "--binding-trusted-keys", str(binding_keys_path),
            "--artifact-root", str(artifact_root),
        ]
        run(command, "Run complete end-to-end evidence custody reconciliation")

        # Prove the orchestrator fails at both custody layers, not just preflight.
        audit_event_path = artifact_root / "audit-event-0001"
        audit_event_path.write_bytes(event_bytes + b"tamper")
        rejected_audit = subprocess.run(
            command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        audit_event_path.write_bytes(event_bytes)
        if rejected_audit.returncode == 0 or "materialized manifest artifact bytes" not in rejected_audit.stdout:
            raise AssertionError("end-to-end gate did not reject tampered audit evidence bytes")

        qualification_path = artifact_root / "qualification-001.bin"
        original_qualification_bytes = qualification_path.read_bytes()
        qualification_path.write_bytes(original_qualification_bytes + b"tamper")
        rejected_qualification = subprocess.run(
            command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        qualification_path.write_bytes(original_qualification_bytes)
        if rejected_qualification.returncode == 0 or "SHA-256 mismatch" not in rejected_qualification.stdout:
            raise AssertionError("end-to-end gate did not reject tampered qualification evidence bytes")

    print("FENCE-001 end-to-end custody integration self-test passed")
    print("Positive path: 14-control qualification record + dual-signed manifest + audit binding + all materialized bytes")
    print("Negative paths rejected: production approval, audit artifact tampering, qualification artifact tampering")
    print("Scope: synthetic fixtures only; no provider calls, external trust roots or production authorization")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--record", type=Path, help="final qualification record")
    parser.add_argument("--manifest", type=Path, help="dual-signed evidence manifest")
    parser.add_argument("--manifest-trusted-keys", type=Path, help="independently provisioned manifest trust keys")
    parser.add_argument("--audit-report", type=Path, help="provider audit provenance report")
    parser.add_argument("--audit-binding", type=Path, help="dual-attested audit provenance binding")
    parser.add_argument("--binding-trusted-keys", type=Path, help="independently provisioned binding trust keys")
    parser.add_argument("--artifact-root", type=Path, help="directory of materialized files named by manifest artifactId")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    required = (
        args.record, args.manifest, args.manifest_trusted_keys, args.audit_report,
        args.audit_binding, args.binding_trusted_keys, args.artifact_root,
    )
    if any(value is None for value in required):
        parser.error("external mode requires --record, --manifest, --manifest-trusted-keys, --audit-report, --audit-binding, --binding-trusted-keys and --artifact-root")

    record = load_object(args.record)
    validate_review_ready_record(record)

    common = [
        "--manifest", str(args.manifest),
        "--manifest-trusted-keys", str(args.manifest_trusted_keys),
        "--audit-report", str(args.audit_report),
        "--binding-trusted-keys", str(args.binding_trusted_keys),
        "--artifact-root", str(args.artifact_root),
    ]
    run([
        sys.executable, str(SCRIPTS / "validate_m0_fence_audit_provenance_manifest_binding.py"),
        *common, "--binding", str(args.audit_binding),
    ], "Dual-signature audit provenance, manifest mapping and materialized-byte verification")

    run([
        sys.executable, str(SCRIPTS / "validate_m0_fence_witness_qualification.py"),
        "--record", str(args.record),
        "--evidence-manifest", str(args.manifest),
        "--trusted-keys", str(args.manifest_trusted_keys),
        "--artifact-root", str(args.artifact_root),
    ], "Final WIT-001–WIT-014 qualification-record and evidence-manifest reconciliation")

    print("\nFENCE-001 end-to-end evidence custody: PASS")
    print("Meaning: supplied signed artifacts, audit provenance binding, materialized bytes and review-ready record are internally consistent.")
    print("Not established: provider truth/completeness, remote immutability, trust-root governance, monitor independence or independent security approval.")
    print("productionApproval remains false; this command does not authorize host admission or execution.")


if __name__ == "__main__":
    main()
