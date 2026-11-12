#!/usr/bin/env python3
"""Create the dual-attested FENCE-001 audit provenance binding envelope.

Private signing keys are loaded only from operator-provisioned files and are never
written to the output. This command does not upload evidence or authorize production.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rfc8785
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
MAPPING_SCHEMA = ROOT / "docs/schemas/m0-fence-audit-provenance-artifact-mapping-v1.schema.json"
sys.path.insert(0, str(ROOT / "scripts"))
from validate_m0_fence_evidence_manifest import validate_manifest  # noqa: E402
from validate_m0_fence_audit_provenance_manifest_binding import (  # noqa: E402
    sign_binding, validate_audit_report, validate_binding, verify_binding_signatures
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unb64(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("private key must use canonical unpadded base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("private key is not canonical base64url")
    return raw


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_signer(path: Path, expected_role: str, trusted_keys: list[dict[str, str]]):
    value = load_object(path)
    if value.get("role") != expected_role:
        raise ValueError(f"{path}: signer role must be {expected_role}")
    identity = value.get("identity")
    if not isinstance(identity, str) or not identity:
        raise ValueError(f"{path}: signer identity is required")
    raw = unb64(value.get("privateKeyBase64Url", ""))
    if len(raw) != 32:
        raise ValueError(f"{path}: Ed25519 private seed must be exactly 32 bytes")
    private = Ed25519PrivateKey.from_private_bytes(raw)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    key_id = sha(public)
    if value.get("keyId") != key_id:
        raise ValueError(f"{path}: private key fingerprint does not match declared key ID")
    trusted = [item for item in trusted_keys if item.get("keyId") == key_id]
    if len(trusted) != 1 or trusted[0].get("identity") != identity or trusted[0].get("role") != expected_role:
        raise ValueError(f"{path}: signing key is not independently authorized for this identity and role")
    trusted_public = unb64(trusted[0]["publicKeyBase64Url"])
    if trusted_public != public:
        raise ValueError(f"{path}: private key does not match independently trusted public key")
    return expected_role, identity, private


def build_binding(manifest: dict[str, Any], manifest_keys: list[dict[str, str]],
                  report: dict[str, Any], mappings: list[dict[str, str]],
                  binding_keys: list[dict[str, str]], collector_key: Path,
                  verifier_key: Path, *, allow_test_only: bool = False) -> dict[str, Any]:
    manifest_digest = validate_manifest(manifest, manifest_keys, allow_test_only=allow_test_only)
    if report.get("qualificationStatus") != "AUDIT_STREAM_AUTHENTICATED_AND_REQUESTS_CORRELATED":
        raise ValueError("audit provenance report is not complete and authenticated")
    if report.get("testOnly") is not False and not allow_test_only:
        raise ValueError("test-only audit report cannot be signed for external qualification")
    manifest_body = manifest["manifestBody"]
    provider = manifest_body["providerScope"]
    expected_provider = {
        "provider": provider["name"], "accountId": provider["account"],
        "region": provider["region"], "service": provider["service"]
    }
    if report.get("providerIdentity") != expected_provider:
        raise ValueError("audit report provider identity does not match signed evidence manifest")
    manifest_signers = {item["role"]: item["signerIdentity"] for item in manifest["attestations"]}
    verifier_identity = manifest_signers["INDEPENDENT_VERIFIER"]
    if report.get("independentVerifierPrincipalId") != verifier_identity:
        raise ValueError("audit report verifier identity does not match signed evidence manifest")
    validate_audit_report(report, expected_provider, verifier_identity)

    required_sources = []
    for page in report.get("pages", []):
        required_sources.append(("pages", page["rawResponseArtifact"]))
        required_sources.append(("authenticationEvidence", page["authenticationEvidenceArtifact"]))
    for event in report.get("events", []):
        required_sources.append(("events", event["artifact"]))
    mapping_keys = [(item.get("sourceGroup"), item.get("sourceArtifact")) for item in mappings]
    if len(mapping_keys) != len(set(mapping_keys)) or set(mapping_keys) != set(required_sources):
        raise ValueError("mapping file must map every page, authentication artifact and event exactly once")
    manifest_ids = [item.get("manifestArtifactId") for item in mappings]
    if len(manifest_ids) != len(set(manifest_ids)):
        raise ValueError("each source artifact must map to a distinct manifest artifact")

    trusted_collector = load_signer(collector_key, "COLLECTOR", binding_keys)
    trusted_verifier = load_signer(verifier_key, "INDEPENDENT_VERIFIER", binding_keys)
    if trusted_collector[1] == trusted_verifier[1] or trusted_collector[2] == trusted_verifier[2]:
        raise ValueError("collector and independent verifier signing keys/identities must differ")
    if trusted_collector[1] != manifest_signers["COLLECTOR"] or trusted_verifier[1] != verifier_identity:
        raise ValueError("binding signers must be the same collector and independent verifier as the manifest")

    body = {
        "profile": "sky-high-fence-audit-provenance-binding-v1",
        "schemaVersion": 1,
        "manifestDigest": manifest_digest,
        "auditReportSha256": sha(rfc8785.dumps(report)),
        "providerIdentity": expected_provider,
        "independentVerifierIdentity": verifier_identity,
        "artifactMappings": sorted(mappings, key=lambda item: (item["sourceGroup"], item["sourceArtifact"]))
    }
    envelope = sign_binding(body, [trusted_collector, trusted_verifier])
    verify_binding_signatures(envelope, binding_keys)
    return envelope


def self_test() -> None:
    """Exercise the real manifest/report/mapping/signing/verification path with ephemeral keys."""
    import copy
    import tempfile
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    vector = load_object(ROOT / "docs/test-vectors/fence-evidence-manifest-v1.json")

    def key_record(role: str, identity: str):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        key_id = sha(public)
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

    collector_private, collector_trust, collector_signer = key_record("COLLECTOR", "collector-fixture")
    verifier_private, verifier_trust, verifier_signer = key_record("INDEPENDENT_VERIFIER", "verifier-fixture")
    trusted_keys = [collector_trust, verifier_trust]

    provider_identity = {
        "provider": "fixture-provider", "accountId": "qualification-account",
        "region": "fixture-region", "service": "audit-service",
    }
    sources = [
        ("page-001.bin", b"fixture raw audit page", "RAW_PROVIDER_EXCHANGE", []),
        ("auth-001.bin", b"fixture audit authentication proof", "CONTRACT_EVIDENCE", []),
        ("event-001.bin", b"fixture provider audit event", "RAW_PROVIDER_EXCHANGE", ["request-001"]),
    ]

    body = copy.deepcopy(vector["manifestBody"])
    body["testOnly"] = False
    body["providerScope"] = {
        "name": provider_identity["provider"], "account": provider_identity["accountId"],
        "region": provider_identity["region"], "service": provider_identity["service"],
    }
    body["artifacts"] = []
    artifact_ids = []
    with tempfile.TemporaryDirectory(prefix="fence-generator-e2e-") as temporary:
        root = Path(temporary)
        for index, (source_name, data, artifact_type, request_ids) in enumerate(sources, start=1):
            artifact_id = f"audit-fixture-{index}"
            artifact_ids.append(artifact_id)
            (root / artifact_id).write_bytes(data)
            artifact = copy.deepcopy(vector["manifestBody"]["artifacts"][0])
            artifact.update({
                "artifactId": artifact_id,
                "testIds": ["WIT-012", "WIT-014"],
                "artifactType": artifact_type,
                "objectRef": f"fixture://evidence/{index}",
                "objectVersion": "immutable-v1",
                "sha256": sha(data),
                "byteCount": len(data),
                "collectorIdentity": "collector-fixture",
                "collectorKeyId": collector_trust["keyId"],
                "independentVerifierIdentity": "verifier-fixture",
                "verifierKeyId": verifier_trust["keyId"],
                "providerRequestIds": request_ids,
            })
            body["artifacts"].append(artifact)

        manifest_digest = sha(rfc8785.dumps(body))
        manifest_prefix = b"SKYHIGH-FENCE-001-EVIDENCE-MANIFEST-V1\x00"
        manifest_attestations = []
        for role, identity, private, trusted in (
            ("COLLECTOR", "collector-fixture", collector_private, collector_trust),
            ("INDEPENDENT_VERIFIER", "verifier-fixture", verifier_private, verifier_trust),
        ):
            payload = manifest_prefix + rfc8785.dumps({
                "manifestDigest": manifest_digest, "role": role,
                "signerIdentity": identity, "keyId": trusted["keyId"],
            })
            manifest_attestations.append({
                "role": role, "signerIdentity": identity, "keyId": trusted["keyId"],
                "signatureBase64Url": base64.urlsafe_b64encode(private.sign(payload)).decode("ascii").rstrip("="),
            })
        manifest = {
            "manifestBody": body, "manifestDigest": manifest_digest,
            "attestations": manifest_attestations,
        }

        report = {
            "profile": "sky-high-fence-provider-audit-provenance-v1",
            "testOnly": False,
            "providerIdentity": provider_identity,
            "independentVerifierPrincipalId": "verifier-fixture",
            "pinnedTrustRoot": {"id": "fixture-root", "sha256": "a" * 64},
            "initialCursor": "cursor-0",
            "finalCursor": "cursor-1",
            "qualificationStatus": "AUDIT_STREAM_AUTHENTICATED_AND_REQUESTS_CORRELATED",
            "pages": [{
                "page": 1, "cursorStart": "cursor-0", "cursorEnd": "cursor-1",
                "rawResponseArtifact": "page-001.bin",
                "rawResponseSha256": sha(sources[0][1]),
                "rawResponseByteCount": len(sources[0][1]),
                "authenticationEvidenceArtifact": "auth-001.bin",
                "authenticationEvidenceSha256": sha(sources[1][1]),
                "authenticationEvidenceByteCount": len(sources[1][1]),
                "authenticationMethod": "PROVIDER_SIGNED_AUDIT_ENVELOPE",
                "trustRootId": "fixture-root", "trustRootSha256": "a" * 64,
                "authenticatedServicePrincipalId": "audit-service-principal",
            }],
            "events": [{
                "artifact": "event-001.bin", "sha256": sha(sources[2][1]),
                "byteCount": len(sources[2][1]), "providerRequestId": "request-001",
                "eventId": "event-001", "sequence": 1,
            }],
            "eventCount": 1,
            "limitations": ["Synthetic fixture; no provider truth is asserted."],
        }
        mappings = [
            {"sourceGroup": "pages", "sourceArtifact": "page-001.bin", "manifestArtifactId": artifact_ids[0]},
            {"sourceGroup": "authenticationEvidence", "sourceArtifact": "auth-001.bin", "manifestArtifactId": artifact_ids[1]},
            {"sourceGroup": "events", "sourceArtifact": "event-001.bin", "manifestArtifactId": artifact_ids[2]},
        ]
        collector_path = root / "collector-signing-key.json"
        verifier_path = root / "verifier-signing-key.json"
        collector_path.write_text(json.dumps(collector_signer), encoding="utf-8")
        verifier_path.write_text(json.dumps(verifier_signer), encoding="utf-8")

        envelope = build_binding(
            manifest, trusted_keys, report, mappings, trusted_keys,
            collector_path, verifier_path,
        )
        validate_binding(
            manifest, trusted_keys, report, envelope, trusted_keys, root,
        )

        wrong_report = copy.deepcopy(report)
        wrong_report["providerIdentity"]["accountId"] = "substituted-account"
        try:
            build_binding(
                manifest, trusted_keys, wrong_report, mappings, trusted_keys,
                collector_path, verifier_path,
            )
        except ValueError as error:
            if "provider identity" not in str(error):
                raise
        else:
            raise AssertionError("provider/account substitution was accepted")

        missing_mapping = mappings[:-1]
        try:
            build_binding(
                manifest, trusted_keys, report, missing_mapping, trusted_keys,
                collector_path, verifier_path,
            )
        except ValueError as error:
            if "map every page" not in str(error):
                raise
        else:
            raise AssertionError("incomplete artifact mapping was accepted")

        tampered_bytes = root / artifact_ids[2]
        tampered_bytes.write_bytes(sources[2][1] + b"tamper")
        try:
            validate_binding(
                manifest, trusted_keys, report, envelope, trusted_keys, root,
            )
        except ValueError as error:
            if "materialized manifest artifact bytes" not in str(error):
                raise
        else:
            raise AssertionError("tampered materialized evidence bytes were accepted")

    print("FENCE-001 audit provenance binding generator end-to-end self-test passed")
    print("Covered: ephemeral manifest signatures, report scope, exact source mapping, binding signatures, byte verification")
    print("Negative cases rejected: provider substitution, missing mapping, tampered materialized bytes")
    print("Scope: synthetic fixtures only; no external provider or production keys")


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--manifest",type=Path)
    parser.add_argument("--manifest-trusted-keys",type=Path)
    parser.add_argument("--audit-report",type=Path)
    parser.add_argument("--mapping-file",type=Path)
    parser.add_argument("--binding-trusted-keys",type=Path)
    parser.add_argument("--collector-signing-key",type=Path)
    parser.add_argument("--verifier-signing-key",type=Path)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.self_test:
        self_test(); return
    required=(args.manifest,args.manifest_trusted_keys,args.audit_report,args.mapping_file,
              args.binding_trusted_keys,args.collector_signing_key,args.verifier_signing_key,args.output)
    if any(value is None for value in required):
        parser.error("external mode requires all manifest, report, mapping, trust, signer-key and output arguments")
    manifest=load_object(args.manifest)
    manifest_keys=load_object(args.manifest_trusted_keys)["keys"]
    report=load_object(args.audit_report)
    mappings=json.loads(args.mapping_file.read_text(encoding="utf-8"))
    mapping_errors=list(Draft202012Validator(load_object(MAPPING_SCHEMA)).iter_errors(mappings))
    if mapping_errors:
        parser.error(f"mapping file schema failure: {mapping_errors[0].message}")
    binding_keys=load_object(args.binding_trusted_keys)["keys"]
    envelope=build_binding(manifest,manifest_keys,report,mappings,binding_keys,
                           args.collector_signing_key,args.verifier_signing_key)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(envelope,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"Created audit provenance binding: {args.output}")
    print(f"Binding digest: {envelope['bindingDigest']}")
    print("The envelope must still pass the independent manifest-binding validator and artifact byte checks.")


if __name__=="__main__":
    main()
