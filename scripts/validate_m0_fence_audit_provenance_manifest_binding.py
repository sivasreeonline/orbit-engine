#!/usr/bin/env python3
"""Bind provider audit provenance outputs to an independently signed FENCE-001 evidence manifest."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_m0_fence_evidence_manifest import validate_manifest  # noqa: E402

SCHEMA = ROOT / "docs/schemas/m0-fence-audit-provenance-binding-v1.schema.json"
DOMAIN = b"SKYHIGH-FENCE-001-AUDIT-PROVENANCE-BINDING-V1\x00"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("signature must be canonical unpadded base64url")
    result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(result) != value:
        raise ValueError("non-canonical base64url signature")
    return result


def binding_payload(digest: str, role: str, identity: str, key_id: str) -> bytes:
    return DOMAIN + rfc8785.dumps({
        "bindingDigest": digest, "role": role,
        "signerIdentity": identity, "keyId": key_id,
    })


def verify_binding_signatures(envelope: dict[str, Any], trusted_keys: list[dict[str, str]]) -> str:
    errors = list(Draft202012Validator(__import__("json").loads(SCHEMA.read_text())).iter_errors(envelope))
    if errors:
        raise ValueError(f"binding schema failure: {errors[0].message}")
    body = envelope["bindingBody"]
    digest = sha(rfc8785.dumps(body))
    if digest != envelope["bindingDigest"]:
        raise ValueError("audit provenance binding digest mismatch")
    keys = {item["keyId"]: item for item in trusted_keys}
    if len(keys) != len(trusted_keys):
        raise ValueError("duplicate binding trusted key IDs")
    attestations = envelope["attestations"]
    if sorted(item["role"] for item in attestations) != ["COLLECTOR", "INDEPENDENT_VERIFIER"]:
        raise ValueError("binding requires exactly collector and independent-verifier attestations")
    if len({item["signerIdentity"] for item in attestations}) != 2 or len({item["keyId"] for item in attestations}) != 2:
        raise ValueError("binding signer identities and keys must be distinct")
    for item in attestations:
        key = keys.get(item["keyId"])
        if key is None or key["identity"] != item["signerIdentity"] or key["role"] != item["role"]:
            raise ValueError("binding signer is not authorized by independently supplied trusted keys")
        public = unb64(key["publicKeyBase64Url"])
        if len(public) != 32 or sha(public) != item["keyId"]:
            raise ValueError("binding trusted key fingerprint mismatch")
        signature = unb64(item["signatureBase64Url"])
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, binding_payload(digest, item["role"], item["signerIdentity"], item["keyId"])
            )
        except InvalidSignature as error:
            raise ValueError("audit provenance binding signature verification failed") from error
    return digest


def validate_binding(
    manifest_envelope: dict[str, Any], manifest_keys: list[dict[str, str]],
    report: dict[str, Any], binding: dict[str, Any], binding_keys: list[dict[str, str]],
    artifact_root: Path, *, allow_test_only: bool = False
) -> str:
    manifest_digest = validate_manifest(manifest_envelope, manifest_keys, allow_test_only=allow_test_only)
    if report.get("testOnly") is not False and not allow_test_only:
        raise ValueError("test-only audit provenance report cannot qualify external evidence")
    if report.get("qualificationStatus") != "AUDIT_STREAM_AUTHENTICATED_AND_REQUESTS_CORRELATED":
        raise ValueError("audit provenance report is not a completed authenticated run")
    body = binding["bindingBody"]
    if body["manifestDigest"] != manifest_digest:
        raise ValueError("binding references a different evidence manifest digest")
    report_bytes = rfc8785.dumps(report)
    report_digest = sha(report_bytes)
    if body["auditReportSha256"] != report_digest:
        raise ValueError("binding does not reference the exact audit provenance report")
    provider = manifest_envelope["manifestBody"]["providerScope"]
    expected_provider = {
        "provider": provider["name"], "accountId": provider["account"],
        "region": provider["region"], "service": provider["service"]
    }
    if body["providerIdentity"] != expected_provider or report.get("providerIdentity") != expected_provider:
        raise ValueError("audit provenance provider scope differs from signed manifest provider scope")
    verifier_identity = next(
        item["signerIdentity"] for item in manifest_envelope["attestations"]
        if item["role"] == "INDEPENDENT_VERIFIER"
    )
    if report.get("independentVerifierPrincipalId") != verifier_identity:
        raise ValueError("audit provenance report verifier does not match signed manifest verifier")
    if body["independentVerifierIdentity"] != verifier_identity:
        raise ValueError("audit provenance verifier does not match evidence-manifest verifier")
    manifest_artifacts = {item["artifactId"]: item for item in manifest_envelope["manifestBody"]["artifacts"]}
    mappings = body["artifactMappings"]
    sources = []
    sources.extend(("pages", item) for item in report.get("pages", []))
    sources.extend(("authenticationEvidence", {
        "artifact": item["authenticationEvidenceArtifact"],
        "sha256": item["authenticationEvidenceSha256"],
        "byteCount": item["authenticationEvidenceByteCount"]
    }) for item in report.get("pages", []))
    sources.extend(("events", item) for item in report.get("events", []))
    if len(mappings) != len(sources):
        raise ValueError("every audit page, authentication proof and event must have exactly one manifest mapping")
    by_source = {item["sourceGroup"] + ":" + item["sourceArtifact"]: item for item in mappings}
    if len(by_source) != len(mappings):
        raise ValueError("duplicate source artifact mapping")
    used_manifest_ids: set[str] = set()
    for group, source in sources:
        source_name = source["rawResponseArtifact"] if group == "pages" else source["artifact"]
        key = group + ":" + source_name
        mapping = by_source.get(key)
        if mapping is None:
            raise ValueError(f"missing manifest mapping for {key}")
        artifact_id = mapping["manifestArtifactId"]
        if artifact_id in used_manifest_ids:
            raise ValueError("one manifest artifact cannot satisfy multiple audit evidence mappings")
        used_manifest_ids.add(artifact_id)
        artifact = manifest_artifacts.get(artifact_id)
        if artifact is None:
            raise ValueError("audit mapping references an artifact absent from the signed manifest")
        expected_hash = source.get("rawResponseSha256") if group == "pages" else (
            source.get("sha256")
        )
        expected_bytes = source.get("rawResponseByteCount") if group == "pages" else source.get("byteCount")
        if artifact["sha256"] != expected_hash or artifact["byteCount"] != expected_bytes:
            raise ValueError("manifest artifact digest or byte count differs from audit provenance output")
        expected_type = "CONTRACT_EVIDENCE" if group == "authenticationEvidence" else "RAW_PROVIDER_EXCHANGE"
        if artifact["artifactType"] != expected_type:
            raise ValueError("manifest artifact type is incorrect for audit provenance evidence")
        if not {"WIT-012", "WIT-014"}.issubset(set(artifact["testIds"])):
            raise ValueError("audit provenance artifacts must bind WIT-012 and WIT-014")
        if artifact["independentVerifierIdentity"] != verifier_identity:
            raise ValueError("audit artifact verifier identity differs from signed manifest verifier")
        if group == "events":
            request_id = source["providerRequestId"]
            if request_id not in artifact["providerRequestIds"]:
                raise ValueError("audit event artifact does not bind its originating provider request ID")
        file_path = artifact_root / artifact_id
        if file_path.is_symlink() or not file_path.is_file():
            raise ValueError("mapped evidence artifact is missing or is not a regular file")
        data = file_path.read_bytes()
        if len(data) != artifact["byteCount"] or sha(data) != artifact["sha256"]:
            raise ValueError("materialized manifest artifact bytes do not match signed digest and byte count")
    return verify_binding_signatures(binding, binding_keys)


def sign_binding(body: dict[str, Any], identities: list[tuple[str, str, Ed25519PrivateKey]]) -> dict[str, Any]:
    digest = sha(rfc8785.dumps(body))
    attestations = []
    for role, identity, private in identities:
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        key_id = sha(public)
        attestations.append({
            "role": role, "signerIdentity": identity, "keyId": key_id,
            "signatureBase64Url": b64(private.sign(binding_payload(digest, role, identity, key_id)))
        })
    return {"bindingBody": body, "bindingDigest": digest, "attestations": attestations}


def fixture_test() -> None:
    vector = json.loads((ROOT / "docs/test-vectors/fence-evidence-manifest-v1.json").read_text())
    manifest = {key: vector[key] for key in ("manifestBody", "manifestDigest", "attestations")}
    raw = b"fixture audit bytes"
    auth = b"fixture authentication proof"
    event = b"fixture event bytes"
    root = Path(tempfile.mkdtemp())
    artifact_defs = [
        ("page-001.bin", raw, "RAW_PROVIDER_EXCHANGE", []),
        ("auth-001.bin", auth, "CONTRACT_EVIDENCE", []),
        ("event-001.bin", event, "RAW_PROVIDER_EXCHANGE", ["request-001"]),
    ]
    body = copy.deepcopy(vector["manifestBody"])
    body["providerScope"] = {"name": "fixture-provider", "account": "qualification-account",
                             "region": "fixture-region", "service": "audit-service"}
    body["artifacts"] = []
    for index, (name, data, kind, request_ids) in enumerate(artifact_defs, start=1):
        artifact_id = f"audit-fixture-{index}"
        (root / artifact_id).write_bytes(data)
        body["artifacts"].append({
            "artifactId": artifact_id, "testIds": ["WIT-012", "WIT-014"],
            "artifactType": kind, "objectRef": f"fixture://evidence/{index}",
            "objectVersion": "immutable-v1", "sha256": sha(data), "byteCount": len(data),
            "acquiredAt": "2026-11-12T00:00:00Z", "collectorIdentity": "collector-fixture",
            "collectorKeyId": vector["attestations"][0]["keyId"],
            "independentVerifierIdentity": "verifier-fixture",
            "verifierKeyId": vector["attestations"][1]["keyId"],
            "providerRequestIds": request_ids, "redaction": "NONE"
        })
    # Sign this synthetic manifest with ephemeral fixture keys.
    manifest_privates = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    manifest_keys = []
    manifest_attestations = []
    for (role, identity), private in zip((("COLLECTOR","collector-fixture"),("INDEPENDENT_VERIFIER","verifier-fixture")), manifest_privates):
        pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        kid = sha(pub)
        manifest_keys.append({"keyId":kid,"identity":identity,"role":role,"publicKeyBase64Url":b64(pub)})
        manifest_attestations.append((role,identity,private))
    # Bind each manifest artifact to the ephemeral signer keys used below.
    generated_collector_public = manifest_privates[0].public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    generated_verifier_public = manifest_privates[1].public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    for artifact in body["artifacts"]:
        artifact["collectorKeyId"] = sha(generated_collector_public)
        artifact["verifierKeyId"] = sha(generated_verifier_public)

    # Build manifest envelope using the repository's established signature profile.
    import rfc8785 as canonical
    prefix = b"SKYHIGH-FENCE-001-EVIDENCE-MANIFEST-V1\x00"
    md = sha(canonical.dumps(body))
    manifest["manifestBody"] = body
    manifest["manifestDigest"] = md
    manifest["attestations"] = []
    for role, identity, private in manifest_attestations:
        pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        kid = sha(pub)
        payload = prefix + canonical.dumps({"manifestDigest":md,"role":role,"signerIdentity":identity,"keyId":kid})
        manifest["attestations"].append({"role":role,"signerIdentity":identity,"keyId":kid,"signatureBase64Url":b64(private.sign(payload))})
    report = {
        "qualificationStatus":"AUDIT_STREAM_AUTHENTICATED_AND_REQUESTS_CORRELATED",
        "testOnly":False,
        "providerIdentity":{"provider":"fixture-provider","accountId":"qualification-account","region":"fixture-region","service":"audit-service"},
        "independentVerifierPrincipalId":"verifier-fixture",
        "pages":[{
            "rawResponseArtifact":"page-001.bin","rawResponseSha256":sha(raw),"rawResponseByteCount":len(raw),
            "authenticationEvidenceArtifact":"auth-001.bin","authenticationEvidenceSha256":sha(auth),
            "authenticationEvidenceByteCount":len(auth)
        }],
        "events":[{"artifact":"event-001.bin","sha256":sha(event),"byteCount":len(event),"providerRequestId":"request-001"}]
    }
    binding_body = {
        "profile":"sky-high-fence-audit-provenance-binding-v1","schemaVersion":1,
        "manifestDigest":md,"auditReportSha256":sha(canonical.dumps(report)),
        "providerIdentity":{"provider":"fixture-provider","accountId":"qualification-account","region":"fixture-region","service":"audit-service"},
        "independentVerifierIdentity":"verifier-fixture",
        "artifactMappings":[
            {"sourceGroup":"pages","sourceArtifact":"page-001.bin","manifestArtifactId":"audit-fixture-1"},
            {"sourceGroup":"authenticationEvidence","sourceArtifact":"auth-001.bin","manifestArtifactId":"audit-fixture-2"},
            {"sourceGroup":"events","sourceArtifact":"event-001.bin","manifestArtifactId":"audit-fixture-3"}
        ]
    }
    binding_privates = [Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()]
    binding_keys=[]; identities=[]
    for (role,identity),private in zip((("COLLECTOR","collector-fixture"),("INDEPENDENT_VERIFIER","verifier-fixture")),binding_privates):
        pub=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        binding_keys.append({"keyId":sha(pub),"identity":identity,"role":role,"publicKeyBase64Url":b64(pub)})
        identities.append((role,identity,private))
    binding=sign_binding(binding_body,identities)
    validate_binding(manifest,manifest_keys,report,binding,binding_keys,root,allow_test_only=True)
    tampered=copy.deepcopy(report); tampered["events"][0]["providerRequestId"]="request-substituted"
    try:
        validate_binding(manifest,manifest_keys,tampered,binding,binding_keys,root,allow_test_only=True)
    except ValueError as error:
        assert "exact audit provenance report" in str(error)
    else:
        raise AssertionError("tampered provenance report was accepted")
    print("FENCE-001 audit provenance manifest-binding self-test passed (synthetic fixtures only)")


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--manifest",type=Path)
    parser.add_argument("--manifest-trusted-keys",type=Path)
    parser.add_argument("--audit-report",type=Path)
    parser.add_argument("--binding",type=Path)
    parser.add_argument("--binding-trusted-keys",type=Path)
    parser.add_argument("--artifact-root",type=Path)
    args=parser.parse_args()
    if args.self_test:
        fixture_test(); return
    required=(args.manifest,args.manifest_trusted_keys,args.audit_report,args.binding,args.binding_trusted_keys,args.artifact_root)
    if any(value is None for value in required):
        parser.error("external mode requires manifest, both independently provisioned trusted-key files, audit report, binding and artifact root")
    manifest=json.loads(args.manifest.read_text())
    manifest_keys=json.loads(args.manifest_trusted_keys.read_text())["keys"]
    report=json.loads(args.audit_report.read_text())
    binding=json.loads(args.binding.read_text())
    binding_keys=json.loads(args.binding_trusted_keys.read_text())["keys"]
    result=validate_binding(manifest,manifest_keys,report,binding,binding_keys,args.artifact_root)
    print(f"FENCE-001 audit provenance binding: PASS ({result})")
    print("This is evidence binding only; independent review and production qualification remain separate.")


if __name__=="__main__":
    main()
