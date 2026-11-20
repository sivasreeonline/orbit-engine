#!/usr/bin/env python3
"""Build a dual-Ed25519 FENCE-001 manifest from a captured CloudTrail bundle.

Private signing keys are supplied by the operator as PEM or raw 32-byte files.
This tool never creates, exports, stores, or trusts signing keys. The generated
manifest is not a production qualification decision.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-fence-evidence-manifest-v1.schema.json"
SIGNATURE_PREFIX = b"SKYHIGH-FENCE-001-EVIDENCE-MANIFEST-V1\x00"
REPOSITORY = "https://github.com/sivasreeonline/orbit-engine"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return rfc8785.dumps(value)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def read_private_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except ValueError:
        if len(raw) != 32:
            raise ValueError(f"{path}: expected unencrypted Ed25519 PEM or exactly 32 raw private-key bytes")
        key = Ed25519PrivateKey.from_private_bytes(raw)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path}: signing key must be Ed25519")
    return key


def public_key_record(key: Ed25519PrivateKey, role: str, identity: str) -> dict[str, str]:
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "role": role,
        "identity": identity,
        "keyId": sha(public),
        "publicKeyBase64Url": base64.urlsafe_b64encode(public).decode("ascii").rstrip("="),
    }


def sign_manifest(body: dict[str, Any], signers: list[tuple[str, str, Ed25519PrivateKey]]) -> dict[str, Any]:
    digest = sha(canonical_json(body))
    attestations: list[dict[str, str]] = []
    for role, identity, private in signers:
        key_id = public_key_record(private, role, identity)["keyId"]
        payload = {
            "manifestDigest": digest,
            "role": role,
            "signerIdentity": identity,
            "keyId": key_id,
        }
        signature = private.sign(SIGNATURE_PREFIX + canonical_json(payload))
        attestations.append({
            "role": role,
            "signerIdentity": identity,
            "keyId": key_id,
            "signatureBase64Url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        })
    return {"manifestBody": body, "manifestDigest": digest, "attestations": attestations}


def safe_artifact(root: Path, artifact_id: str) -> bytes:
    if not ID_RE.fullmatch(artifact_id):
        raise ValueError(f"unsafe artifact ID: {artifact_id}")
    path = root / artifact_id
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required bundle artifact is missing or is a symlink: {artifact_id}")
    resolved = path.resolve(strict=True)
    if root.resolve(strict=True) not in resolved.parents:
        raise ValueError(f"artifact escapes bundle root: {artifact_id}")
    return path.read_bytes()


def artifact_record(
    *, artifact_id: str, artifact_type: str, object_ref: str, object_version: str,
    data: bytes, test_ids: list[str], acquired_at: str,
    collector_identity: str, collector_key_id: str,
    verifier_identity: str, verifier_key_id: str,
    request_ids: list[str],
) -> dict[str, Any]:
    return {
        "artifactId": artifact_id,
        "testIds": test_ids,
        "artifactType": artifact_type,
        "objectRef": object_ref,
        "objectVersion": object_version,
        "sha256": sha(data),
        "byteCount": len(data),
        "acquiredAt": acquired_at,
        "collectorIdentity": collector_identity,
        "collectorKeyId": collector_key_id,
        "independentVerifierIdentity": verifier_identity,
        "verifierKeyId": verifier_key_id,
        "providerRequestIds": sorted(set(request_ids)),
        "redaction": "NONE",
    }


def build_manifest(
    bundle_root: Path,
    collector_private: Ed25519PrivateKey,
    verifier_private: Ed25519PrivateKey,
    *,
    adapter_commit: str,
    configuration_digest: str,
    manifest_id: str,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not re.fullmatch(r"[0-9a-f]{40}", adapter_commit):
        raise ValueError("adapter commit must be a full 40-character lowercase Git SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", configuration_digest):
        raise ValueError("configuration digest must be a lowercase SHA-256")
    if not ID_RE.fullmatch(manifest_id):
        raise ValueError("manifest ID contains unsupported characters")

    root = bundle_root.resolve(strict=True)
    index = load_json(root / "collection-bundle-index.json")
    report_bytes = safe_artifact(root, "cloudtrail-verification-report.json")
    report = json.loads(report_bytes)
    provider_exchange = load_json(root / "cloudtrail-provider-exchange.json")
    collector = load_json(root / "aws-sts-collector-identity.json")
    verifier = load_json(root / "aws-sts-independent-verifier-identity.json")

    if report.get("profile") != "sky-high-cloudtrail-digest-verification-v1":
        raise ValueError("unsupported CloudTrail verification report profile")
    if report.get("verificationStatus") != "CHAIN_AND_REFERENCED_OBJECTS_VERIFIED":
        raise ValueError("CloudTrail chain and referenced objects are not verified")
    if report.get("testOnly") is not index.get("testOnly") or provider_exchange.get("testOnly") is not index.get("testOnly"):
        raise ValueError("bundle, provider exchange and report testOnly flags differ")
    if report.get("accountId") != index.get("accountId") or report.get("region") != index.get("region"):
        raise ValueError("bundle index and CloudTrail report scope differ")
    if collector.get("identityRole") != "COLLECTOR" or verifier.get("identityRole") != "INDEPENDENT_VERIFIER":
        raise ValueError("STS identity artifacts do not have the required roles")
    collector_identity = collector.get("callerArn")
    verifier_identity = verifier.get("callerArn")
    if not isinstance(collector_identity, str) or not collector_identity or not isinstance(verifier_identity, str) or not verifier_identity:
        raise ValueError("STS identity artifacts must contain callerArn")
    if collector_identity == verifier_identity:
        raise ValueError("collector and independent verifier STS identities must differ")

    collector_record = public_key_record(collector_private, "COLLECTOR", collector_identity)
    verifier_record = public_key_record(verifier_private, "INDEPENDENT_VERIFIER", verifier_identity)
    if collector_record["keyId"] == verifier_record["keyId"]:
        raise ValueError("collector and verifier signing keys must differ")

    acquired_at = index.get("collectionEndTime")
    if not isinstance(acquired_at, str) or not acquired_at:
        acquired_at = index.get("collectionEndTime")
    if not isinstance(acquired_at, str) or not acquired_at:
        raise ValueError("bundle index must include collectionEndTime")
    # Validate the timestamp and normalize it to UTC.
    parsed = datetime.fromisoformat(acquired_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("collectionEndTime must include a timezone")
    acquired_at = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    request_ids = list(provider_exchange.get("cloudTrailListPublicKeysRequestIds", []))
    request_ids.extend(provider_exchange.get("inventoryListObjectVersionsRequestIds", []))
    report_id = "cloudtrail-verification-report.json"
    records: list[dict[str, Any]] = []
    records_by_id: dict[str, dict[str, Any]] = {}

    def add(artifact_id: str, artifact_type: str, object_ref: str, version: str, tests: list[str], ids: list[str] | None = None) -> None:
        data = safe_artifact(root, artifact_id)
        record = artifact_record(
            artifact_id=artifact_id, artifact_type=artifact_type, object_ref=object_ref,
            object_version=version, data=data, test_ids=tests, acquired_at=acquired_at,
            collector_identity=collector_identity, collector_key_id=collector_record["keyId"],
            verifier_identity=verifier_identity, verifier_key_id=verifier_record["keyId"],
            request_ids=ids if ids is not None else request_ids,
        )
        previous = records_by_id.get(artifact_id)
        if previous is not None:
            identity_fields = ("artifactType", "objectRef", "objectVersion", "sha256", "byteCount")
            if any(previous[field] != record[field] for field in identity_fields):
                raise ValueError(f"one artifact ID is rebound to different evidence: {artifact_id}")
            previous["testIds"] = sorted(set(previous["testIds"]) | set(record["testIds"]))
            previous["providerRequestIds"] = sorted(set(previous["providerRequestIds"]) | set(record["providerRequestIds"]))
            return
        records_by_id[artifact_id] = record
        records.append(record)

    object_catalog = {
        (item["bucket"], item["key"], item["versionId"]): item["artifactId"]
        for item in provider_exchange.get("s3ObjectReads", [])
    }
    public_key_catalog = {
        item["fingerprint"]: item["artifactId"]
        for item in provider_exchange.get("regionalPublicKeys", [])
    }
    for digest in report.get("digests", []):
        bucket, key, version = digest.get("bucket"), digest.get("key"), digest.get("versionId")
        if not all(isinstance(x, str) and x for x in (bucket, key, version)) or version == "null":
            raise ValueError("each digest must carry an exact non-null S3 VersionId")
        artifact_id = object_catalog.get((bucket, key, version))
        if not artifact_id or not artifact_id.startswith("cloudtrail-digest-"):
            raise ValueError(f"raw digest object bytes missing for {bucket}/{key}@{version}")
        add(artifact_id, "CLOUDTRAIL_DIGEST", f"s3://{bucket}/{key}", version, ["CT-001", "CT-002", "CT-004", "CT-006"])

        for log in digest.get("logs", []):
            lb, lk, lv = log.get("bucket"), log.get("key"), log.get("versionId")
            if not all(isinstance(x, str) and x for x in (lb, lk, lv)) or lv == "null":
                raise ValueError("each log must carry an exact non-null S3 VersionId")
            log_id = object_catalog.get((lb, lk, lv))
            if not log_id or not log_id.startswith("cloudtrail-log-"):
                raise ValueError(f"raw log object bytes missing for {lb}/{lk}@{lv}")
            add(log_id, "CLOUDTRAIL_LOG", f"s3://{lb}/{lk}", lv, ["CT-003", "CT-004", "CT-006"])

        public_key = digest.get("publicKey", {})
        key_id = public_key_catalog.get(public_key.get("fingerprint"))
        if not key_id or not key_id.startswith("cloudtrail-public-key-"):
            raise ValueError(f"regional CloudTrail public key DER bytes missing for {public_key.get('fingerprint')}")
        add(
            key_id,
            "CLOUDTRAIL_PUBLIC_KEY",
            f"cloudtrail-public-key://{public_key['region']}/{public_key['fingerprint']}",
            f"{public_key['validityStartTime']}/{public_key['validityEndTime']}",
            ["CT-001", "CT-006"],
        )

    add(report_id, "CLOUDTRAIL_VERIFICATION_REPORT", "cloudtrail-verification-report://verification-v1", "report-v1", ["CT-006"])

    # Preserve inventory pagination and identity/provider-call provenance in the same signed envelope.
    add(
        "cloudtrail-inventory-index.json",
        "CLOUDTRAIL_DIGEST_INVENTORY",
        f"s3-inventory://{index['bucket']}/{index['prefix']}",
        "inventory-v1",
        ["CT-007"],
        provider_exchange.get("inventoryListObjectVersionsRequestIds", []),
    )
    for page_id in sorted(name for name in index["artifacts"] if name.startswith("cloudtrail-inventory-page-")):
        add(
            page_id,
            "CLOUDTRAIL_INVENTORY_PAGE",
            f"s3-inventory-page://{index['bucket']}/{index['prefix']}/{page_id}",
            "page-v1",
            ["CT-007"],
            provider_exchange.get("inventoryListObjectVersionsRequestIds", []),
        )
    add(
        "aws-sts-collector-identity.json",
        "AWS_STS_CALLER_IDENTITY",
        f"aws-sts-identity://{collector_identity}",
        "sts-v1",
        ["CT-008"],
        [],
    )
    add(
        "aws-sts-independent-verifier-identity.json",
        "AWS_STS_CALLER_IDENTITY",
        f"aws-sts-identity://{verifier_identity}",
        "sts-v1",
        ["CT-008"],
        [],
    )
    add(
        "cloudtrail-provider-exchange.json",
        "RAW_PROVIDER_EXCHANGE",
        f"aws-provider-exchange://cloudtrail/{report['accountId']}/{report['region']}",
        "exchange-v1",
        ["CT-009"],
        request_ids,
    )
    if not records:
        raise ValueError("no CloudTrail evidence artifacts were bound")
    artifact_ids = [item["artifactId"] for item in records]
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError("bundle maps one raw artifact to multiple CloudTrail source objects")

    body = {
        "profile": "sky-high-fence-evidence-manifest-v1",
        "schemaVersion": 1,
        "manifestId": manifest_id,
        "createdAt": acquired_at,
        "testOnly": index["testOnly"],
        "providerScope": {
            "name": "aws",
            "account": report["accountId"],
            "region": report["region"],
            "service": "cloudtrail",
        },
        "adapter": {
            "repository": REPOSITORY,
            "commit": adapter_commit,
            "version": "m0-fence-cloudtrail-readonly-collection-v1",
            "configurationDigest": configuration_digest,
        },
        "artifacts": records,
    }
    envelope = sign_manifest(body, [
        ("COLLECTOR", collector_identity, collector_private),
        ("INDEPENDENT_VERIFIER", verifier_identity, verifier_private),
    ])
    trusted_keys = [
        {k: record[k] for k in ("keyId", "identity", "role", "publicKeyBase64Url")}
        for record in (collector_record, verifier_record)
    ]
    return envelope, trusted_keys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--collector-private-key", type=Path, required=True)
    parser.add_argument("--verifier-private-key", type=Path, required=True)
    parser.add_argument("--adapter-commit", required=True)
    parser.add_argument("--configuration-digest", required=True)
    parser.add_argument("--manifest-id", required=True)
    parser.add_argument("--public-keys-output", type=Path, help="optional public-key records; still require independent trust approval")
    args = parser.parse_args()

    envelope, public_keys = build_manifest(
        args.bundle_dir,
        read_private_key(args.collector_private_key),
        read_private_key(args.verifier_private_key),
        adapter_commit=args.adapter_commit,
        configuration_digest=args.configuration_digest,
        manifest_id=args.manifest_id,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json.dumps(envelope, sort_keys=True, indent=2).encode("utf-8") + b"\n")
    if args.public_keys_output:
        args.public_keys_output.parent.mkdir(parents=True, exist_ok=True)
        args.public_keys_output.write_bytes(json.dumps({"keys": public_keys}, sort_keys=True, indent=2).encode("utf-8") + b"\n")
    print(f"Dual-signed FENCE-001 CloudTrail manifest generated: {args.output}")
    print(f"Manifest digest: {envelope['manifestDigest']}")
    print(f"Artifacts: {len(envelope['manifestBody']['artifacts'])}")
    print(f"Test-only: {envelope['manifestBody']['testOnly']}")
    print("The generated public-key file is not an independently governed trust decision.")
    print("Manifest signatures do not establish AWS qualification or complete CloudTrail delivery.")


if __name__ == "__main__":
    main()
