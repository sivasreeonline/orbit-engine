#!/usr/bin/env python3
"""Reconcile a captured S3 ListObjectVersions inventory against verified CloudTrail digests."""
from __future__ import annotations

import argparse
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from validate_m0_fence_cloudtrail_manifest_binding import (
    _artifact,
    _fixture,
    _read_artifact,
    _signed_manifest,
    _strict_json,
    parse_utc,
    sha,
    validate_cloudtrail_manifest,
)

INDEX_TYPE = "CLOUDTRAIL_DIGEST_INVENTORY"
PAGE_TYPE = "CLOUDTRAIL_INVENTORY_PAGE"
DIGEST_KEY = re.compile(r"_(\d{8}T\d{6}Z)(_backfill)?\.json\.gz$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _digest_key_time(key: str) -> tuple[datetime, bool]:
    match = DIGEST_KEY.search(key)
    if not match:
        raise ValueError(f"CloudTrail digest inventory key has no supported timestamp suffix: {key}")
    value = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    return value, bool(match.group(2))


def reconcile_inventory(
    report: dict[str, Any],
    inventory: dict[str, Any],
    page_documents: list[dict[str, Any]],
) -> dict[str, Any]:
    if inventory.get("profile") != "sky-high-cloudtrail-digest-inventory-v1":
        raise ValueError("unsupported CloudTrail digest inventory profile")
    if inventory.get("schemaVersion") != 1:
        raise ValueError("unsupported CloudTrail digest inventory schema version")
    if inventory.get("testOnly") is not report.get("testOnly"):
        raise ValueError("inventory and verification report testOnly flags differ")
    if inventory.get("accountId") != report.get("accountId") or inventory.get("region") != report.get("region"):
        raise ValueError("inventory account/Region differs from the verified CloudTrail report")
    bucket = inventory.get("bucket")
    if not isinstance(bucket, str) or not bucket:
        raise ValueError("inventory bucket is required")
    if any(item.get("bucket") != bucket for item in report.get("digests", [])):
        raise ValueError("inventory bucket differs from a verified digest bucket")
    account, region = inventory["accountId"], inventory["region"]
    required_prefix = f"AWSLogs/{account}/CloudTrail-Digest/{region}/"
    prefix = inventory.get("prefix")
    if not isinstance(prefix, str) or not prefix.endswith(required_prefix):
        raise ValueError("inventory prefix must be scoped to the pinned account and Region digest path")
    start = parse_utc(inventory.get("requestedStartTime"), "requestedStartTime")
    end = parse_utc(inventory.get("requestedEndTime"), "requestedEndTime")
    if start >= end:
        raise ValueError("requestedStartTime must precede requestedEndTime")
    collection_start = parse_utc(inventory.get("collectionStartTime"), "collectionStartTime")
    collection_end = parse_utc(inventory.get("collectionEndTime"), "collectionEndTime")
    if collection_start > collection_end:
        raise ValueError("inventory collection interval is reversed")
    if inventory.get("paginationComplete") is not True:
        raise ValueError("S3 ListObjectVersions inventory pagination is not marked complete")

    pages = inventory.get("pages")
    if not isinstance(pages, list) or not pages or len(pages) != len(page_documents):
        raise ValueError("inventory page index and captured page artifact count differ")
    if inventory.get("pageCount") != len(pages):
        raise ValueError("inventory pageCount mismatch")

    versions_by_key: dict[str, list[dict[str, Any]]] = {}
    seen_page_artifacts: set[str] = set()
    seen_versions: set[tuple[str, str, bool]] = set()
    previous_next_key: str | None = None
    previous_next_version: str | None = None
    for index, (page_entry, page_doc) in enumerate(zip(pages, page_documents), start=1):
        if not isinstance(page_entry, dict) or not isinstance(page_doc, dict):
            raise ValueError("inventory page entry and response must be JSON objects")
        artifact_id = page_entry.get("artifactId")
        if not isinstance(artifact_id, str) or not artifact_id or artifact_id in seen_page_artifacts:
            raise ValueError("inventory page artifact ID is missing or duplicated")
        seen_page_artifacts.add(artifact_id)
        request_key = page_entry.get("requestKeyMarker")
        request_version = page_entry.get("requestVersionIdMarker")
        next_key = page_entry.get("nextKeyMarker")
        next_version = page_entry.get("nextVersionIdMarker")
        truncated = page_entry.get("isTruncated")
        if type(truncated) is not bool:
            raise ValueError("inventory page isTruncated must be boolean")
        if page_doc.get("Name") != bucket or page_doc.get("Prefix") != prefix:
            raise ValueError(f"inventory page {index} bucket/prefix differs from the signed inventory scope")
        if page_doc.get("KeyMarker") != request_key or page_doc.get("VersionIdMarker") != request_version:
            raise ValueError(f"inventory page {index} request markers differ from the captured response")
        if page_doc.get("IsTruncated") is not truncated:
            raise ValueError(f"inventory page {index} truncation flag differs from the captured response")
        if page_doc.get("NextKeyMarker") != next_key or page_doc.get("NextVersionIdMarker") != next_version:
            raise ValueError(f"inventory page {index} continuation markers differ from the captured response")
        if index == 1:
            if request_key is not None or request_version is not None:
                raise ValueError("first ListObjectVersions page must not have request markers")
        else:
            if request_key != previous_next_key or request_version != previous_next_version:
                raise ValueError(f"inventory page {index} does not continue the prior page markers")
        if truncated:
            if not isinstance(next_key, str) or not next_key or not isinstance(next_version, str) or not next_version:
                raise ValueError(f"truncated inventory page {index} lacks both continuation markers")
        else:
            if next_key is not None or next_version is not None:
                raise ValueError(f"non-truncated inventory page {index} unexpectedly has continuation markers")
            if index != len(pages):
                raise ValueError("a non-final inventory page cannot terminate pagination")
        previous_next_key, previous_next_version = next_key, next_version

        versions = page_doc.get("Versions")
        delete_markers = page_doc.get("DeleteMarkers")
        if not isinstance(versions, list) or not isinstance(delete_markers, list):
            raise ValueError(f"inventory page {index} must contain Versions and DeleteMarkers arrays")
        for is_delete, entries in ((False, versions), (True, delete_markers)):
            for item in entries:
                if not isinstance(item, dict):
                    raise ValueError("S3 version inventory entry must be an object")
                key, version_id = item.get("Key"), item.get("VersionId")
                if not isinstance(key, str) or not key.startswith(prefix):
                    raise ValueError("S3 inventory key is outside the pinned digest prefix")
                if not isinstance(version_id, str) or not version_id or version_id == "null":
                    raise ValueError("S3 inventory entry lacks a non-null VersionId")
                if type(item.get("IsLatest")) is not bool:
                    raise ValueError("S3 inventory IsLatest must be boolean")
                parse_utc(item.get("LastModified"), "S3 inventory LastModified")
                identity = (key, version_id, is_delete)
                if identity in seen_versions:
                    raise ValueError("duplicate S3 object version across inventory pages")
                seen_versions.add(identity)
                versions_by_key.setdefault(key, []).append({
                    "versionId": version_id,
                    "isLatest": item["IsLatest"],
                    "isDeleteMarker": is_delete,
                    "lastModified": item["LastModified"],
                })

    if pages[-1].get("isTruncated") is not False:
        raise ValueError("final ListObjectVersions page must have IsTruncated=false")

    inventory_standard: dict[str, dict[str, Any]] = {}
    inventory_backfill: list[str] = []
    delete_marker_keys: list[str] = []
    version_count = 0
    for key, entries in versions_by_key.items():
        latest = [item for item in entries if item["isLatest"]]
        if len(latest) != 1:
            raise ValueError(f"S3 inventory key must have exactly one latest version or delete marker: {key}")
        current = latest[0]
        version_count += len(entries)
        end_time, is_backfill = _digest_key_time(key)
        if start <= end_time <= end:
            if current["isDeleteMarker"]:
                delete_marker_keys.append(key)
                raise ValueError(f"current CloudTrail digest key is a delete marker: {key}")
            if is_backfill:
                inventory_backfill.append(key)
            else:
                inventory_standard[key] = current

    report_standard: dict[str, dict[str, Any]] = {}
    report_backfill: dict[str, dict[str, Any]] = {}
    for digest in report.get("digests", []):
        if not isinstance(digest, dict):
            raise ValueError("verification report digest entry is malformed")
        digest_end = parse_utc(digest.get("digestEndTime"), "digestEndTime")
        if start <= digest_end <= end:
            key = digest.get("key")
            target = report_backfill if digest.get("chainType", "STANDARD") == "BACKFILL" else report_standard
            if key in target:
                raise ValueError("verification report contains duplicate digest keys in requested range")
            target[key] = digest

    unlinked = sorted(set(inventory_standard) - set(report_standard))
    if unlinked:
        raise ValueError(f"inventory contains digest keys not covered by the verified standard chain: {unlinked}")
    missing = sorted(set(report_standard) - set(inventory_standard))
    if missing:
        raise ValueError(f"verified standard chain contains digest keys missing from inventory: {missing}")

    for key, current in inventory_standard.items():
        digest = report_standard[key]
        if digest.get("versionId") != current["versionId"]:
            raise ValueError(f"verified digest did not use the latest S3 version from inventory: {key}")
        key_end, _ = _digest_key_time(key)
        digest_end = parse_utc(digest.get("digestEndTime"), "digestEndTime")
        if key_end != digest_end:
            raise ValueError(f"digest filename timestamp differs from digestEndTime: {key}")

    unverified_backfill = sorted(set(inventory_backfill) - set(report_backfill))
    missing_backfill = sorted(set(report_backfill) - set(inventory_backfill))
    if missing_backfill:
        raise ValueError(f"verified backfill chain contains digest keys missing from inventory: {missing_backfill}")
    for key in set(inventory_backfill) & set(report_backfill):
        current = versions_by_key[key]
        latest = next(item for item in current if item["isLatest"])
        digest = report_backfill[key]
        if digest.get("versionId") != latest["versionId"]:
            raise ValueError(f"verified backfill digest did not use the latest S3 version: {key}")
        key_end, _ = _digest_key_time(key)
        if key_end != parse_utc(digest.get("digestEndTime"), "digestEndTime"):
            raise ValueError(f"backfill digest filename timestamp differs from digestEndTime: {key}")

    backfill_present = bool(inventory_backfill)
    backfill_verified = backfill_present and not unverified_backfill
    complete = not backfill_present or backfill_verified
    if backfill_verified:
        status = "STANDARD_AND_BACKFILL_INVENTORY_RECONCILED"
    elif backfill_present:
        status = "STANDARD_CHAIN_RECONCILED_BACKFILL_UNVERIFIED"
    else:
        status = "STANDARD_CHAIN_INVENTORY_RECONCILED"
    return {
        "profile": "sky-high-cloudtrail-digest-inventory-reconciliation-v1",
        "schemaVersion": 1,
        "testOnly": inventory["testOnly"],
        "accountId": account,
        "region": region,
        "bucket": bucket,
        "requestedStartTime": inventory["requestedStartTime"],
        "requestedEndTime": inventory["requestedEndTime"],
        "status": status,
        "completeWithinCapturedStandardInventory": True,
        "completeWithinCapturedInventory": complete,
        "backfillVerified": backfill_verified,
        "absoluteSnapshotCompleteness": "NOT_PROVEN_NON_ATOMIC_LISTOBJECTVERSIONS_PAGINATION",
        "paginationPageCount": len(pages),
        "inventoryKeyCountInRange": len(inventory_standard) + len(inventory_backfill),
        "verifiedStandardDigestCountInRange": len(report_standard),
        "verifiedBackfillDigestCountInRange": len(report_backfill),
        "backfillDigestCountInRange": len(inventory_backfill),
        "unverifiedBackfillDigestKeys": unverified_backfill,
        "objectVersionCount": version_count,
        "deleteMarkerKeysInRange": delete_marker_keys,
        "unlinkedStandardDigestKeys": unlinked,
        "missingInventoryDigestKeys": missing,
        "limitations": [
            "ListObjectVersions pagination is captured and internally reconciled but is not an atomic snapshot across pages.",
            "Backfill digests are a separate chain and are only considered reconciled when their own verified report records are present.",
            "This result does not establish that CloudTrail delivered every event or that no delivery gap occurred outside the captured S3 inventory scope.",
        ],
    }


def validate_inventory_manifest(
    envelope: dict[str, Any],
    trusted_keys: list[dict[str, str]],
    artifact_root: Path,
    *,
    allow_test_only: bool = False,
) -> dict[str, Any]:
    custody = validate_cloudtrail_manifest(
        envelope, trusted_keys, artifact_root, allow_test_only=allow_test_only
    )
    body = envelope["manifestBody"]
    root = artifact_root.resolve(strict=True)
    artifacts = body["artifacts"]
    index_artifacts = [item for item in artifacts if item["artifactType"] == INDEX_TYPE]
    if len(index_artifacts) != 1:
        raise ValueError("manifest must contain exactly one CloudTrail digest inventory index")
    index_artifact = index_artifacts[0]
    if not {"CT-007", "CT-008"}.issubset(set(index_artifact["testIds"])):
        raise ValueError("CloudTrail inventory index lacks CT-007/CT-008")
    if index_artifact["objectVersion"] != "inventory-v1":
        raise ValueError("CloudTrail inventory index objectVersion must be inventory-v1")
    inventory = _strict_json(_read_artifact(root, index_artifact["artifactId"]), "CloudTrail digest inventory")
    expected_index_ref = f"cloudtrail-digest-inventory://{inventory.get('bucket')}/{inventory.get('prefix')}"
    if index_artifact["objectRef"] != expected_index_ref:
        raise ValueError("CloudTrail inventory index objectRef differs from its declared bucket/prefix")
    if inventory.get("testOnly") is not body["testOnly"]:
        raise ValueError("inventory testOnly flag differs from signed manifest")

    page_artifacts = [item for item in artifacts if item["artifactType"] == PAGE_TYPE]
    if not page_artifacts:
        raise ValueError("manifest contains no CloudTrail inventory page artifacts")
    page_by_id = {item["artifactId"]: item for item in page_artifacts}
    page_documents: list[dict[str, Any]] = []
    for index, page_entry in enumerate(inventory.get("pages", []), start=1):
        artifact_id = page_entry.get("artifactId") if isinstance(page_entry, dict) else None
        artifact = page_by_id.get(artifact_id)
        if artifact is None:
            raise ValueError("inventory index references a page artifact missing from the manifest")
        if "CT-007" not in artifact["testIds"]:
            raise ValueError("CloudTrail inventory page artifact lacks CT-007")
        if artifact["objectVersion"] != f"page-{index}":
            raise ValueError("CloudTrail inventory page objectVersion does not match its page order")
        expected_page_ref = f"s3-list-object-versions://{inventory['bucket']}/{inventory['prefix']}?page={index}"
        if artifact["objectRef"] != expected_page_ref:
            raise ValueError("CloudTrail inventory page objectRef differs from its bucket/prefix/page order")
        page_documents.append(_strict_json(_read_artifact(root, artifact_id), f"CloudTrail inventory page {index}"))
    if set(page_by_id) != {item["artifactId"] for item in inventory.get("pages", [])}:
        raise ValueError("manifest has unreferenced or duplicate CloudTrail inventory page artifacts")

    report_artifact_id = custody["reportArtifactId"]
    report_artifact = next(item for item in artifacts if item["artifactId"] == report_artifact_id)
    report = _strict_json(_read_artifact(root, report_artifact_id), "CloudTrail verification report")
    result = reconcile_inventory(report, inventory, page_documents)
    result["inventoryIndexArtifactId"] = index_artifact["artifactId"]
    result["inventoryIndexSha256"] = index_artifact["sha256"]
    result["inventoryPageArtifactIds"] = [item["artifactId"] for item in inventory["pages"]]
    result["manifestDigest"] = custody["manifestDigest"]
    return result


def _inventory_fixture(root: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    from validate_m0_fence_cloudtrail_manifest_binding import _strict_json as strict_json

    envelope, trusted = _fixture(root)
    body = envelope["manifestBody"]
    report_artifact = next(item for item in body["artifacts"] if item["artifactType"] == "CLOUDTRAIL_VERIFICATION_REPORT")
    report = strict_json((root / report_artifact["artifactId"]).read_bytes(), "fixture report")
    digest = report["digests"][0]
    bucket = digest["bucket"]
    key = digest["key"]
    account, region = report["accountId"], report["region"]
    prefix = f"AWSLogs/{account}/CloudTrail-Digest/{region}/"

    page_one = {
        "Name": bucket, "Prefix": prefix, "KeyMarker": None, "VersionIdMarker": None,
        "IsTruncated": True, "NextKeyMarker": key, "NextVersionIdMarker": digest["versionId"],
        "Versions": [{
            "Key": key, "VersionId": digest["versionId"], "IsLatest": True,
            "LastModified": "2026-11-20T01:01:00Z", "Size": digest["rawByteCount"],
        }],
        "DeleteMarkers": [],
    }
    page_two = {
        "Name": bucket, "Prefix": prefix, "KeyMarker": key, "VersionIdMarker": digest["versionId"],
        "IsTruncated": False, "NextKeyMarker": None, "NextVersionIdMarker": None,
        "Versions": [{
            "Key": key, "VersionId": "older-version-000", "IsLatest": False,
            "LastModified": "2026-11-20T00:59:00Z", "Size": digest["rawByteCount"],
        }],
        "DeleteMarkers": [],
    }
    page_docs = [page_one, page_two]
    page_bytes = [json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8") for item in page_docs]
    page_ids = ["inventory-page-001", "inventory-page-002"]
    for artifact_id, data in zip(page_ids, page_bytes):
        (root / artifact_id).write_bytes(data)

    index = {
        "profile": "sky-high-cloudtrail-digest-inventory-v1",
        "schemaVersion": 1,
        "testOnly": True,
        "accountId": account,
        "region": region,
        "bucket": bucket,
        "prefix": prefix,
        "requestedStartTime": "2026-11-20T00:00:00Z",
        "requestedEndTime": "2026-11-20T02:00:00Z",
        "collectionStartTime": "2026-11-20T02:05:00Z",
        "collectionEndTime": "2026-11-20T02:06:00Z",
        "paginationComplete": True,
        "pageCount": 2,
        "pages": [
            {
                "artifactId": page_ids[0],
                "requestKeyMarker": None, "requestVersionIdMarker": None,
                "nextKeyMarker": key, "nextVersionIdMarker": digest["versionId"],
                "isTruncated": True,
            },
            {
                "artifactId": page_ids[1],
                "requestKeyMarker": key, "requestVersionIdMarker": digest["versionId"],
                "nextKeyMarker": None, "nextVersionIdMarker": None,
                "isTruncated": False,
            },
        ],
    }
    index_bytes = json.dumps(index, sort_keys=True, separators=(",", ":")).encode("utf-8")
    (root / "inventory-001").write_bytes(index_bytes)

    page_artifacts = [
        _artifact(
            artifact_id, PAGE_TYPE,
            f"s3-list-object-versions://{bucket}/{prefix}?page={i}",
            f"page-{i}", data, ["CT-007"],
        )
        for i, (artifact_id, data) in enumerate(zip(page_ids, page_bytes), start=1)
    ]
    index_artifact = _artifact(
        "inventory-001", INDEX_TYPE,
        f"cloudtrail-digest-inventory://{bucket}/{prefix}",
        "inventory-v1", index_bytes, ["CT-007", "CT-008"],
    )
    body["artifacts"].extend(page_artifacts + [index_artifact])
    envelope, trusted = _signed_manifest(body)
    return envelope, trusted


def run_fixture_tests() -> int:
    cases = 0
    with tempfile.TemporaryDirectory(prefix="fence-cloudtrail-inventory-") as directory:
        root = Path(directory)
        envelope, trusted = _inventory_fixture(root)
        result = validate_inventory_manifest(envelope, trusted, root, allow_test_only=True)
        if not result["completeWithinCapturedStandardInventory"] or result["paginationPageCount"] != 2:
            raise AssertionError("complete standard digest inventory was not reconciled")
        cases += 1

        report_artifact = next(item for item in envelope["manifestBody"]["artifacts"] if item["artifactType"] == "CLOUDTRAIL_VERIFICATION_REPORT")
        report_for_backfill = _strict_json((root / report_artifact["artifactId"]).read_bytes(), "fixture report")
        inventory_for_backfill = _strict_json(
            (root / next(item for item in envelope["manifestBody"]["artifacts"] if item["artifactType"] == INDEX_TYPE)["artifactId"]).read_bytes(),
            "fixture inventory",
        )
        page_docs_for_backfill = [
            _strict_json((root / entry["artifactId"]).read_bytes(), "fixture page")
            for entry in inventory_for_backfill["pages"]
        ]
        backfill_key = (
            f"{inventory_for_backfill['prefix']}2026/11/20/"
            "123456789012_CloudTrail-Digest_us-east-1_fixture-trail_us-east-1_"
            "20261120T020000Z_backfill.json.gz"
        )
        backfill_digest = json.loads(json.dumps(report_for_backfill["digests"][0]))
        backfill_digest["chainType"] = "BACKFILL"
        backfill_digest["backfillGenerationTimestamp"] = "2026-11-20T03:00:00Z"
        backfill_digest["key"] = backfill_key
        backfill_digest["versionId"] = "backfill-version-001"
        backfill_digest["digestEndTime"] = "2026-11-20T02:00:00Z"
        report_for_backfill["digests"].append(backfill_digest)
        page_docs_for_backfill[1]["Versions"].append({
            "Key": backfill_key, "VersionId": "backfill-version-001", "IsLatest": True,
            "LastModified": "2026-11-20T02:01:00Z", "Size": 100,
        })
        reconciled_backfill = reconcile_inventory(
            report_for_backfill, inventory_for_backfill, page_docs_for_backfill
        )
        if not reconciled_backfill["completeWithinCapturedInventory"] or not reconciled_backfill["backfillVerified"]:
            raise AssertionError("separately verified backfill chain did not reconcile with inventory")
        cases += 1

        unverified_backfill = json.loads(json.dumps(report_for_backfill))
        unverified_backfill["digests"] = unverified_backfill["digests"][:1]
        partial = reconcile_inventory(unverified_backfill, inventory_for_backfill, page_docs_for_backfill)
        if partial["completeWithinCapturedInventory"] or partial["backfillVerified"]:
            raise AssertionError("inventory with an unverified backfill chain was reported complete")
        cases += 1
        report = _strict_json((root / report_artifact["artifactId"]).read_bytes(), "fixture report")
        inventory_artifact = next(item for item in envelope["manifestBody"]["artifacts"] if item["artifactType"] == INDEX_TYPE)
        inventory = _strict_json((root / inventory_artifact["artifactId"]).read_bytes(), "fixture inventory")
        page_docs = [_strict_json((root / entry["artifactId"]).read_bytes(), "fixture page") for entry in inventory["pages"]]

        bad_pages = json.loads(json.dumps(page_docs))
        bad_pages[1]["KeyMarker"] = "wrong-marker"
        try:
            reconcile_inventory(report, inventory, bad_pages)
        except ValueError as error:
            if "request markers differ" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("broken ListObjectVersions pagination markers were accepted")

        bad_pages = json.loads(json.dumps(page_docs))
        bad_pages[0]["Versions"][0]["IsLatest"] = False
        bad_pages[0]["DeleteMarkers"] = [{
            "Key": bad_pages[0]["Versions"][0]["Key"],
            "VersionId": "delete-marker-001", "IsLatest": True,
            "LastModified": "2026-11-20T01:02:00Z",
        }]
        try:
            reconcile_inventory(report, inventory, bad_pages)
        except ValueError as error:
            if "delete marker" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("current digest delete marker was accepted")

        bad_pages = json.loads(json.dumps(page_docs))
        bad_pages[0]["Versions"][0]["VersionId"] = "different-latest-version"
        bad_pages[0]["NextVersionIdMarker"] = "different-latest-version"
        bad_pages[1]["VersionIdMarker"] = "different-latest-version"
        bad_inventory = json.loads(json.dumps(inventory))
        bad_inventory["pages"][0]["nextVersionIdMarker"] = "different-latest-version"
        bad_inventory["pages"][1]["requestVersionIdMarker"] = "different-latest-version"
        try:
            reconcile_inventory(report, bad_inventory, bad_pages)
        except ValueError as error:
            if "latest S3 version" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("inventory latest version mismatch was accepted")

        bad_pages = json.loads(json.dumps(page_docs))
        extra_key = f"{inventory['prefix']}2026/11/20/123456789012_CloudTrail-Digest_us-east-1_extra_us-east-1_20261120T013000Z.json.gz"
        bad_pages[1]["Versions"].append({
            "Key": extra_key, "VersionId": "unlinked-version", "IsLatest": True,
            "LastModified": "2026-11-20T01:30:00Z", "Size": 100,
        })
        try:
            reconcile_inventory(report, inventory, bad_pages)
        except ValueError as error:
            if "not covered by the verified standard chain" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("unlinked digest inventory key was accepted")

        envelope, trusted = _inventory_fixture(root)
        inventory_artifact = next(item for item in envelope["manifestBody"]["artifacts"] if item["artifactType"] == INDEX_TYPE)
        inventory_path = root / inventory_artifact["artifactId"]
        inventory_path.write_bytes(inventory_path.read_bytes() + b" ")
        try:
            validate_inventory_manifest(envelope, trusted, root, allow_test_only=True)
        except ValueError as error:
            if "SHA-256 mismatch" not in str(error):
                raise
            cases += 1
        else:
            raise AssertionError("tampered inventory index artifact was accepted")
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--trusted-keys", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()
    supplied = (args.manifest, args.trusted_keys, args.artifact_root)
    if any(supplied) and not all(supplied):
        parser.error("--manifest, --trusted-keys and --artifact-root must be supplied together")
    if all(supplied):
        envelope = json.loads(args.manifest.read_text(encoding="utf-8"))
        trust = json.loads(args.trusted_keys.read_text(encoding="utf-8"))
        result = validate_inventory_manifest(envelope, trust["keys"], args.artifact_root)
        print(f"CloudTrail digest inventory reconciliation: {result['status']}")
        print(f"Standard digests: {result['verifiedStandardDigestCountInRange']}; inventory pages: {result['paginationPageCount']}")
        print(f"Complete within captured standard inventory: {result['completeWithinCapturedStandardInventory']}")
        print(f"Snapshot completeness: {result['absoluteSnapshotCompleteness']}")
        return
    cases = run_fixture_tests()
    print("FENCE-001 CloudTrail digest inventory reconciliation: PASS")
    print(f"Synthetic negative cases rejected: {cases}")
    print("Scope: synthetic S3 ListObjectVersions pages and dual-signed manifest only; no AWS account or provider API calls.")


if __name__ == "__main__":
    main()
