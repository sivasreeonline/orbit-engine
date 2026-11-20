#!/usr/bin/env python3
"""Injected, read-only AWS CloudTrail/S3 adapters with no credential discovery."""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from verify_m0_fence_cloudtrail_digest_chain import ReadObject


MAX_PUBLIC_KEY_PAGES = 100
MAX_INVENTORY_PAGES = 10000


def _utc_text(value: Any, field: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as error:
            raise ValueError(f"{field} is not a valid ISO-8601 timestamp") from error
    else:
        raise ValueError(f"{field} must be a datetime or ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _response_request_id(response: dict[str, Any]) -> str | None:
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, dict):
        return None
    request_id = metadata.get("RequestId")
    return request_id if isinstance(request_id, str) and request_id else None


class AwsCloudTrailPublicKeyProvider:
    """Read-only CloudTrail ListPublicKeys adapter around an injected client."""

    def __init__(self, client: Any, *, expected_region: str) -> None:
        if not expected_region:
            raise ValueError("expected_region is required")
        client_region = getattr(getattr(client, "meta", None), "region_name", None)
        if client_region is not None and client_region != expected_region:
            raise ValueError("injected CloudTrail client Region differs from expected_region")
        if not callable(getattr(client, "list_public_keys", None)):
            raise TypeError("injected CloudTrail client must provide list_public_keys")
        self._client = client
        self._region = expected_region
        self.last_request_ids: tuple[str, ...] = ()

    def list_public_keys(
        self, region: str, start_time: datetime, end_time: datetime
    ) -> list[dict[str, Any]]:
        if region != self._region:
            raise ValueError("CloudTrail public-key request Region differs from pinned Region")
        if start_time.tzinfo is None or end_time.tzinfo is None or start_time >= end_time:
            raise ValueError("CloudTrail public-key lookup requires an ordered aware time range")
        token: str | None = None
        seen_tokens: set[str] = set()
        request_ids: list[str] = []
        records: list[dict[str, Any]] = []
        for _ in range(MAX_PUBLIC_KEY_PAGES):
            request: dict[str, Any] = {"StartTime": start_time, "EndTime": end_time}
            if token is not None:
                request["NextToken"] = token
            response = self._client.list_public_keys(**request)
            if not isinstance(response, dict):
                raise ValueError("CloudTrail ListPublicKeys response must be an object")
            request_id = _response_request_id(response)
            if request_id:
                request_ids.append(request_id)
            page = response.get("PublicKeyList")
            if not isinstance(page, list):
                raise ValueError("CloudTrail ListPublicKeys response lacks PublicKeyList")
            for item in page:
                if not isinstance(item, dict):
                    raise ValueError("CloudTrail public-key entry must be an object")
                fingerprint = item.get("Fingerprint")
                value = item.get("Value")
                if isinstance(value, str):
                    try:
                        value = base64.b64decode(value, validate=True)
                    except (ValueError, binascii.Error) as error:
                        raise ValueError("CloudTrail public-key Value is not valid base64/DER") from error
                if not isinstance(fingerprint, str) or not fingerprint or not isinstance(value, bytes):
                    raise ValueError("CloudTrail public-key fingerprint or DER Value is missing")
                start = item.get("ValidityStartTime")
                end = item.get("ValidityEndTime")
                if not isinstance(start, datetime) or not isinstance(end, datetime):
                    raise ValueError("CloudTrail public-key validity timestamps must be datetimes")
                records.append({
                    "Fingerprint": fingerprint,
                    "Value": value,
                    "ValidityStartTime": start,
                    "ValidityEndTime": end,
                })
            next_token = response.get("NextToken")
            if next_token is None:
                self.last_request_ids = tuple(request_ids)
                return records
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                raise ValueError("CloudTrail ListPublicKeys returned an invalid or repeated NextToken")
            seen_tokens.add(next_token)
            token = next_token
        raise ValueError("CloudTrail ListPublicKeys exceeded the maximum page count")


class S3VersionedEvidenceReader:
    """Read-only S3 GetObject adapter that returns exact VersionId and user metadata."""

    def __init__(
        self,
        client: Any,
        *,
        expected_bucket: str,
        allowed_prefixes: tuple[str, ...] = (),
    ) -> None:
        if not expected_bucket:
            raise ValueError("expected_bucket is required")
        if not callable(getattr(client, "get_object", None)):
            raise TypeError("injected S3 client must provide get_object")
        self._client = client
        self._bucket = expected_bucket
        self._prefixes = allowed_prefixes

    def read_object(
        self, bucket: str, key: str, *, version_id: str | None = None
    ) -> ReadObject:
        if bucket != self._bucket:
            raise ValueError("S3 evidence read bucket differs from the pinned bucket")
        if not isinstance(key, str) or not key:
            raise ValueError("S3 evidence object key is required")
        if self._prefixes and not any(key.startswith(prefix) for prefix in self._prefixes):
            raise ValueError("S3 evidence object key is outside the configured prefixes")
        request: dict[str, Any] = {"Bucket": bucket, "Key": key}
        if version_id is not None:
            if not isinstance(version_id, str) or not version_id or version_id == "null":
                raise ValueError("requested S3 VersionId must be exact and non-null")
            request["VersionId"] = version_id
        response = self._client.get_object(**request)
        if not isinstance(response, dict):
            raise ValueError("S3 GetObject response must be an object")
        actual_version = response.get("VersionId")
        if not isinstance(actual_version, str) or not actual_version or actual_version == "null":
            raise ValueError("S3 GetObject did not return an exact non-null VersionId")
        if version_id is not None and actual_version != version_id:
            raise ValueError("S3 GetObject returned a different VersionId than requested")
        body_stream = response.get("Body")
        if isinstance(body_stream, bytes):
            body = body_stream
        elif callable(getattr(body_stream, "read", None)):
            body = body_stream.read()
            close = getattr(body_stream, "close", None)
            if callable(close):
                close()
        else:
            raise ValueError("S3 GetObject response Body is not a readable byte stream")
        if not isinstance(body, bytes) or not body:
            raise ValueError("S3 GetObject returned an empty or invalid body")
        content_length = response.get("ContentLength")
        if content_length is not None and content_length != len(body):
            raise ValueError("S3 GetObject ContentLength differs from returned bytes")
        metadata = response.get("Metadata", {})
        if not isinstance(metadata, dict) or any(
            not isinstance(key_name, str) or not isinstance(value, str)
            for key_name, value in metadata.items()
        ):
            raise ValueError("S3 GetObject Metadata must be a string map")
        return ReadObject(
            body=body,
            version_id=actual_version,
            metadata={key_name.lower(): value for key_name, value in metadata.items()},
        )


@dataclass(frozen=True)
class CollectedDigestInventory:
    index: dict[str, Any]
    index_bytes: bytes
    page_artifacts: dict[str, bytes]


class S3ListObjectVersionsInventoryCollector:
    """Capture read-only S3 ListObjectVersions pages in the manifest inventory format."""

    def __init__(self, client: Any, *, expected_bucket: str, expected_prefix: str) -> None:
        if not expected_bucket or not expected_prefix:
            raise ValueError("expected_bucket and expected_prefix are required")
        if not callable(getattr(client, "list_object_versions", None)):
            raise TypeError("injected S3 client must provide list_object_versions")
        self._client = client
        self._bucket = expected_bucket
        self._prefix = expected_prefix

    def collect(
        self,
        *,
        account_id: str,
        region: str,
        requested_start_time: datetime,
        requested_end_time: datetime,
        test_only: bool,
        collection_started_at: datetime | None = None,
        collection_completed_at: datetime | None = None,
    ) -> CollectedDigestInventory:
        if type(test_only) is not bool:
            raise ValueError("test_only must be an explicit boolean")
        required_prefix = f"AWSLogs/{account_id}/CloudTrail-Digest/{region}/"
        if not self._prefix.endswith(required_prefix):
            raise ValueError("expected_prefix is not scoped to the pinned CloudTrail account/Region")
        if requested_start_time.tzinfo is None or requested_end_time.tzinfo is None or requested_start_time >= requested_end_time:
            raise ValueError("requested inventory window must be ordered and timezone-aware")
        started = collection_started_at or datetime.now(timezone.utc)
        if started.tzinfo is None:
            raise ValueError("collection_started_at must be timezone-aware")

        page_artifacts: dict[str, bytes] = {}
        page_index: list[dict[str, Any]] = []
        key_marker: str | None = None
        version_marker: str | None = None
        seen_markers: set[tuple[str | None, str | None]] = set()
        request_ids: list[str] = []

        for page_number in range(1, MAX_INVENTORY_PAGES + 1):
            marker = (key_marker, version_marker)
            if marker in seen_markers:
                raise ValueError("S3 ListObjectVersions pagination markers repeated")
            seen_markers.add(marker)
            request: dict[str, Any] = {"Bucket": self._bucket, "Prefix": self._prefix}
            if key_marker is not None:
                request["KeyMarker"] = key_marker
            if version_marker is not None:
                request["VersionIdMarker"] = version_marker
            response = self._client.list_object_versions(**request)
            if not isinstance(response, dict):
                raise ValueError("S3 ListObjectVersions response must be an object")
            if response.get("Name") != self._bucket or response.get("Prefix") != self._prefix:
                raise ValueError("S3 ListObjectVersions response bucket/prefix differs from pinned scope")
            if response.get("KeyMarker", key_marker) != key_marker or response.get("VersionIdMarker", version_marker) != version_marker:
                raise ValueError("S3 ListObjectVersions response request markers differ from the issued request")
            truncated = response.get("IsTruncated")
            if type(truncated) is not bool:
                raise ValueError("S3 ListObjectVersions response lacks boolean IsTruncated")
            versions = response.get("Versions", [])
            delete_markers = response.get("DeleteMarkers", [])
            if not isinstance(versions, list) or not isinstance(delete_markers, list):
                raise ValueError("S3 ListObjectVersions Versions/DeleteMarkers must be arrays")
            next_key = response.get("NextKeyMarker")
            next_version = response.get("NextVersionIdMarker")
            if truncated:
                if not isinstance(next_key, str) or not next_key or not isinstance(next_version, str) or not next_version:
                    raise ValueError("truncated S3 ListObjectVersions response lacks continuation markers")
            elif next_key is not None or next_version is not None:
                raise ValueError("non-truncated S3 ListObjectVersions response has continuation markers")

            normalized_versions = []
            for item in versions:
                if not isinstance(item, dict):
                    raise ValueError("S3 Version entry must be an object")
                normalized_versions.append({
                    "Key": item.get("Key"),
                    "VersionId": item.get("VersionId"),
                    "IsLatest": item.get("IsLatest"),
                    "LastModified": _utc_text(item.get("LastModified"), "Version.LastModified"),
                    "Size": item.get("Size"),
                    "ETag": item.get("ETag"),
                    "StorageClass": item.get("StorageClass"),
                })
            normalized_delete_markers = []
            for item in delete_markers:
                if not isinstance(item, dict):
                    raise ValueError("S3 DeleteMarker entry must be an object")
                normalized_delete_markers.append({
                    "Key": item.get("Key"),
                    "VersionId": item.get("VersionId"),
                    "IsLatest": item.get("IsLatest"),
                    "LastModified": _utc_text(item.get("LastModified"), "DeleteMarker.LastModified"),
                })

            request_id = _response_request_id(response)
            if request_id:
                request_ids.append(request_id)
            page = {
                "Name": self._bucket,
                "Prefix": self._prefix,
                "KeyMarker": key_marker,
                "VersionIdMarker": version_marker,
                "IsTruncated": truncated,
                "NextKeyMarker": next_key,
                "NextVersionIdMarker": next_version,
                "Versions": normalized_versions,
                "DeleteMarkers": normalized_delete_markers,
                "RequestId": request_id,
            }
            artifact_id = f"cloudtrail-inventory-page-{page_number:04d}.json"
            page_bytes = json.dumps(page, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            page_artifacts[artifact_id] = page_bytes
            page_index.append({
                "artifactId": artifact_id,
                "requestKeyMarker": key_marker,
                "requestVersionIdMarker": version_marker,
                "nextKeyMarker": next_key,
                "nextVersionIdMarker": next_version,
                "isTruncated": truncated,
                "requestId": request_id,
            })
            if not truncated:
                break
            key_marker, version_marker = next_key, next_version
        else:
            raise ValueError("S3 ListObjectVersions exceeded the maximum page count")

        completed = collection_completed_at or datetime.now(timezone.utc)
        if completed.tzinfo is None or completed < started:
            raise ValueError("collection_completed_at must be timezone-aware and not precede start")

        index = {
            "profile": "sky-high-cloudtrail-digest-inventory-v1",
            "schemaVersion": 1,
            "testOnly": test_only,
            "accountId": account_id,
            "region": region,
            "bucket": self._bucket,
            "prefix": self._prefix,
            "requestedStartTime": _utc_text(requested_start_time, "requested_start_time"),
            "requestedEndTime": _utc_text(requested_end_time, "requested_end_time"),
            "collectionStartTime": _utc_text(started, "collection_started_at"),
            "collectionEndTime": _utc_text(completed, "collection_completed_at"),
            "paginationComplete": True,
            "pageCount": len(page_index),
            "requestIds": request_ids,
            "pages": page_index,
        }
        index_bytes = json.dumps(index, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return CollectedDigestInventory(index, index_bytes, page_artifacts)
