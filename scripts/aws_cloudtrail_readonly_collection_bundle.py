#!/usr/bin/env python3
"""Assemble a read-only CloudTrail qualification evidence bundle from injected AWS clients.

No credential discovery, SDK client construction, writes, deletes, or live calls
occur unless a caller explicitly supplies configured clients and invokes collect().
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aws_cloudtrail_readonly_adapters import (
    AwsCloudTrailPublicKeyProvider,
    CollectedDigestInventory,
    S3ListObjectVersionsInventoryCollector,
    S3VersionedEvidenceReader,
)
from aws_sts_caller_identity import AwsStsCallerIdentityVerifier
from validate_m0_fence_cloudtrail_digest_inventory import reconcile_inventory
from verify_m0_fence_cloudtrail_digest_chain import (
    CloudTrailDigestChainVerifier,
    ReadObject,
    VerificationReport,
)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _utc(value: datetime, field: str) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _object_id(kind: str, bucket: str, key: str, version_id: str) -> str:
    digest = hashlib.sha256(f"{bucket}\0{key}\0{version_id}".encode("utf-8")).hexdigest()[:24]
    return f"cloudtrail-{kind}-{digest}.bin"


class _RecordingReader:
    def __init__(self, delegate: S3VersionedEvidenceReader) -> None:
        self._delegate = delegate
        self.objects: dict[tuple[str, str, str], ReadObject] = {}

    def read_object(self, bucket: str, key: str, *, version_id: str | None = None) -> ReadObject:
        result = self._delegate.read_object(bucket, key, version_id=version_id)
        identity = (bucket, key, result.version_id)
        previous = self.objects.get(identity)
        if previous is not None and previous != result:
            raise ValueError("same S3 object version returned different bytes/metadata during one collection")
        self.objects[identity] = result
        return result


@dataclass(frozen=True)
class CloudTrailReadOnlyEvidenceBundle:
    index: dict[str, Any]
    artifacts: dict[str, bytes]
    inventory_reconciliation: dict[str, Any]
    verification_report: dict[str, Any]
    collector_identity: dict[str, Any]
    verifier_identity: dict[str, Any]
    provider_exchange: dict[str, Any]

    def summary(self) -> dict[str, Any]:
        return {
            "profile": "sky-high-cloudtrail-readonly-collection-bundle-v1",
            "schemaVersion": 1,
            "testOnly": self.index["testOnly"],
            "accountId": self.index["accountId"],
            "region": self.index["region"],
            "bucket": self.index["bucket"],
            "prefix": self.index["prefix"],
            "artifactCount": len(self.artifacts),
            "artifactIds": sorted(self.artifacts),
            "digestCount": self.verification_report["digestCount"],
            "logCount": self.verification_report["logCount"],
            "inventoryStatus": self.inventory_reconciliation["status"],
            "completeWithinCapturedInventory": self.inventory_reconciliation["completeWithinCapturedInventory"],
            "absoluteSnapshotCompleteness": self.inventory_reconciliation["absoluteSnapshotCompleteness"],
            "collectorCallerArn": self.collector_identity["callerArn"],
            "verifierCallerArn": self.verifier_identity["callerArn"],
            "productionQualificationReady": False,
            "manifestSigningStatus": "NOT_SIGNED",
            "externalQualificationStatus": "REQUIRED",
        }


class AwsCloudTrailReadOnlyCollection:
    """One-shot read-only evidence collector; all AWS clients are injected by caller."""

    def __init__(
        self,
        *,
        sts_collector_client: Any,
        sts_verifier_client: Any,
        cloudtrail_client: Any,
        s3_client: Any,
        account_id: str,
        region: str,
        bucket: str,
        digest_prefix: str,
        collector_role_arn: str,
        verifier_role_arn: str,
        log_prefixes: tuple[str, ...] = (),
    ) -> None:
        if collector_role_arn == verifier_role_arn:
            raise ValueError("collector and verifier must be configured with distinct IAM role ARNs")
        self._account = account_id
        self._region = region
        self._bucket = bucket
        self._prefix = digest_prefix
        self._collector_sts = AwsStsCallerIdentityVerifier(
            sts_collector_client, expected_account_id=account_id,
            expected_role_arn=collector_role_arn,
        )
        self._verifier_sts = AwsStsCallerIdentityVerifier(
            sts_verifier_client, expected_account_id=account_id,
            expected_role_arn=verifier_role_arn,
        )
        self._keys = AwsCloudTrailPublicKeyProvider(
            cloudtrail_client, expected_region=region,
        )
        self._s3_reader = S3VersionedEvidenceReader(
            s3_client, expected_bucket=bucket,
            allowed_prefixes=(digest_prefix, *log_prefixes),
        )
        self._inventory = S3ListObjectVersionsInventoryCollector(
            s3_client, expected_bucket=bucket, expected_prefix=digest_prefix,
        )

    def collect(
        self,
        *,
        standard_latest: tuple[str, str, str],
        backfill_latest: tuple[str, str, str] | None,
        requested_start_time: datetime,
        requested_end_time: datetime,
        test_only: bool,
        collection_started_at: datetime | None = None,
        collection_completed_at: datetime | None = None,
    ) -> CloudTrailReadOnlyEvidenceBundle:
        if type(test_only) is not bool:
            raise ValueError("test_only must be an explicit boolean")
        started = collection_started_at or datetime.now(timezone.utc)
        collector_identity = self._collector_sts.verify().to_dict(
            test_only=test_only, identity_role="COLLECTOR"
        )
        verifier_identity = self._verifier_sts.verify().to_dict(
            test_only=test_only, identity_role="INDEPENDENT_VERIFIER"
        )
        if collector_identity["callerArn"] == verifier_identity["callerArn"]:
            raise ValueError("collector and verifier STS caller ARNs must be distinct")
        if collector_identity["requestId"] == verifier_identity["requestId"]:
            raise ValueError("collector and verifier STS request IDs must be distinct")

        inventory = self._inventory.collect(
            account_id=self._account,
            region=self._region,
            requested_start_time=requested_start_time,
            requested_end_time=requested_end_time,
            test_only=test_only,
            collection_started_at=started,
            collection_completed_at=collection_completed_at,
        )

        recording_reader = _RecordingReader(self._s3_reader)
        verifier = CloudTrailDigestChainVerifier(
            recording_reader,
            self._keys,
            expected_account_id=self._account,
            expected_region=self._region,
            expected_digest_bucket=self._bucket,
        )
        report: VerificationReport = verifier.verify_standard_and_backfill(
            standard=standard_latest,
            backfill=backfill_latest,
        )
        report_data = report.to_dict(test_only=test_only)

        page_documents = [
            json.loads(raw.decode("utf-8"))
            for _, raw in sorted(inventory.page_artifacts.items())
        ]
        reconciliation = reconcile_inventory(report_data, inventory.index, page_documents)
        if not reconciliation["completeWithinCapturedInventory"]:
            raise ValueError(
                "captured S3 digest inventory is not fully covered by the supplied standard/backfill chains"
            )

        artifacts: dict[str, bytes] = {}
        artifacts["cloudtrail-verification-report.json"] = _json_bytes(report_data)
        artifacts["cloudtrail-inventory-index.json"] = inventory.index_bytes
        artifacts.update(inventory.page_artifacts)
        artifacts["aws-sts-collector-identity.json"] = _json_bytes(collector_identity)
        artifacts["aws-sts-independent-verifier-identity.json"] = _json_bytes(verifier_identity)

        object_catalog: list[dict[str, Any]] = []
        for (bucket, key, version_id), read in sorted(recording_reader.objects.items()):
            kind = "digest" if "/CloudTrail-Digest/" in key else "log"
            artifact_id = _object_id(kind, bucket, key, version_id)
            artifacts[artifact_id] = read.body
            object_catalog.append({
                "artifactId": artifact_id,
                "artifactType": "RAW_PROVIDER_EXCHANGE",
                "bucket": bucket,
                "key": key,
                "versionId": version_id,
                "sha256": hashlib.sha256(read.body).hexdigest(),
                "byteCount": len(read.body),
                "metadata": dict(sorted(read.metadata.items())),
            })

        public_key_catalog: dict[str, dict[str, Any]] = {}
        for digest in report_data["digests"]:
            key_info = digest["publicKey"]
            fingerprint = key_info["fingerprint"]
            der = base64.b64decode(key_info["derBase64"], validate=True)
            if hashlib.sha256(der).hexdigest() != key_info["derSha256"] or len(der) != key_info["derByteCount"]:
                raise ValueError("verification report public-key DER bytes failed their own digest/length binding")
            artifact_id = f"cloudtrail-public-key-{key_info['derSha256'][:24]}.der"
            artifacts[artifact_id] = der
            public_key_catalog[fingerprint] = {
                "artifactId": artifact_id,
                "artifactType": "RAW_PROVIDER_EXCHANGE",
                "region": self._region,
                "fingerprint": fingerprint,
                "sha256": key_info["derSha256"],
                "byteCount": key_info["derByteCount"],
                "validityStartTime": key_info["validityStartTime"],
                "validityEndTime": key_info["validityEndTime"],
            }

        provider_exchange = {
            "profile": "sky-high-cloudtrail-provider-exchange-v1",
            "schemaVersion": 1,
            "testOnly": test_only,
            "accountId": self._account,
            "region": self._region,
            "cloudTrailListPublicKeysRequestIds": list(self._keys.last_request_ids),
            "s3ObjectReads": object_catalog,
            "regionalPublicKeys": list(public_key_catalog.values()),
            "inventoryListObjectVersionsRequestIds": inventory.index["requestIds"],
            "collectionStartedAt": _utc(started, "collection_started_at"),
            "collectionCompletedAt": inventory.index["collectionEndTime"],
        }
        artifacts["cloudtrail-provider-exchange.json"] = _json_bytes(provider_exchange)

        index = {
            "profile": "sky-high-cloudtrail-readonly-collection-bundle-v1",
            "schemaVersion": 1,
            "testOnly": test_only,
            "accountId": self._account,
            "region": self._region,
            "bucket": self._bucket,
            "prefix": self._prefix,
            "requestedStartTime": inventory.index["requestedStartTime"],
            "requestedEndTime": inventory.index["requestedEndTime"],
            "collectionStartTime": inventory.index["collectionStartTime"],
            "collectionEndTime": inventory.index["collectionEndTime"],
            "artifactCount": len(artifacts),
            "artifacts": sorted(artifacts),
            "verificationStatus": report_data["verificationStatus"],
            "inventoryStatus": reconciliation["status"],
            "completeWithinCapturedInventory": reconciliation["completeWithinCapturedInventory"],
            "absoluteSnapshotCompleteness": reconciliation["absoluteSnapshotCompleteness"],
            "manifestSigningStatus": "NOT_SIGNED",
            "productionQualificationReady": False,
        }
        artifacts["collection-bundle-index.json"] = _json_bytes(index)
        return CloudTrailReadOnlyEvidenceBundle(
            index=index,
            artifacts=artifacts,
            inventory_reconciliation=reconciliation,
            verification_report=report_data,
            collector_identity=collector_identity,
            verifier_identity=verifier_identity,
            provider_exchange=provider_exchange,
        )
