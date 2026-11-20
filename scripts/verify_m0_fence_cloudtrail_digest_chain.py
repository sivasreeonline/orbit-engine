#!/usr/bin/env python3
"""Offline, fail-closed AWS CloudTrail digest-chain verifier.

This module has no AWS SDK, credential discovery, network client, or account
side effects. Callers inject exact-version evidence reads and a regional
ListPublicKeys provider. CI exercises only synthetic RSA keys and gzip files.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_DIGEST_COMPRESSED_BYTES = 16 * 1024 * 1024
MAX_DIGEST_JSON_BYTES = 16 * 1024 * 1024
MAX_LOG_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_LOG_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_CHAIN_DEPTH = 1000


class DigestVerificationError(RuntimeError):
    """A digest, signature, referenced log, or chain binding failed."""


@dataclass(frozen=True)
class ReadObject:
    body: bytes
    version_id: str
    metadata: dict[str, str]


@dataclass(frozen=True)
class VerifiedLog:
    bucket: str
    key: str
    version_id: str
    raw_sha256: str
    raw_byte_count: int
    uncompressed_sha256: str
    uncompressed_byte_count: int


@dataclass(frozen=True)
class VerifiedDigest:
    bucket: str
    key: str
    version_id: str
    raw_sha256: str
    raw_byte_count: int
    uncompressed_sha256: str
    uncompressed_byte_count: int
    signature_hex: str
    signature_algorithm: str
    signature_fingerprint: str
    public_key_der_sha256: str
    public_key_der_byte_count: int
    public_key_der_base64: str
    public_key_validity_start: str
    public_key_validity_end: str
    digest_start_time: str
    digest_end_time: str
    logs: tuple[VerifiedLog, ...]


@dataclass(frozen=True)
class VerificationReport:
    account_id: str
    region: str
    digests: tuple[VerifiedDigest, ...]

    @property
    def digest_count(self) -> int:
        return len(self.digests)

    @property
    def log_count(self) -> int:
        return sum(len(item.logs) for item in self.digests)

    def to_dict(self, *, test_only: bool) -> dict[str, Any]:
        """Serialize a custody-ready report; callers must explicitly label fixture runs."""
        if type(test_only) is not bool:
            raise ValueError("test_only must be an explicit boolean")
        return {
            "profile": "sky-high-cloudtrail-digest-verification-v1",
            "schemaVersion": 1,
            "testOnly": test_only,
            "accountId": self.account_id,
            "region": self.region,
            "verificationStatus": "CHAIN_AND_REFERENCED_OBJECTS_VERIFIED",
            "completenessStatus": "NOT_ESTABLISHED_BY_CHAIN_WALK",
            "digestCount": self.digest_count,
            "logCount": self.log_count,
            "digests": [
                {
                    "bucket": digest.bucket,
                    "key": digest.key,
                    "versionId": digest.version_id,
                    "rawSha256": digest.raw_sha256,
                    "rawByteCount": digest.raw_byte_count,
                    "uncompressedSha256": digest.uncompressed_sha256,
                    "uncompressedByteCount": digest.uncompressed_byte_count,
                    "signatureHex": digest.signature_hex,
                    "signatureAlgorithm": digest.signature_algorithm,
                    "signatureFingerprint": digest.signature_fingerprint,
                    "publicKey": {
                        "region": self.region,
                        "fingerprint": digest.signature_fingerprint,
                        "derSha256": digest.public_key_der_sha256,
                        "derByteCount": digest.public_key_der_byte_count,
                        "derBase64": digest.public_key_der_base64,
                        "validityStartTime": digest.public_key_validity_start,
                        "validityEndTime": digest.public_key_validity_end,
                    },
                    "logs": [
                        {
                            "bucket": log.bucket,
                            "key": log.key,
                            "versionId": log.version_id,
                            "rawSha256": log.raw_sha256,
                            "rawByteCount": log.raw_byte_count,
                            "uncompressedSha256": log.uncompressed_sha256,
                            "uncompressedByteCount": log.uncompressed_byte_count,
                        }
                        for log in digest.logs
                    ],
                }
                for digest in self.digests
            ],
        }


class EvidenceReader(Protocol):
    def read_object(
        self, bucket: str, key: str, *, version_id: str | None = None
    ) -> ReadObject: ...


class PublicKeyProvider(Protocol):
    def list_public_keys(
        self, region: str, start_time: datetime, end_time: datetime
    ) -> list[dict[str, Any]]: ...


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise DigestVerificationError(f"{field} must be a non-empty UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise DigestVerificationError(f"{field} is not a valid ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DigestVerificationError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _bounded_gunzip(raw: bytes, *, compressed_limit: int, output_limit: int, label: str) -> bytes:
    if not isinstance(raw, bytes) or not raw:
        raise DigestVerificationError(f"{label} is empty or not bytes")
    if len(raw) > compressed_limit:
        raise DigestVerificationError(f"{label} exceeds the compressed byte limit")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            content = stream.read(output_limit + 1)
    except (OSError, EOFError) as error:
        raise DigestVerificationError(f"{label} is not a valid gzip stream") from error
    if len(content) > output_limit:
        raise DigestVerificationError(f"{label} exceeds the decompressed byte limit")
    return content


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DigestVerificationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _parse_digest(raw: bytes, bucket: str, key: str) -> tuple[dict[str, Any], bytes]:
    uncompressed = _bounded_gunzip(
        raw,
        compressed_limit=MAX_DIGEST_COMPRESSED_BYTES,
        output_limit=MAX_DIGEST_JSON_BYTES,
        label="CloudTrail digest object",
    )
    try:
        document = json.loads(
            uncompressed.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DigestVerificationError("CloudTrail digest JSON is invalid UTF-8 or malformed") from error
    if not isinstance(document, dict):
        raise DigestVerificationError("CloudTrail digest root must be a JSON object")
    if document.get("digestS3Bucket") != bucket or document.get("digestS3Object") != key:
        raise DigestVerificationError("digest was moved from its original S3 bucket/key")
    return document, uncompressed


def _validate_scope(document: dict[str, Any], bucket: str, key: str, account_id: str, region: str) -> None:
    if document.get("awsAccountId") != account_id:
        raise DigestVerificationError("digest account ID differs from the pinned qualification account")
    if document.get("digestS3Bucket") != bucket:
        raise DigestVerificationError("digest bucket differs from the pinned evidence bucket")
    marker = f"/{account_id}/CloudTrail-Digest/{region}/"
    if marker not in f"/{key}":
        raise DigestVerificationError("digest object path is outside the pinned account/Region digest prefix")
    if key.endswith("_backfill.json.gz"):
        raise DigestVerificationError("backfill digest chains are a separate qualification scope")


def _load_public_key(
    provider: PublicKeyProvider,
    region: str,
    fingerprint: str,
    digest_start: datetime,
    digest_end: datetime,
) -> tuple[rsa.RSAPublicKey, bytes, datetime, datetime]:
    records = provider.list_public_keys(region, digest_start, digest_end)
    matches = [item for item in records if item.get("Fingerprint") == fingerprint]
    if len(matches) != 1:
        raise DigestVerificationError("regional CloudTrail public-key fingerprint is missing or ambiguous")
    record = matches[0]
    start = record.get("ValidityStartTime")
    end = record.get("ValidityEndTime")
    if not isinstance(start, datetime) or not isinstance(end, datetime):
        raise DigestVerificationError("CloudTrail public-key validity interval is missing")
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if not (start.astimezone(timezone.utc) <= digest_end <= end.astimezone(timezone.utc)):
        raise DigestVerificationError("CloudTrail public key is not valid at digestEndTime")
    value = record.get("Value")
    if not isinstance(value, bytes):
        raise DigestVerificationError("CloudTrail public-key Value must be DER bytes")
    try:
        public_key = serialization.load_der_public_key(value)
    except (TypeError, ValueError) as error:
        raise DigestVerificationError("CloudTrail public key is not valid DER") from error
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise DigestVerificationError("CloudTrail digest signing key is not RSA")
    return public_key, value, start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def _verify_digest_signature(
    document: dict[str, Any],
    uncompressed_digest: bytes,
    bucket: str,
    key: str,
    signature_hex: str,
    provider: PublicKeyProvider,
    region: str,
) -> tuple[str, bytes, datetime, datetime]:
    if document.get("digestSignatureAlgorithm") != "SHA256withRSA":
        raise DigestVerificationError("unsupported CloudTrail digest signature algorithm")
    fingerprint = document.get("digestPublicKeyFingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise DigestVerificationError("digestPublicKeyFingerprint is missing")
    digest_end_text = document.get("digestEndTime")
    digest_end = _parse_time(digest_end_text, "digestEndTime")
    digest_start = _parse_time(document.get("digestStartTime"), "digestStartTime")
    previous_signature = document.get("previousDigestSignature")
    if previous_signature is None:
        previous_signature = "null"
    if not isinstance(previous_signature, str):
        raise DigestVerificationError("previousDigestSignature must be hex text or null")
    if previous_signature and (len(previous_signature) % 2 or not re.fullmatch(r"[0-9a-f]+", previous_signature)):
        raise DigestVerificationError("previousDigestSignature is not lowercase hexadecimal")
    if not isinstance(signature_hex, str) or not signature_hex or len(signature_hex) % 2:
        raise DigestVerificationError("digest signature metadata is missing or malformed")
    if not re.fullmatch(r"[0-9a-f]+", signature_hex):
        raise DigestVerificationError("digest signature metadata is not lowercase hexadecimal")

    digest_hash = hashlib.sha256(uncompressed_digest).hexdigest()
    data_to_sign = (
        f"{digest_end_text}\n"
        f"{bucket}/{key}\n"
        f"{digest_hash}\n"
        f"{previous_signature}"
    ).encode("utf-8")
    public_key, public_key_der, key_valid_from, key_valid_to = _load_public_key(
        provider, region, fingerprint, digest_start, digest_end
    )
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as error:
        raise DigestVerificationError("CloudTrail digest RSA signature verification failed") from error
    return fingerprint, public_key_der, key_valid_from, key_valid_to


def _verify_logs(
    document: dict[str, Any],
    reader: EvidenceReader,
    account_id: str,
    region: str,
) -> tuple[VerifiedLog, ...]:
    entries = document.get("logFiles")
    if not isinstance(entries, list):
        raise DigestVerificationError("digest logFiles must be an array")
    verified: list[VerifiedLog] = []
    seen: set[tuple[str, str]] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise DigestVerificationError("digest logFiles entry must be an object")
        bucket = item.get("s3Bucket")
        key = item.get("s3Object")
        expected_hash = item.get("hashValue")
        if not isinstance(bucket, str) or not bucket or not isinstance(key, str) or not key:
            raise DigestVerificationError("digest log file bucket/key is missing")
        if bucket != document.get("digestS3Bucket"):
            raise DigestVerificationError("log file bucket differs from the digest evidence bucket")
        marker = f"/{account_id}/CloudTrail/{region}/"
        if marker not in f"/{key}":
            raise DigestVerificationError("log object path is outside the pinned account/Region CloudTrail prefix")
        if item.get("hashAlgorithm") != "SHA-256" or not isinstance(expected_hash, str) or not HEX_SHA256.fullmatch(expected_hash):
            raise DigestVerificationError("log file hash algorithm/value is unsupported or malformed")
        ref = (bucket, key)
        if ref in seen:
            raise DigestVerificationError("digest contains a duplicate log object reference")
        seen.add(ref)
        read = reader.read_object(bucket, key)
        if not isinstance(read.version_id, str) or not read.version_id or read.version_id == "null":
            raise DigestVerificationError("CloudTrail log read did not return an exact non-null S3 VersionId")
        content = _bounded_gunzip(
            read.body,
            compressed_limit=MAX_LOG_COMPRESSED_BYTES,
            output_limit=MAX_LOG_UNCOMPRESSED_BYTES,
            label="CloudTrail log object",
        )
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise DigestVerificationError("CloudTrail log file SHA-256 does not match its digest entry")
        verified.append(
            VerifiedLog(
                bucket=bucket,
                key=key,
                version_id=read.version_id,
                raw_sha256=hashlib.sha256(read.body).hexdigest(),
                raw_byte_count=len(read.body),
                uncompressed_sha256=actual_hash,
                uncompressed_byte_count=len(content),
            )
        )
    return tuple(verified)


class CloudTrailDigestChainVerifier:
    def __init__(
        self,
        reader: EvidenceReader,
        public_keys: PublicKeyProvider,
        *,
        expected_account_id: str,
        expected_region: str,
        expected_digest_bucket: str,
        max_chain_depth: int = 1000,
    ) -> None:
        if not re.fullmatch(r"[0-9]{12}", expected_account_id):
            raise ValueError("expected_account_id must be a 12-digit AWS account ID")
        if not re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-\d", expected_region):
            raise ValueError("expected_region is not a valid AWS Region identifier")
        if not expected_digest_bucket.strip():
            raise ValueError("expected_digest_bucket is required")
        if type(max_chain_depth) is not int or not 1 <= max_chain_depth <= MAX_CHAIN_DEPTH:
            raise ValueError("max_chain_depth must be between 1 and 1000")
        self._reader = reader
        self._public_keys = public_keys
        self._account = expected_account_id
        self._region = expected_region
        self._bucket = expected_digest_bucket
        self._max_depth = max_chain_depth

    def verify_chain(
        self,
        latest_bucket: str,
        latest_key: str,
        *,
        latest_version_id: str,
    ) -> VerificationReport:
        if latest_bucket != self._bucket:
            raise DigestVerificationError("latest digest bucket differs from the pinned bucket")
        if not isinstance(latest_version_id, str) or not latest_version_id or latest_version_id == "null":
            raise DigestVerificationError("latest digest requires an exact non-null S3 VersionId")

        bucket, key = latest_bucket, latest_key
        requested_version: str | None = latest_version_id
        supplied_signature: str | None = None
        expected_predecessor_hash: str | None = None
        previous_end: datetime | None = None
        visited: set[tuple[str, str, str]] = set()
        verified: list[VerifiedDigest] = []

        for _ in range(self._max_depth):
            read = self._reader.read_object(bucket, key, version_id=requested_version)
            if not isinstance(read.version_id, str) or not read.version_id or read.version_id == "null":
                raise DigestVerificationError("digest read did not return an exact non-null S3 VersionId")
            if requested_version is not None and read.version_id != requested_version:
                raise DigestVerificationError("S3 returned a different digest VersionId than requested")
            identity = (bucket, key, read.version_id)
            if identity in visited:
                raise DigestVerificationError("CloudTrail digest chain contains a cycle")
            visited.add(identity)

            document, uncompressed = _parse_digest(read.body, bucket, key)
            _validate_scope(document, bucket, key, self._account, self._region)
            start = _parse_time(document.get("digestStartTime"), "digestStartTime")
            end = _parse_time(document.get("digestEndTime"), "digestEndTime")
            if start >= end:
                raise DigestVerificationError("digestStartTime must be earlier than digestEndTime")
            if previous_end is not None and end >= previous_end:
                raise DigestVerificationError("previous digest is not earlier than its successor")
            if expected_predecessor_hash is not None:
                actual_predecessor_hash = hashlib.sha256(uncompressed).hexdigest()
                if actual_predecessor_hash != expected_predecessor_hash:
                    raise DigestVerificationError("previousDigestHashValue does not match the fetched predecessor")
            signature = supplied_signature
            if signature is None:
                signature = read.metadata.get("signature")
            if not isinstance(signature, str) or not signature:
                raise DigestVerificationError("current digest S3 object metadata has no signature")
            fingerprint, public_key_der, key_valid_from, key_valid_to = _verify_digest_signature(
                document, uncompressed, bucket, key, signature, self._public_keys, self._region
            )
            logs = _verify_logs(document, self._reader, self._account, self._region)
            verified.append(
                VerifiedDigest(
                    bucket=bucket,
                    key=key,
                    version_id=read.version_id,
                    raw_sha256=hashlib.sha256(read.body).hexdigest(),
                    raw_byte_count=len(read.body),
                    uncompressed_sha256=hashlib.sha256(uncompressed).hexdigest(),
                    uncompressed_byte_count=len(uncompressed),
                    signature_hex=signature,
                    signature_algorithm=document["digestSignatureAlgorithm"],
                    signature_fingerprint=fingerprint,
                    public_key_der_sha256=hashlib.sha256(public_key_der).hexdigest(),
                    public_key_der_byte_count=len(public_key_der),
                    public_key_der_base64=base64.b64encode(public_key_der).decode("ascii"),
                    public_key_validity_start=key_valid_from.isoformat().replace("+00:00", "Z"),
                    public_key_validity_end=key_valid_to.isoformat().replace("+00:00", "Z"),
                    digest_start_time=document["digestStartTime"],
                    digest_end_time=document["digestEndTime"],
                    logs=logs,
                )
            )

            previous_bucket = document.get("previousDigestS3Bucket")
            previous_key = document.get("previousDigestS3Object")
            previous_hash = document.get("previousDigestHashValue")
            previous_hash_algorithm = document.get("previousDigestHashAlgorithm")
            previous_signature = document.get("previousDigestSignature")
            previous_fields = (previous_bucket, previous_key, previous_hash, previous_hash_algorithm, previous_signature)
            if all(value is None for value in previous_fields):
                return VerificationReport(self._account, self._region, tuple(verified))
            if any(value is None for value in previous_fields):
                raise DigestVerificationError("previous digest linkage is partially populated")
            if previous_bucket != self._bucket or not isinstance(previous_key, str) or not previous_key:
                raise DigestVerificationError("previous digest reference is outside the pinned bucket or malformed")
            if previous_hash_algorithm != "SHA-256" or not isinstance(previous_hash, str) or not HEX_SHA256.fullmatch(previous_hash):
                raise DigestVerificationError("previous digest hash binding is unsupported or malformed")
            if not isinstance(previous_signature, str) or not previous_signature:
                raise DigestVerificationError("previous digest signature binding is missing")
            previous_end = end
            bucket, key = previous_bucket, previous_key
            requested_version = None
            supplied_signature = previous_signature
            expected_predecessor_hash = previous_hash

        raise DigestVerificationError("CloudTrail digest chain exceeds the configured maximum depth")


def main() -> None:
    print("CloudTrail digest verifier module: importable contract only")
    print("No AWS SDK, credentials, network access, or provider API calls are used.")


if __name__ == "__main__":
    main()
