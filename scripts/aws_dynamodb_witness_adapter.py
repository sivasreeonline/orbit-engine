#!/usr/bin/env python3
"""AWS DynamoDB implementation of the provider-neutral FENCE-001 witness contract.

The adapter stores a mutable high-water pointer and append-only generation,
operation and idempotency records in one DynamoDB table. Every append is one
TransactWriteItems operation. All authoritative reads use ConsistentRead=True.

Live factory creation is guarded by an explicit write opt-in, a run-bound
approval file, a pinned read-only preflight report, an expected account/Region/
table ARN, and STS + DescribeTable identity checks. The self-test uses only an
in-memory DynamoDB API double and never creates AWS clients or reads credentials.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any

import rfc8785

from validate_m0_witness_provider_adapter_conformance import (
    AmbiguousCommit,
    AppendConflict,
    Checkpoint,
    IdempotencyConflict,
    Receipt,
    Scope,
    StoredCheckpoint,
    run_conformance,
)

PROFILE = "sky-high-fence-aws-dynamodb-witness-v1"
APPROVAL_PROFILE = "sky-high-fence-aws-dynamodb-witness-write-approval-v1"
WRITE_OPT_IN = "I_APPROVE_DYNAMODB_WITNESS_CONFORMANCE_WRITES_TO_THIS_DISPOSABLE_TABLE"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_FUTURE_SKEW = timedelta(minutes=2)


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def _jcs(value: Any) -> str:
    return rfc8785.dumps(value).decode("utf-8")


def _scope_body(scope: Scope) -> dict[str, str]:
    return {
        "trustDomainId": scope.trust_domain_id,
        "witnessId": scope.witness_id,
        "authorityId": scope.authority_id,
        "hostId": scope.host_id,
    }


def _checkpoint_body(value: Checkpoint) -> dict[str, Any]:
    return {
        "scope": _scope_body(value.scope),
        "generation": value.generation,
        "operationId": value.operation_id,
        "phase": value.phase,
        "checkpointDigest": value.checkpoint_digest,
        "previousDigest": value.previous_digest,
    }


def _receipt_body(value: Receipt) -> dict[str, Any]:
    return {
        "scope": _scope_body(value.scope),
        "generation": value.generation,
        "operationId": value.operation_id,
        "checkpointDigest": value.checkpoint_digest,
        "previousDigest": value.previous_digest,
        "consistencyToken": value.consistency_token,
    }


def _scope_from(body: dict[str, Any]) -> Scope:
    return Scope(
        trust_domain_id=body["trustDomainId"],
        witness_id=body["witnessId"],
        authority_id=body["authorityId"],
        host_id=body["hostId"],
    )


def _checkpoint_from_json(raw: str) -> Checkpoint:
    body = json.loads(raw)
    return Checkpoint(
        scope=_scope_from(body["scope"]),
        generation=body["generation"],
        operation_id=body["operationId"],
        phase=body["phase"],
        checkpoint_digest=body["checkpointDigest"],
        previous_digest=body["previousDigest"],
    )


def _receipt_from_json(raw: str) -> Receipt:
    body = json.loads(raw)
    return Receipt(
        scope=_scope_from(body["scope"]),
        generation=body["generation"],
        operation_id=body["operationId"],
        checkpoint_digest=body["checkpointDigest"],
        previous_digest=body["previousDigest"],
        consistency_token=body["consistencyToken"],
    )


def _av_s(item: dict[str, Any], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, dict) or not isinstance(value.get("S"), str):
        raise ValueError(f"DynamoDB item is missing string attribute {name}")
    return value["S"]


def _av_n(item: dict[str, Any], name: str) -> int:
    value = item.get(name)
    if not isinstance(value, dict) or not isinstance(value.get("N"), str):
        raise ValueError(f"DynamoDB item is missing numeric attribute {name}")
    return int(value["N"])


def _error_code(error: Exception) -> str | None:
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return None
    detail = response.get("Error", {})
    return detail.get("Code") if isinstance(detail, dict) else None


def _is_ambiguous_transport_error(error: Exception) -> bool:
    code = _error_code(error)
    if code in {
        "RequestTimeout", "RequestTimeoutException", "InternalServerError",
        "ServiceUnavailable", "ServiceUnavailableException",
        "PriorRequestNotComplete",
    }:
        return True
    name = type(error).__name__
    return name in {
        "EndpointConnectionError", "ReadTimeoutError", "ConnectTimeoutError",
        "ConnectionClosedError", "ConnectionError", "TimeoutError",
    } or isinstance(error, (TimeoutError, ConnectionError))


def _parse_timestamp(value: Any, label: str) -> datetime:
    _require(isinstance(value, str) and value.strip(), f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    _require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _scope_partition(scope: Scope) -> str:
    raw = _jcs(_scope_body(scope)).encode("utf-8")
    return "SCOPE#" + hashlib.sha256(raw).hexdigest()


def _key_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _client_request_token(scope_pk: str, idempotency_key: str) -> str:
    seed = (scope_pk + "\0" + idempotency_key).encode("utf-8")
    raw = hashlib.sha256(seed).digest()[:16]
    return str(uuid.UUID(bytes=raw))


class AWSDynamoDBWitnessAdapter:
    """Linearizable compare-and-append backed by DynamoDB transactions.

    Four records are committed atomically:
      HEAD, immutable generation, immutable operation index, immutable
      idempotency index. The two read paths fetch the base table directly and
      always request strongly consistent reads.
    """

    def __init__(self, client: Any, table_name: str):
        _require(isinstance(table_name, str) and table_name.strip(), "DynamoDB table name is required")
        self._client = client
        self._table = table_name

    def _get(self, scope: Scope, sort_key: str) -> dict[str, Any] | None:
        response = self._client.get_item(
            TableName=self._table,
            Key={
                "PK": {"S": _scope_partition(scope)},
                "SK": {"S": sort_key},
            },
            ConsistentRead=True,
        )
        item = response.get("Item")
        return item if isinstance(item, dict) else None

    def _stored(self, item: dict[str, Any]) -> StoredCheckpoint:
        checkpoint = _checkpoint_from_json(_av_s(item, "checkpointJson"))
        receipt = _receipt_from_json(_av_s(item, "receiptJson"))
        if checkpoint.scope != receipt.scope:
            raise ValueError("DynamoDB witness checkpoint/receipt scope mismatch")
        if (
            checkpoint.generation != receipt.generation
            or checkpoint.operation_id != receipt.operation_id
            or checkpoint.checkpoint_digest != receipt.checkpoint_digest
            or checkpoint.previous_digest != receipt.previous_digest
        ):
            raise ValueError("DynamoDB witness checkpoint/receipt field mismatch")
        return StoredCheckpoint(checkpoint, receipt)

    def _read_idempotency(self, scope: Scope, idempotency_key: str) -> dict[str, Any] | None:
        return self._get(scope, "IDEMP#" + _key_digest(idempotency_key))

    def _read_operation_item(self, scope: Scope, operation_id: str) -> dict[str, Any] | None:
        return self._get(scope, "OP#" + _key_digest(operation_id))

    def _recover_idempotent(
        self, item: dict[str, Any], canonical_checkpoint: str
    ) -> Receipt:
        prior = _av_s(item, "checkpointCanonicalJson")
        if prior != canonical_checkpoint:
            raise IdempotencyConflict("idempotency key is already bound to different checkpoint content")
        stored = self._stored(item)
        return stored.receipt

    def _validate_append(
        self,
        value: Checkpoint,
        expected_generation: int,
        expected_digest: str,
        idempotency_key: str,
    ) -> None:
        _require(type(expected_generation) is int and 0 <= expected_generation <= MAX_SAFE_INTEGER,
                 "expected_generation must be a non-negative safe integer")
        _require(type(value.generation) is int and 1 <= value.generation <= MAX_SAFE_INTEGER,
                 "checkpoint generation must be a positive safe integer")
        _require(value.generation == expected_generation + 1,
                 "checkpoint generation must advance exactly one")
        _require(value.previous_digest == expected_digest,
                 "checkpoint predecessor differs from expected digest")
        _require(isinstance(expected_digest, str) and SHA256.fullmatch(expected_digest) is not None,
                 "expected predecessor digest must be lowercase SHA-256")
        _require(isinstance(value.checkpoint_digest, str)
                 and SHA256.fullmatch(value.checkpoint_digest) is not None,
                 "checkpoint digest must be lowercase SHA-256")
        _require(isinstance(value.operation_id, str) and 1 <= len(value.operation_id) <= 256
                 and bool(value.operation_id.strip()), "operation ID must be a non-empty string of at most 256 characters")
        _require(isinstance(idempotency_key, str) and 1 <= len(idempotency_key) <= 256
                 and bool(idempotency_key.strip()), "idempotency key must be a non-empty string of at most 256 characters")
        for name, field in (
            ("trust_domain_id", value.scope.trust_domain_id),
            ("witness_id", value.scope.witness_id),
            ("authority_id", value.scope.authority_id),
            ("host_id", value.scope.host_id),
        ):
            _require(isinstance(field, str) and 1 <= len(field) <= 256 and field.strip(),
                     f"{name} must be a non-empty string of at most 256 characters")
        _require(value.phase in {"ISSUED", "ACCEPTED", "REVOKED"},
                 "unsupported witness checkpoint phase")

    @staticmethod
    def _record_item(
        scope_pk: str,
        sort_key: str,
        record_type: str,
        value: Checkpoint,
        receipt: Receipt,
        canonical_checkpoint: str,
    ) -> dict[str, Any]:
        checkpoint_json = _jcs(_checkpoint_body(value))
        receipt_json = _jcs(_receipt_body(receipt))
        return {
            "PK": {"S": scope_pk},
            "SK": {"S": sort_key},
            "recordType": {"S": record_type},
            "scopeJson": {"S": _jcs(_scope_body(value.scope))},
            "generation": {"N": str(value.generation)},
            "operationId": {"S": value.operation_id},
            "checkpointDigest": {"S": value.checkpoint_digest},
            "previousDigest": {"S": value.previous_digest},
            "checkpointCanonicalJson": {"S": canonical_checkpoint},
            "checkpointJson": {"S": checkpoint_json},
            "receiptJson": {"S": receipt_json},
            "consistencyToken": {"S": receipt.consistency_token},
        }

    def append_if_current(
        self,
        value: Checkpoint,
        *,
        expected_generation: int,
        expected_digest: str,
        idempotency_key: str,
    ) -> Receipt:
        self._validate_append(value, expected_generation, expected_digest, idempotency_key)
        scope_pk = _scope_partition(value.scope)
        canonical_checkpoint = _jcs(_checkpoint_body(value))

        # This durable lookup is the long-lived idempotency mechanism. It works
        # after DynamoDB's native transaction-token window has expired.
        prior_idempotency = self._read_idempotency(value.scope, idempotency_key)
        if prior_idempotency is not None:
            return self._recover_idempotent(prior_idempotency, canonical_checkpoint)

        prior_operation = self._read_operation_item(value.scope, value.operation_id)
        if prior_operation is not None:
            raise IdempotencyConflict("operation ID already exists under another idempotency key")

        client_token = _client_request_token(scope_pk, idempotency_key)
        receipt = Receipt(
            scope=value.scope,
            generation=value.generation,
            operation_id=value.operation_id,
            checkpoint_digest=value.checkpoint_digest,
            previous_digest=value.previous_digest,
            # Correlation/idempotency handle only. Strong consistency comes
            # from atomic condition checks and ConsistentRead=True, not this
            # client-supplied token by itself.
            consistency_token=f"aws-dynamodb-v1:client-request-token:{client_token}",
        )

        head_item = self._record_item(scope_pk, "HEAD", "HEAD", value, receipt, canonical_checkpoint)
        generation_key = f"GEN#{value.generation:020d}"
        generation_item = self._record_item(
            scope_pk, generation_key, "GENERATION", value, receipt, canonical_checkpoint
        )
        operation_item = self._record_item(
            scope_pk, "OP#" + _key_digest(value.operation_id), "OPERATION",
            value, receipt, canonical_checkpoint
        )
        idempotency_item = self._record_item(
            scope_pk, "IDEMP#" + _key_digest(idempotency_key), "IDEMPOTENCY",
            value, receipt, canonical_checkpoint
        )

        if expected_generation == 0:
            head_condition = "attribute_not_exists(#pk)"
            head_names = {"#pk": "PK"}
            head_values: dict[str, Any] = {}
        else:
            head_condition = "#generation = :expectedGeneration AND #checkpointDigest = :expectedDigest"
            head_names = {"#generation": "generation", "#checkpointDigest": "checkpointDigest"}
            head_values = {
                ":expectedGeneration": {"N": str(expected_generation)},
                ":expectedDigest": {"S": expected_digest},
            }

        def immutable_put(item: dict[str, Any]) -> dict[str, Any]:
            return {
                "Put": {
                    "TableName": self._table,
                    "Item": item,
                    "ConditionExpression": "attribute_not_exists(#pk)",
                    "ExpressionAttributeNames": {"#pk": "PK"},
                }
            }

        transaction = {
            "ClientRequestToken": client_token,
            "ReturnConsumedCapacity": "TOTAL",
            "TransactItems": [
                {
                    "Put": {
                        "TableName": self._table,
                        "Item": head_item,
                        "ConditionExpression": head_condition,
                        "ExpressionAttributeNames": head_names,
                        **({"ExpressionAttributeValues": head_values} if head_values else {}),
                    }
                },
                immutable_put(generation_item),
                immutable_put(operation_item),
                immutable_put(idempotency_item),
            ],
        }

        try:
            self._client.transact_write_items(**transaction)
        except Exception as error:
            code = _error_code(error)
            if code in {
                "TransactionCanceledException",
                "ConditionalCheckFailedException",
                "IdempotentParameterMismatchException",
            }:
                # A competing identical retry may have committed after our
                # pre-read. Reconcile by exact key and exact canonical bytes.
                committed = self._read_idempotency(value.scope, idempotency_key)
                if committed is not None:
                    return self._recover_idempotent(committed, canonical_checkpoint)
                operation = self._read_operation_item(value.scope, value.operation_id)
                if operation is not None:
                    raise IdempotencyConflict(
                        "operation ID already committed with another idempotency key"
                    ) from error
                raise AppendConflict(
                    "DynamoDB compare-and-append condition failed; reconcile the current high-water"
                ) from error
            if _is_ambiguous_transport_error(error):
                raise AmbiguousCommit(
                    "DynamoDB append outcome is ambiguous; retry the identical checkpoint and idempotency key"
                ) from error
            raise

        # A transaction success is followed by an exact strong read of the
        # immutable operation record. Missing readback is never silently
        # treated as a successful provider commit.
        committed = self.read_by_operation(value.scope, value.operation_id)
        if committed is None:
            raise AmbiguousCommit(
                "DynamoDB transaction returned success but exact operation readback was absent"
            )
        if committed.checkpoint != value or committed.receipt != receipt:
            raise ValueError("DynamoDB exact operation readback differs from submitted checkpoint")
        return committed.receipt

    def read_latest(self, scope: Scope) -> StoredCheckpoint | None:
        item = self._get(scope, "HEAD")
        if item is None:
            return None
        stored = self._stored(item)
        if stored.checkpoint.scope != scope:
            raise ValueError("DynamoDB high-water scope mismatch")
        return stored

    def read_by_operation(self, scope: Scope, operation_id: str) -> StoredCheckpoint | None:
        item = self._read_operation_item(scope, operation_id)
        if item is None:
            return None
        stored = self._stored(item)
        if stored.checkpoint.scope != scope or stored.checkpoint.operation_id != operation_id:
            raise ValueError("DynamoDB operation-index binding mismatch")
        return stored


class _FakeDynamoDBError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeDynamoDBClient:
    """Thread-safe DynamoDB API double; it models only the adapter's four item writes."""

    def __init__(self):
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def get_item(self, *, TableName: str, Key: dict[str, Any], ConsistentRead: bool = False) -> dict[str, Any]:
        if not ConsistentRead:
            raise AssertionError("authoritative DynamoDB read omitted ConsistentRead=True")
        self.calls.append("GetItem")
        key = (_av_s(Key, "PK"), _av_s(Key, "SK"))
        with self._lock:
            item = self.items.get(key)
            return {"Item": deepcopy(item)} if item is not None else {}

    def transact_write_items(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("TransactWriteItems")
        if len(kwargs.get("TransactItems", [])) != 4:
            raise AssertionError("append must atomically write exactly four records")
        token = kwargs.get("ClientRequestToken")
        if not isinstance(token, str) or len(token) != 36:
            raise AssertionError("DynamoDB ClientRequestToken must be a deterministic UUID")
        puts = [action["Put"] for action in kwargs["TransactItems"]]
        if any(put.get("TableName") != "fence-witness-fixture" for put in puts):
            raise AssertionError("unexpected DynamoDB table name")
        with self._lock:
            keys: list[tuple[str, str]] = []
            for index, put in enumerate(puts):
                item = put["Item"]
                key = (_av_s(item, "PK"), _av_s(item, "SK"))
                existing = self.items.get(key)
                keys.append(key)
                expression = put["ConditionExpression"]
                if index == 0 and expression.startswith("#generation"):
                    names = put["ExpressionAttributeNames"]
                    values = put["ExpressionAttributeValues"]
                    valid = (
                        existing is not None
                        and _av_n(existing, names["#generation"]) == int(values[":expectedGeneration"]["N"])
                        and _av_s(existing, names["#checkpointDigest"]) == values[":expectedDigest"]["S"]
                    )
                else:
                    valid = existing is None
                if not valid:
                    raise _FakeDynamoDBError("TransactionCanceledException")
            for key, put in zip(keys, puts):
                self.items[key] = deepcopy(put["Item"])
        return {"ResponseMetadata": {"RequestId": "fake-dynamodb-request-id"}}


def _load_approval(config: dict[str, str]) -> None:
    approval_path = Path(config["approvalFile"])
    report_path = Path(config["preflightReport"])
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    report_raw = report_path.read_bytes()
    report = json.loads(report_raw.decode("utf-8"))
    now = datetime.now(timezone.utc)
    _require(isinstance(approval, dict), "AWS witness approval file must contain a JSON object")
    _require(approval.get("profile") == APPROVAL_PROFILE, "unsupported AWS witness approval profile")
    expected = {
        "runId": config["runId"],
        "accountId": config["accountId"],
        "region": config["region"],
        "tableArn": config["tableArn"],
        "expectedCallerArnPrefix": config["expectedCallerArnPrefix"],
        "operation": "AWS_DYNAMODB_WITNESS_ADAPTER_CONFORMANCE_WRITES",
        "preflightReportSha256": hashlib.sha256(report_raw).hexdigest(),
    }
    for field, value in expected.items():
        _require(approval.get(field) == value, f"AWS witness approval {field} does not match operator-pinned scope")
    _require(isinstance(approval.get("approvedBy"), str) and approval["approvedBy"].strip(),
             "AWS witness approval must name the approving operator")
    issued = _parse_timestamp(approval.get("issuedAt"), "approval issuedAt")
    expires = _parse_timestamp(approval.get("expiresAt"), "approval expiresAt")
    _require(issued <= now + MAX_FUTURE_SKEW, "AWS witness approval issue time is in the future")
    _require(expires > now and issued < expires, "AWS witness approval is expired or has an empty validity window")
    _require(expires - issued <= timedelta(hours=8),
             "AWS witness approval validity window must not exceed eight hours")
    _require(report.get("result") == "READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION",
             "read-only AWS preflight report is not ready")
    _require(report.get("qualificationRunId") == config["runId"],
             "read-only AWS preflight run ID differs from approval")
    _require(report.get("accountId") == config["accountId"] and report.get("region") == config["region"],
             "read-only AWS preflight account/Region differs from approval")
    _require(report.get("readOnlyInspection") is True,
             "AWS preflight report is not marked as read-only inspection")
    _require(report.get("resourcePins", {}).get("dynamodbTableArn") == config["tableArn"],
             "read-only AWS preflight table ARN differs from approval")
    _require(report.get("resourceMutationsPerformed") is False
             and report.get("privilegedMutationAttemptsPerformed") is False
             and report.get("restoreOperationsPerformed") is False
             and report.get("productionApproval") is False
             and report.get("hostAdmissionEnabled") is False,
             "read-only AWS preflight report does not preserve its no-mutation boundary")


def create_adapter() -> AWSDynamoDBWitnessAdapter:
    """Explicitly guarded live factory for the generic witness harness.

    This function performs read-only STS/DescribeTable preflight and returns a
    writer only after the operator opt-in, run-bound approval and preflight
    report agree. The approval document is a local operator gate, not a
    substitute for the independently signed attestation and review chain.
    """
    if os.getenv("FENCE_AWS_DDB_ENABLE_WRITES") != WRITE_OPT_IN:
        raise SystemExit("AWS DynamoDB witness writes are disabled; the exact FENCE_AWS_DDB_ENABLE_WRITES opt-in is required")
    required = {
        "accountId": os.getenv("FENCE_AWS_DDB_EXPECTED_ACCOUNT_ID", ""),
        "region": os.getenv("FENCE_AWS_DDB_REGION", ""),
        "tableName": os.getenv("FENCE_AWS_DDB_TABLE_NAME", ""),
        "tableArn": os.getenv("FENCE_AWS_DDB_EXPECTED_TABLE_ARN", ""),
        "expectedCallerArnPrefix": os.getenv("FENCE_AWS_DDB_EXPECTED_CALLER_ARN_PREFIX", ""),
        "runId": os.getenv("FENCE_AWS_DDB_QUALIFICATION_RUN_ID", ""),
        "preflightReport": os.getenv("FENCE_AWS_DDB_PREFLIGHT_REPORT", ""),
        "approvalFile": os.getenv("FENCE_AWS_DDB_APPROVAL_FILE", ""),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise SystemExit("missing AWS DynamoDB witness gate inputs: " + ", ".join(missing))
    _require(re.fullmatch(r"[0-9]{12}", required["accountId"]) is not None,
             "expected AWS account ID must contain 12 digits")
    _require(
        required["expectedCallerArnPrefix"].startswith(
            f"arn:aws:sts::{required['accountId']}:assumed-role/"
        ) and required["expectedCallerArnPrefix"].endswith("/"),
        "expected caller ARN prefix must pin an assumed-role ARN in the approved account",
    )
    _require(SAFE_ID.fullmatch(required["runId"]) is not None, "qualification run ID is unsafe")
    _load_approval(required)

    try:
        import boto3
    except ImportError as exc:
        raise SystemExit("install the pinned boto3 dependency before using the AWS adapter") from exc

    profile = os.getenv("AWS_PROFILE")
    session_kwargs: dict[str, Any] = {"region_name": required["region"]}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(**session_kwargs)
    identity = session.client("sts", region_name=required["region"]).get_caller_identity()
    _require(identity.get("Account") == required["accountId"],
             "live AWS caller account differs from the approved qualification account")
    _require(isinstance(identity.get("Arn"), str)
             and identity["Arn"].startswith(required["expectedCallerArnPrefix"]),
             "live AWS caller ARN differs from the approved assumed-role prefix")

    client = session.client("dynamodb", region_name=required["region"])
    table = client.describe_table(TableName=required["tableName"]).get("Table", {})
    _require(table.get("TableArn") == required["tableArn"],
             "live DynamoDB table ARN differs from the approved qualification table")
    _require(table.get("TableStatus") == "ACTIVE", "approved DynamoDB witness table is not ACTIVE")
    key_schema = {item.get("AttributeName"): item.get("KeyType") for item in table.get("KeySchema", [])}
    _require(key_schema == {"PK": "HASH", "SK": "RANGE"},
             "AWS witness table must use string partition key PK and string sort key SK")
    attributes = {item.get("AttributeName"): item.get("AttributeType") for item in table.get("AttributeDefinitions", [])}
    _require(attributes.get("PK") == "S" and attributes.get("SK") == "S",
             "AWS witness table PK and SK must both be DynamoDB string attributes")
    return AWSDynamoDBWitnessAdapter(client, required["tableName"])


def self_test() -> None:
    # Live mode must remain unavailable unless the exact operator opt-in is set.
    previous_opt_in = os.environ.pop("FENCE_AWS_DDB_ENABLE_WRITES", None)
    try:
        try:
            create_adapter()
        except SystemExit as error:
            _require("exact FENCE_AWS_DDB_ENABLE_WRITES opt-in" in str(error),
                     "live factory rejected an unapproved call for an unexpected reason")
        else:
            raise AssertionError("live AWS factory opened without the explicit write opt-in")
    finally:
        if previous_opt_in is not None:
            os.environ["FENCE_AWS_DDB_ENABLE_WRITES"] = previous_opt_in

    clients: list[FakeDynamoDBClient] = []

    def fresh_adapter() -> AWSDynamoDBWitnessAdapter:
        client = FakeDynamoDBClient()
        clients.append(client)
        return AWSDynamoDBWitnessAdapter(client, "fence-witness-fixture")

    results = run_conformance(fresh_adapter)
    failed = [item for item in results if not item.passed]
    for item in results:
        print(f"{'PASS' if item.passed else 'FAIL'} AWS DynamoDB witness {item.name}: {item.detail}")
    _require(not failed, f"{len(failed)} AWS DynamoDB adapter contract tests failed")
    _require(bool(clients), "conformance suite did not create a DynamoDB API fixture")
    for fake in clients:
        _require(set(fake.calls).issubset({"GetItem", "TransactWriteItems"}),
                 "fake DynamoDB client observed an unexpected operation")
        _require(fake.calls.count("TransactWriteItems") > 0,
                 "a conformance case did not exercise an atomic DynamoDB transaction")
        _require(fake.calls.count("GetItem") > 0,
                 "a conformance case did not exercise a strongly consistent DynamoDB read")

    # A second independent adapter object must recover the same durable
    # operation from the idempotency index, without issuing another transaction.
    durable_fake = FakeDynamoDBClient()
    adapter = AWSDynamoDBWitnessAdapter(durable_fake, "fence-witness-fixture")
    from validate_m0_fence_provider_adapter_conformance import ZERO_DIGEST
    sample = Checkpoint(Scope("domain-x", "witness-x", "authority-x", "host-x"),
                        1, "durable-op", "ISSUED", "a" * 64, ZERO_DIGEST)
    first = adapter.append_if_current(
        sample, expected_generation=0, expected_digest=ZERO_DIGEST,
        idempotency_key="long-lived-idempotency-key",
    )
    transaction_count = durable_fake.calls.count("TransactWriteItems")
    second_adapter = AWSDynamoDBWitnessAdapter(durable_fake, "fence-witness-fixture")
    second = second_adapter.append_if_current(
        sample, expected_generation=0, expected_digest=ZERO_DIGEST,
        idempotency_key="long-lived-idempotency-key",
    )
    _require(first == second, "durable idempotency recovery returned a different receipt")
    _require(durable_fake.calls.count("TransactWriteItems") == transaction_count,
             "durable idempotency retry issued another transaction")
    idem_record = durable_fake.items[(_scope_partition(sample.scope), "IDEMP#" + _key_digest("long-lived-idempotency-key"))]
    _require("ttl" not in idem_record and "expiresAt" not in idem_record,
             "durable idempotency record must not expire automatically")

    # The client request token is stable for the same scope/key; the stored
    # token is a correlation handle, not an independently verified proof.
    _require(first.consistency_token.startswith("aws-dynamodb-v1:client-request-token:"),
             "AWS receipt correlation token profile mismatch")
    print("AWS DynamoDB witness adapter self-test: PASS")
    print("Synthetic API double only; no boto3 session, credentials or AWS API calls were created.")
    print("DynamoDB strong reads are requested explicitly; client token is not treated as a consistency proof.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    parser.error("use this module via FENCE_WITNESS_ADAPTER_FACTORY=aws_dynamodb_witness_adapter:create_adapter")


if __name__ == "__main__":
    main()
