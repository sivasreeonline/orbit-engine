#!/usr/bin/env python3
"""AWS DynamoDB witness adapter for FENCE-001.

Local mode targets only a loopback DynamoDB Local endpoint and creates a fresh,
ephemeral local table for each adapter factory call. Live AWS mode is disabled
unless a run-bound disposable-qualification approval is explicitly supplied.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError

def _contract_types():
    """Return the active witness harness module, preserving type identity.

    The conformance script is usually executed as __main__. Importing it again
    by module name would create duplicate dataclasses and exceptions.
    """
    main_module = sys.modules.get("__main__")
    required = (
        "AmbiguousCommit", "AppendConflict", "Checkpoint",
        "IdempotencyConflict", "Receipt", "Scope", "StoredCheckpoint",
    )
    if main_module is not None and all(hasattr(main_module, name) for name in required):
        return main_module
    return importlib.import_module("validate_m0_witness_provider_adapter_conformance")


LIVE_OPT_IN = "I_UNDERSTAND_THIS_WRITES_TO_A_DISPOSABLE_QUALIFICATION_TABLE"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _scope_document(scope: Any) -> dict[str, str]:
    values = {
        "trust_domain_id": scope.trust_domain_id,
        "witness_id": scope.witness_id,
        "authority_id": scope.authority_id,
        "host_id": scope.host_id,
    }
    for field, value in values.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"scope {field} must be a non-empty string")
    return values


def _checkpoint_document(value: Any) -> dict[str, Any]:
    return {
        "scope": _scope_document(value.scope),
        "generation": value.generation,
        "operation_id": value.operation_id,
        "phase": value.phase,
        "checkpoint_digest": value.checkpoint_digest,
        "previous_digest": value.previous_digest,
    }


def _receipt_document(value: Any) -> dict[str, Any]:
    return {
        "scope": _scope_document(value.scope),
        "generation": value.generation,
        "operation_id": value.operation_id,
        "checkpoint_digest": value.checkpoint_digest,
        "previous_digest": value.previous_digest,
        "consistency_token": value.consistency_token,
    }


def _decode_record(item: dict[str, Any] | None) -> Any:
    if not item:
        return None
    contract = _contract_types()
    checkpoint_json = item.get("checkpointJson", {}).get("S")
    receipt_json = item.get("receiptJson", {}).get("S")
    if not isinstance(checkpoint_json, str) or not isinstance(receipt_json, str):
        raise ValueError("DynamoDB witness record is missing its canonical checkpoint or receipt")
    checkpoint_body = json.loads(checkpoint_json)
    receipt_body = json.loads(receipt_json)
    scope = contract.Scope(**checkpoint_body["scope"])
    checkpoint = contract.Checkpoint(
        scope=scope,
        generation=checkpoint_body["generation"],
        operation_id=checkpoint_body["operation_id"],
        phase=checkpoint_body["phase"],
        checkpoint_digest=checkpoint_body["checkpoint_digest"],
        previous_digest=checkpoint_body["previous_digest"],
    )
    receipt = contract.Receipt(
        scope=contract.Scope(**receipt_body["scope"]),
        generation=receipt_body["generation"],
        operation_id=receipt_body["operation_id"],
        checkpoint_digest=receipt_body["checkpoint_digest"],
        previous_digest=receipt_body["previous_digest"],
        consistency_token=receipt_body["consistency_token"],
    )
    return contract.StoredCheckpoint(checkpoint=checkpoint, receipt=receipt)


class DynamoDBWitnessAdapter:
    """Single-table atomic witness implementation using DynamoDB base-table reads.

    The transaction writes four distinct records in one partition:
      HEAD, immutable generation record, immutable operation record, and
      durable idempotency record. The durable record makes retries independent
      of DynamoDB's 10-minute ClientRequestToken window.
    """

    def __init__(self, client: Any, table_name: str) -> None:
        if not table_name:
            raise ValueError("DynamoDB table name is required")
        self._client = client
        self._table_name = table_name

    @staticmethod
    def _partition_key(scope: Any) -> str:
        raw = _canonical(_scope_document(scope)).encode("utf-8")
        return "SCOPE#" + hashlib.sha256(raw).hexdigest()

    def _get(self, scope: Any, sort_key: str) -> dict[str, Any] | None:
        response = self._client.get_item(
            TableName=self._table_name,
            Key={"PK": {"S": self._partition_key(scope)}, "SK": {"S": sort_key}},
            ConsistentRead=True,
        )
        return response.get("Item")

    def _read_idempotency(self, scope: Any, idempotency_hash: str) -> Any:
        return _decode_record(self._get(scope, f"IDEMP#{idempotency_hash}"))

    @staticmethod
    def _validate_append(
        value: Any,
        *,
        expected_generation: int,
        expected_digest: str,
        idempotency_key: str,
    ) -> None:
        _scope_document(value.scope)
        if type(expected_generation) is not int or expected_generation < 0:
            raise ValueError("expected_generation must be a non-negative integer")
        if type(value.generation) is not int or value.generation != expected_generation + 1:
            raise _contract_types().AppendConflict("checkpoint generation must advance exactly one")
        if not isinstance(expected_digest, str) or DIGEST.fullmatch(expected_digest) is None:
            raise ValueError("expected_digest must be lowercase SHA-256 hex")
        if not isinstance(value.checkpoint_digest, str) or DIGEST.fullmatch(value.checkpoint_digest) is None:
            raise ValueError("checkpoint_digest must be lowercase SHA-256 hex")
        if value.previous_digest != expected_digest:
            raise _contract_types().AppendConflict("checkpoint does not name the exact expected predecessor")
        if not isinstance(value.operation_id, str) or SAFE_ID.fullmatch(value.operation_id) is None:
            raise ValueError("operation_id must be a safe non-empty identifier")
        if not isinstance(value.phase, str) or SAFE_ID.fullmatch(value.phase) is None:
            raise ValueError("phase must be a safe non-empty identifier")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("idempotency_key must be a non-empty string")
        if len(idempotency_key.encode("utf-8")) > 512:
            raise ValueError("idempotency_key exceeds 512 UTF-8 bytes")

    @staticmethod
    def _require_same_idempotent_record(
        stored: Any,
        checkpoint_json: str,
        idempotency_hash: str,
        item: dict[str, Any] | None,
    ) -> Any:
        stored_checkpoint_json = (item or {}).get("checkpointJson", {}).get("S")
        stored_key_hash = (item or {}).get("idempotencyKeySha256", {}).get("S")
        if stored_checkpoint_json != checkpoint_json or stored_key_hash != idempotency_hash:
            raise _contract_types().IdempotencyConflict("idempotency key is already bound to different checkpoint content")
        return stored.receipt

    def append_if_current(
        self,
        value: Any,
        *,
        expected_generation: int,
        expected_digest: str,
        idempotency_key: str,
    ) -> Any:
        self._validate_append(
            value,
            expected_generation=expected_generation,
            expected_digest=expected_digest,
            idempotency_key=idempotency_key,
        )
        scope = value.scope
        partition_key = self._partition_key(scope)
        checkpoint_json = _canonical(_checkpoint_document(value))
        idempotency_hash = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()

        # The durable record is authoritative for every retry, even after the
        # native DynamoDB transaction token has expired.
        prior_idempotency_item = self._get(scope, f"IDEMP#{idempotency_hash}")
        prior_idempotency = _decode_record(prior_idempotency_item)
        if prior_idempotency is not None:
            return self._require_same_idempotent_record(
                prior_idempotency, checkpoint_json, idempotency_hash, prior_idempotency_item
            )

        prior_operation_item = self._get(scope, f"OP#{value.operation_id}")
        if prior_operation_item is not None:
            raise _contract_types().IdempotencyConflict("operation ID already exists with another checkpoint or idempotency key")

        head_item = self._get(scope, "HEAD")
        head_record = _decode_record(head_item)
        actual_generation = head_record.checkpoint.generation if head_record else 0
        actual_digest = head_record.checkpoint.checkpoint_digest if head_record else "0" * 64
        if (actual_generation, actual_digest) != (expected_generation, expected_digest):
            raise _contract_types().AppendConflict("expected predecessor is not the current DynamoDB witness high-water")

        # This stable opaque value is an adapter transaction-correlation token,
        # not a cryptographic proof of linearizability or provider authenticity.
        transaction_binding = hashlib.sha256(
            (self._table_name + "\x00" + partition_key + "\x00" + idempotency_hash + "\x00" + checkpoint_json).encode("utf-8")
        ).hexdigest()
        consistency_token = "dynamodb-correlation-" + transaction_binding[:32]
        receipt = _contract_types().Receipt(
            scope=scope,
            generation=value.generation,
            operation_id=value.operation_id,
            checkpoint_digest=value.checkpoint_digest,
            previous_digest=value.previous_digest,
            consistency_token=consistency_token,
        )
        receipt_json = _canonical(_receipt_document(receipt))
        client_request_token = str(uuid.UUID(hex=transaction_binding[:32]))

        def record_item(sort_key: str) -> dict[str, Any]:
            return {
                "PK": {"S": partition_key},
                "SK": {"S": sort_key},
                "recordType": {"S": sort_key.split("#", 1)[0]},
                "generation": {"N": str(value.generation)},
                "checkpointDigest": {"S": value.checkpoint_digest},
                "operationId": {"S": value.operation_id},
                "idempotencyKeySha256": {"S": idempotency_hash},
                "checkpointJson": {"S": checkpoint_json},
                "receiptJson": {"S": receipt_json},
            }

        immutable_puts = []
        for sort_key in (
            f"GEN#{value.generation:020d}",
            f"OP#{value.operation_id}",
            f"IDEMP#{idempotency_hash}",
        ):
            immutable_puts.append({
                "Put": {
                    "TableName": self._table_name,
                    "Item": record_item(sort_key),
                    "ConditionExpression": "attribute_not_exists(#pk)",
                    "ExpressionAttributeNames": {"#pk": "PK"},
                }
            })

        head = {
            "PK": {"S": partition_key},
            "SK": {"S": "HEAD"},
            "recordType": {"S": "HEAD"},
            "generation": {"N": str(value.generation)},
            "checkpointDigest": {"S": value.checkpoint_digest},
            "operationId": {"S": value.operation_id},
            "idempotencyKeySha256": {"S": idempotency_hash},
            "checkpointJson": {"S": checkpoint_json},
            "receiptJson": {"S": receipt_json},
        }
        if expected_generation == 0:
            head_action = {
                "Put": {
                    "TableName": self._table_name,
                    "Item": head,
                    "ConditionExpression": "attribute_not_exists(#pk)",
                    "ExpressionAttributeNames": {"#pk": "PK"},
                }
            }
        else:
            head_action = {
                "Update": {
                    "TableName": self._table_name,
                    "Key": {"PK": {"S": partition_key}, "SK": {"S": "HEAD"}},
                    "UpdateExpression": (
                        "SET #generation = :generation, #digest = :digest, "
                        "#operation = :operation, #idempotency = :idempotency, "
                        "#checkpoint = :checkpoint, #receipt = :receipt, #recordType = :recordType"
                    ),
                    "ConditionExpression": "#generation = :expectedGeneration AND #digest = :expectedDigest",
                    "ExpressionAttributeNames": {
                        "#generation": "generation",
                        "#digest": "checkpointDigest",
                        "#operation": "operationId",
                        "#idempotency": "idempotencyKeySha256",
                        "#checkpoint": "checkpointJson",
                        "#receipt": "receiptJson",
                        "#recordType": "recordType",
                    },
                    "ExpressionAttributeValues": {
                        ":generation": {"N": str(value.generation)},
                        ":digest": {"S": value.checkpoint_digest},
                        ":operation": {"S": value.operation_id},
                        ":idempotency": {"S": idempotency_hash},
                        ":checkpoint": {"S": checkpoint_json},
                        ":receipt": {"S": receipt_json},
                        ":recordType": {"S": "HEAD"},
                        ":expectedGeneration": {"N": str(expected_generation)},
                        ":expectedDigest": {"S": expected_digest},
                    },
                }
            }

        try:
            self._client.transact_write_items(
                TransactItems=[*immutable_puts, head_action],
                ClientRequestToken=client_request_token,
            )
            return receipt
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {
                "InternalServerError", "ServiceUnavailable", "ThrottlingException",
                "RequestLimitExceeded", "ProvisionedThroughputExceededException",
                "TransactionInProgressException", "LimitExceededException",
            }:
                recovered = self._read_idempotency(scope, idempotency_hash)
                if recovered is not None:
                    item = self._get(scope, f"IDEMP#{idempotency_hash}")
                    recovered_receipt = self._require_same_idempotent_record(
                        recovered, checkpoint_json, idempotency_hash, item
                    )
                    return recovered_receipt
                raise _contract_types().AmbiguousCommit(
                    "DynamoDB returned a transient service error; retry the exact checkpoint and idempotency key"
                ) from exc
            if code == "IdempotentParameterMismatchException":
                raise _contract_types().IdempotencyConflict(
                    "DynamoDB received the same transaction token with different request parameters"
                ) from exc
            if code != "TransactionCanceledException":
                raise
        except BotoCoreError as exc:
            try:
                recovered_item = self._get(scope, f"IDEMP#{idempotency_hash}")
                recovered = _decode_record(recovered_item)
                if recovered is not None:
                    return self._require_same_idempotent_record(
                        recovered, checkpoint_json, idempotency_hash, recovered_item
                    )
            except Exception:
                # The operation remains ambiguous if readback itself is unavailable.
                pass
            raise _contract_types().AmbiguousCommit(
                "DynamoDB transaction outcome is ambiguous; retry the exact checkpoint and idempotency key"
            ) from exc

        # A canceled transaction may be a lost race. Reconcile by the durable
        # keys first so retries recover a commit instead of being called forks.
        recovered_item = self._get(scope, f"IDEMP#{idempotency_hash}")
        recovered = _decode_record(recovered_item)
        if recovered is not None:
            return self._require_same_idempotent_record(
                recovered, checkpoint_json, idempotency_hash, recovered_item
            )
        if self._get(scope, f"OP#{value.operation_id}") is not None:
            raise _contract_types().IdempotencyConflict("operation ID was committed with different checkpoint content")
        current = _decode_record(self._get(scope, "HEAD"))
        current_generation = current.checkpoint.generation if current else 0
        current_digest = current.checkpoint.checkpoint_digest if current else "0" * 64
        if (current_generation, current_digest) != (expected_generation, expected_digest):
            raise _contract_types().AppendConflict("DynamoDB compare-and-append lost the predecessor race")
        raise _contract_types().AppendConflict("DynamoDB rejected one or more immutable witness-key conditions")

    def read_latest(self, scope: Any) -> Any:
        return _decode_record(self._get(scope, "HEAD"))

    def read_by_operation(self, scope: Any, operation_id: str) -> Any:
        if not isinstance(operation_id, str) or SAFE_ID.fullmatch(operation_id) is None:
            raise ValueError("operation_id must be a safe non-empty identifier")
        return _decode_record(self._get(scope, f"OP#{operation_id}"))


def _create_local_table(client: Any, table_name: str) -> None:
    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )
    client.get_waiter("table_exists").wait(
        TableName=table_name,
        WaiterConfig={"Delay": 1, "MaxAttempts": 20},
    )


def create_adapter() -> DynamoDBWitnessAdapter:
    """Factory consumed by the provider-neutral conformance harness."""
    endpoint = os.getenv("FENCE_AWS_WITNESS_ENDPOINT_URL")
    region = os.getenv("FENCE_AWS_WITNESS_REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    if not region:
        raise RuntimeError("FENCE_AWS_WITNESS_REGION or AWS_REGION is required")

    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("local DynamoDB endpoint must be an HTTP loopback address")
        prefix = os.getenv("FENCE_AWS_WITNESS_LOCAL_TABLE_PREFIX", "fence001-local-witness")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{2,79}", prefix):
            raise RuntimeError("local table prefix must be a safe DynamoDB identifier")
        client = boto3.client(
            "dynamodb",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "local"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "local"),
        )
        for attempt in range(40):
            try:
                client.list_tables(Limit=1)
                break
            except BotoCoreError:
                if attempt == 39:
                    raise RuntimeError("DynamoDB Local endpoint did not become ready")
                time.sleep(0.5)
        table_name = f"{prefix}-{uuid.uuid4().hex[:16]}"
        _create_local_table(client, table_name)
        return DynamoDBWitnessAdapter(client, table_name)

    if os.getenv("FENCE_AWS_WITNESS_ALLOW_LIVE") != LIVE_OPT_IN:
        raise RuntimeError(
            "live AWS witness writes are disabled; use a loopback DynamoDB Local endpoint "
            "or supply the complete run-bound disposable qualification approval"
        )

    expected_account = os.getenv("FENCE_AWS_WITNESS_EXPECTED_ACCOUNT_ID", "")
    expected_arn_prefix = os.getenv("FENCE_AWS_WITNESS_EXPECTED_CALLER_ARN_PREFIX", "")
    table_name = os.getenv("FENCE_AWS_WITNESS_TABLE_NAME", "")
    qualification_run = os.getenv("FENCE_AWS_WITNESS_QUALIFICATION_RUN_ID", "")
    approval_id = os.getenv("FENCE_AWS_WITNESS_APPROVAL_ID", "")
    approval_run_id = os.getenv("FENCE_AWS_WITNESS_APPROVAL_RUN_ID", "")
    approval_expiry = os.getenv("FENCE_AWS_WITNESS_APPROVAL_EXPIRES_AT", "")
    qualification_environment = os.getenv("FENCE_AWS_WITNESS_ENVIRONMENT", "")
    disposable = os.getenv("FENCE_AWS_WITNESS_DISPOSABLE", "")
    production = os.getenv("FENCE_AWS_WITNESS_PRODUCTION", "")
    admission_enabled = os.getenv("FENCE_AWS_WITNESS_ADMISSION_ENABLED", "")
    if not ACCOUNT_ID.fullmatch(expected_account):
        raise RuntimeError("a pinned 12-digit qualification account ID is required")
    if (
        not expected_arn_prefix.startswith(f"arn:aws:sts::{expected_account}:assumed-role/")
        or not expected_arn_prefix.endswith("/")
    ):
        raise RuntimeError("an exact assumed-role ARN prefix in the pinned account is required")
    if not table_name or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name):
        raise RuntimeError("a pre-provisioned qualification witness table is required")
    if not SAFE_ID.fullmatch(qualification_run) or not SAFE_ID.fullmatch(approval_id):
        raise RuntimeError("a run ID and approval ID are required")
    if approval_run_id != qualification_run:
        raise RuntimeError("the qualification approval must be bound to this exact run ID")
    if (qualification_environment, disposable, production, admission_enabled) != (
        "QUALIFICATION", "true", "false", "false"
    ):
        raise RuntimeError(
            "live writes require QUALIFICATION, disposable=true, production=false and admissionEnabled=false"
        )
    try:
        expiry = datetime.fromisoformat(approval_expiry.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("approval expiry must be an ISO-8601 timestamp with timezone") from exc
    if expiry.tzinfo is None or expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        raise RuntimeError("qualification approval is missing timezone or expired")

    session = boto3.Session(region_name=region)
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    if identity.get("Account") != expected_account or not identity.get("Arn", "").startswith(expected_arn_prefix):
        raise RuntimeError("live AWS caller does not match the pinned qualification account and role")
    client = session.client("dynamodb")
    description = client.describe_table(TableName=table_name).get("Table", {})
    expected_table_arn = f"arn:aws:dynamodb:{region}:{expected_account}:table/{table_name}"
    key_schema = {(item.get("AttributeName"), item.get("KeyType")) for item in description.get("KeySchema", [])}
    expected_key_schema = {("PK", "HASH"), ("SK", "RANGE")}
    if (
        description.get("TableArn") != expected_table_arn
        or description.get("TableStatus") != "ACTIVE"
        or key_schema != expected_key_schema
    ):
        raise RuntimeError(
            "live AWS witness table ARN, Region, ACTIVE state or PK/SK schema does not match the pinned adapter contract"
        )
    return DynamoDBWitnessAdapter(client, table_name)
