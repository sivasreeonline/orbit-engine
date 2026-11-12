#!/usr/bin/env python3
"""Additional integration checks for the FENCE-001 DynamoDB Local adapter.

These tests require only an AWS-published DynamoDB Local loopback endpoint.
They do not authenticate to AWS or create cloud resources.
"""
from __future__ import annotations

import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import boto3

from aws_dynamodb_witness_adapter import DynamoDBWitnessAdapter, _create_local_table
from validate_m0_witness_provider_adapter_conformance import (
    AppendConflict,
    Checkpoint,
    Scope,
    ZERO_DIGEST,
)

def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def make_checkpoint(scope: Scope, generation: int, operation_id: str, digest_char: str,
                    previous_digest: str) -> Checkpoint:
    return Checkpoint(
        scope=scope,
        generation=generation,
        operation_id=operation_id,
        phase="ISSUED",
        checkpoint_digest=digest_char * 64,
        previous_digest=previous_digest,
    )


class NoTransactionAfterFirstCommit:
    def __init__(self, delegate):
        self._delegate = delegate

    def __getattr__(self, name):
        if name == "transact_write_items":
            raise AssertionError("durable retry unexpectedly called TransactWriteItems again")
        return getattr(self._delegate, name)


def main() -> None:
    endpoint = os.getenv("FENCE_AWS_WITNESS_ENDPOINT_URL", "")
    region = os.getenv("FENCE_AWS_WITNESS_REGION") or os.getenv("AWS_REGION") or "us-east-1"
    parsed = urlparse(endpoint)
    require(parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"},
            "integration tests require a loopback DynamoDB Local endpoint")
    client_kwargs = {
        "endpoint_url": endpoint,
        "region_name": region,
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID", "local"),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY", "local"),
    }

    # A retry recovers from the durable idempotency record without depending on
    # the 10-minute DynamoDB ClientRequestToken cache or issuing another write.
    durable_adapter = __import__("aws_dynamodb_witness_adapter").create_adapter()
    scope = Scope("local-domain", "durable-witness", "local-authority", "local-host")
    original = make_checkpoint(scope, 1, "durable-op-001", "1", ZERO_DIGEST)
    first = durable_adapter.append_if_current(
        original,
        expected_generation=0,
        expected_digest=ZERO_DIGEST,
        idempotency_key="long-lived-idempotency-key",
    )
    durable_adapter._client = NoTransactionAfterFirstCommit(durable_adapter._client)
    retried = durable_adapter.append_if_current(
        original,
        expected_generation=0,
        expected_digest=ZERO_DIGEST,
        idempotency_key="long-lived-idempotency-key",
    )
    require(retried == first, "durable retry did not recover the original receipt")

    # Use eight independent SDK clients against one local table so the race is
    # resolved by the DynamoDB transaction condition, not a shared Python lock.
    table_name = "fence001-multiclient-" + uuid.uuid4().hex[:16]
    creator = boto3.client("dynamodb", **client_kwargs)
    _create_local_table(creator, table_name)
    adapters = [
        DynamoDBWitnessAdapter(boto3.client("dynamodb", **client_kwargs), table_name)
        for _ in range(8)
    ]
    race_scope = Scope("local-domain", "multiclient-witness", "local-authority", "local-host")
    genesis = make_checkpoint(race_scope, 1, "multi-genesis", "a", ZERO_DIGEST)
    genesis_receipt = adapters[0].append_if_current(
        genesis, expected_generation=0, expected_digest=ZERO_DIGEST,
        idempotency_key="multi-genesis-key",
    )
    digest_characters = "bcdef012"
    candidates = [
        make_checkpoint(race_scope, 2, f"multi-race-{index}", digest_characters[index],
                        genesis_receipt.checkpoint_digest)
        for index in range(len(adapters))
    ]

    def attempt(pair):
        adapter, candidate = pair
        try:
            receipt = adapter.append_if_current(
                candidate,
                expected_generation=1,
                expected_digest=genesis_receipt.checkpoint_digest,
                idempotency_key=f"multi-race-key-{candidate.operation_id}",
            )
            return ("committed", receipt)
        except AppendConflict:
            return ("conflict", None)

    with ThreadPoolExecutor(max_workers=len(adapters)) as pool:
        outcomes = list(pool.map(attempt, zip(adapters, candidates)))
    winners = [receipt for status, receipt in outcomes if status == "committed"]
    conflicts = [status for status, _ in outcomes if status == "conflict"]
    require(len(winners) == 1, f"independent clients produced {len(winners)} winners instead of one")
    require(len(conflicts) == len(adapters) - 1, "not all losing independent clients were rejected")
    latest = adapters[0].read_latest(race_scope)
    require(latest is not None and latest.receipt == winners[0],
            "strong latest read did not return the independent-client winner")

    print("AWS DynamoDB Local adapter integration: PASS")
    print("- durable idempotency retry did not issue a second transaction")
    print("- eight independent SDK clients produced exactly one conditional-transaction winner")
    print("Synthetic local service only; not AWS provider qualification.")


if __name__ == "__main__":
    main()
