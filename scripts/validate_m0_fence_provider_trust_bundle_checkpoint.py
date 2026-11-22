#!/usr/bin/env python3
"""Durably accept a root-verified FENCE-001 trust-bundle head through a witness."""
from __future__ import annotations
import argparse
from pathlib import Path
from typing import Any
from validate_m0_fence_rooted_trust_bundle import load_json, load_pinned_roots, verify_trust_bundle
from validate_m0_witness_provider_adapter_conformance import (
    AppendConflict, AmbiguousCommit, Checkpoint, Scope, ZERO_DIGEST, load_adapter_factory,
)

class CheckpointAcceptanceError(RuntimeError):
    pass

def _assert_record(record: Any, value: Checkpoint) -> None:
    if record is None or record.checkpoint != value:
        raise CheckpointAcceptanceError("durable witness operation is missing or bound to different checkpoint content")
    receipt = record.receipt
    if (receipt.scope != value.scope or receipt.generation != value.generation
        or receipt.operation_id != value.operation_id or receipt.checkpoint_digest != value.checkpoint_digest
        or receipt.previous_digest != value.previous_digest or not receipt.consistency_token.strip()):
        raise CheckpointAcceptanceError("witness receipt does not bind the exact trust-bundle checkpoint")

def accept_trust_bundle_checkpoint(adapter: Any, envelope: dict[str, Any], pinned_roots: dict[str, bytes],
    *, manifest: dict[str, Any], trust_domain_id: str, witness_id: str, authority_id: str, host_id: str) -> dict[str, Any]:
    scope = Scope(trust_domain_id, witness_id, authority_id, host_id)
    body = envelope.get("body")
    if not isinstance(body, dict):
        raise CheckpointAcceptanceError("trust-bundle body is missing")
    generation, digest, predecessor = body.get("generation"), envelope.get("bundleDigest"), body.get("previousBundleDigest")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise CheckpointAcceptanceError("trust-bundle generation must be a positive integer")
    if not isinstance(digest, str) or len(digest) != 64 or not isinstance(predecessor, str) or len(predecessor) != 64:
        raise CheckpointAcceptanceError("trust-bundle or predecessor digest is malformed")
    operation_id = f"fence-trust-bundle-{generation}-{digest[:24]}"
    value = Checkpoint(scope, generation, operation_id, "ACCEPTED", digest, predecessor)

    # Recover a lost acknowledgement only if this exact operation remains current.
    prior = adapter.read_by_operation(scope, operation_id)
    if prior is not None:
        _assert_record(prior, value)
        latest = adapter.read_latest(scope)
        if latest is None or latest.checkpoint != value:
            raise CheckpointAcceptanceError("replayed trust-bundle checkpoint is no longer the current high-water")
        return {"status": "ALREADY_ACCEPTED", "generation": generation, "bundleDigest": digest, "receipt": prior.receipt}

    latest = adapter.read_latest(scope)
    expected_generation = latest.checkpoint.generation if latest else 0
    expected_digest = latest.checkpoint.checkpoint_digest if latest else ZERO_DIGEST
    verify_trust_bundle(envelope, pinned_roots, expected_generation=expected_generation,
        expected_predecessor_digest=expected_digest, expected_trust_domain_id=trust_domain_id, manifest=manifest)
    if generation != expected_generation + 1 or predecessor != expected_digest:
        raise CheckpointAcceptanceError("trust bundle does not extend the durable witness high-water")

    try:
        receipt = adapter.append_if_current(value, expected_generation=expected_generation,
            expected_digest=expected_digest, idempotency_key=operation_id)
    except AmbiguousCommit:
        recovered = adapter.read_by_operation(scope, operation_id)
        if recovered is None:
            raise
        _assert_record(recovered, value)
        receipt = recovered.receipt
    except AppendConflict:
        raise

    committed = adapter.read_by_operation(scope, operation_id)
    _assert_record(committed, value)
    current = adapter.read_latest(scope)
    if current is None or current.checkpoint != value or current.receipt != receipt:
        raise CheckpointAcceptanceError("strong latest readback did not return the accepted trust-bundle head")
    return {"status": "ACCEPTED", "generation": generation, "bundleDigest": digest, "receipt": receipt}

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--trust-bundle", type=Path, required=True)
    parser.add_argument("--pinned-roots", type=Path, required=True)
    parser.add_argument("--trust-domain-id", required=True)
    parser.add_argument("--witness-id", required=True)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--host-id", required=True)
    args = parser.parse_args()
    factory, adapter_kind = load_adapter_factory()
    result = accept_trust_bundle_checkpoint(factory(), load_json(args.trust_bundle), load_pinned_roots(args.pinned_roots),
        manifest=load_json(args.manifest), trust_domain_id=args.trust_domain_id, witness_id=args.witness_id,
        authority_id=args.authority_id, host_id=args.host_id)
    print(f"Durable trust-bundle checkpoint: {result['status']}")
    print(f"Generation: {result['generation']}")
    print(f"Bundle digest: {result['bundleDigest']}")
    print(f"Adapter mode: {adapter_kind}")
    print("This result does not qualify witness independence, anti-equivocation or production readiness.")

if __name__ == "__main__":
    main()
