#!/usr/bin/env python3
"""Provider-neutral immutable witness checkpoints for monitor replay snapshots."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from validate_m0_witness_provider_adapter_conformance import AmbiguousCommit, AppendConflict, Checkpoint, Scope, ZERO_DIGEST, load_adapter_factory

class ReplayCheckpointError(RuntimeError):
    pass

def canonical_snapshot_bytes(snapshot: dict[str, Any]) -> bytes:
    if not isinstance(snapshot, dict):
        raise ReplayCheckpointError("replay snapshot must be a JSON object")
    try:
        return json.dumps(snapshot, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ReplayCheckpointError("replay snapshot is not canonical JSON data") from error

def snapshot_digest(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_snapshot_bytes(snapshot)).hexdigest()

def _assert_record(record: Any, expected: Checkpoint) -> None:
    if record is None or record.checkpoint != expected:
        raise ReplayCheckpointError("witness operation is missing or bound to different replay snapshot")
    receipt = record.receipt
    if (receipt.scope != expected.scope or receipt.generation != expected.generation
        or receipt.operation_id != expected.operation_id or receipt.checkpoint_digest != expected.checkpoint_digest
        or receipt.previous_digest != expected.previous_digest or not receipt.consistency_token.strip()):
        raise ReplayCheckpointError("witness receipt does not bind the exact replay checkpoint")

def checkpoint_replay_snapshot(adapter: Any, scope: Scope, snapshot: dict[str, Any]) -> dict[str, Any]:
    digest = snapshot_digest(snapshot)
    latest = adapter.read_latest(scope)
    expected_generation = latest.checkpoint.generation if latest else 0
    expected_digest = latest.checkpoint.checkpoint_digest if latest else ZERO_DIGEST
    operation_id = f"fence-monitor-replay-{digest}"
    prior = adapter.read_by_operation(scope, operation_id)
    if prior is not None:
        value = prior.checkpoint
        _assert_record(prior, value)
        if value.phase != "MONITOR_GOSSIP_REPLAY_V1" or value.checkpoint_digest != digest:
            raise ReplayCheckpointError("existing operation is not bound to this canonical replay snapshot")
        current = adapter.read_latest(scope)
        if current is None or current.checkpoint != value:
            raise ReplayCheckpointError("snapshot replay is stale; it is no longer the current witness head")
        return {"status": "ALREADY_CHECKPOINTED", "generation": value.generation, "digest": digest, "receipt": prior.receipt}
    generation = expected_generation + 1
    value = Checkpoint(scope, generation, operation_id, "MONITOR_GOSSIP_REPLAY_V1", digest, expected_digest)
    try:
        receipt = adapter.append_if_current(value, expected_generation=expected_generation,
            expected_digest=expected_digest, idempotency_key=operation_id)
    except AmbiguousCommit:
        recovered = adapter.read_by_operation(scope, operation_id)
        if recovered is None:
            raise ReplayCheckpointError("ambiguous witness acknowledgement could not be recovered")
        _assert_record(recovered, value)
        receipt = recovered.receipt
    except AppendConflict:
        raise
    committed = adapter.read_by_operation(scope, operation_id)
    _assert_record(committed, value)
    current = adapter.read_latest(scope)
    if current is None or current.checkpoint != value or current.receipt != receipt:
        raise ReplayCheckpointError("strong witness latest readback differs from committed replay snapshot")
    return {"status": "CHECKPOINTED", "generation": generation, "digest": digest, "receipt": receipt}

def reconcile_replay_snapshot(adapter: Any, scope: Scope, local_snapshot: dict[str, Any]) -> dict[str, Any]:
    local_digest = snapshot_digest(local_snapshot)
    latest = adapter.read_latest(scope)
    if latest is None:
        if local_snapshot == {}:
            return {"status": "NO_CHECKPOINT_EMPTY_STATE", "localDigest": local_digest}
        return {"status": "QUARANTINE", "reason": "local replay state exists without an independent witness checkpoint", "localDigest": local_digest}
    expected = latest.checkpoint
    if expected.phase != "MONITOR_GOSSIP_REPLAY_V1":
        return {"status": "BLOCKED", "reason": "witness scope head is not a monitor replay checkpoint"}
    if local_digest != expected.checkpoint_digest:
        return {"status": "QUARANTINE", "reason": "local replay snapshot differs from independently witnessed high-water",
            "localDigest": local_digest, "witnessDigest": expected.checkpoint_digest, "witnessGeneration": expected.generation}
    return {"status": "MATCH", "localDigest": local_digest, "witnessGeneration": expected.generation,
        "witnessOperationId": expected.operation_id}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--trust-domain-id", required=True)
    parser.add_argument("--witness-id", required=True)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--reconcile-only", action="store_true")
    args = parser.parse_args()
    factory, adapter_kind = load_adapter_factory()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    scope = Scope(args.trust_domain_id, args.witness_id, args.authority_id, args.host_id)
    result = (reconcile_replay_snapshot if args.reconcile_only else checkpoint_replay_snapshot)(factory(), scope, snapshot)
    print(f"Monitor replay witness result: {result['status']}")
    print(f"Adapter mode: {adapter_kind}")
    print("This result does not establish production witness independence or Cloudflare rollback protection.")

if __name__ == "__main__":
    main()
