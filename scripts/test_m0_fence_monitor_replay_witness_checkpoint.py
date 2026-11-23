#!/usr/bin/env python3
"""Synthetic monitor replay snapshot witness-checkpoint tests."""
from __future__ import annotations
from validate_m0_fence_monitor_replay_witness_checkpoint import (
    ReplayCheckpointError,
    build_checkpoint_artifact,
    checkpoint_replay_snapshot,
    is_empty_replay_snapshot,
    reconcile_replay_snapshot,
    snapshot_digest,
)
from validate_m0_witness_provider_adapter_conformance import AppendConflict, InMemoryWitnessAdapter, LoseAcknowledgementOnce, Scope

SCOPE = Scope("monitor-test-domain", "monitor-test-witness", "monitor-a", "monitor-b", "monitor-a", "monitor-b", "domain|witness|authority|host")

def sample(sequence: int = 1) -> dict:
    return {"version": 1, "senderId": "monitor-a", "recipientId": "monitor-b",
        "scope": "domain|witness|authority|host", "highestSequence": sequence,
        "seenBySequence": {str(sequence): {"messageId": f"message-{sequence}", "digest": f"{sequence:064x}"}},
        "seenByMessageId": {f"message-{sequence}": {"sequence": sequence, "digest": f"{sequence:064x}"}},
        "outstandingRequests": {}, "consumedNonces": [], "missingSequences": []}

def main() -> None:
    adapter = InMemoryWitnessAdapter()
    first = sample(1)
    accepted = checkpoint_replay_snapshot(adapter, SCOPE, first)
    assert accepted["status"] == "CHECKPOINTED"
    assert accepted["snapshotDigest"] == snapshot_digest(first)
    assert accepted["snapshotDigest"] == "3e67d5db1c0f34ddd48fd964ef7b3993ee395f3fd166010ebd74076594dba7cb"
    assert accepted["checkpointBody"]["responseDigest"] == "6f6d145824a1186726d43b65ff6edff79631be9e088f33e655386d3c1b189a5d"
    assert accepted["checkpointDigest"] == "c9db31c134f4e476758bca6860ce8dd4567691fae04a78dc18814cf9e1426ce2"
    assert accepted["checkpointDigest"] != accepted["snapshotDigest"]
    assert accepted["checkpointBody"]["authorityStateDigest"] == accepted["snapshotDigest"]
    assert accepted["checkpointBody"]["phase"] == "ACCEPTED"
    assert reconcile_replay_snapshot(adapter, SCOPE, first)["status"] == "MATCH"
    assert checkpoint_replay_snapshot(adapter, SCOPE, first)["status"] == "ALREADY_CHECKPOINTED"
    changed_order = dict(reversed(list(first.items())))
    assert snapshot_digest(changed_order) == snapshot_digest(first)

    artifact = build_checkpoint_artifact(
        SCOPE,
        first,
        generation=1,
        previous_digest="0" * 64,
    )
    assert artifact["operationId"] == f"fence-monitor-replay-{snapshot_digest(first)}"
    assert artifact["checkpointBody"]["authorityStateDigest"] == snapshot_digest(first)
    assert artifact["checkpointDigest"] != snapshot_digest(first)
    print("PASS snapshot digest is bound separately from cryptographic checkpoint artifact digest")
    print("PASS canonical snapshot digest and exact retry idempotency")

    tampered = sample(2)
    result = reconcile_replay_snapshot(adapter, SCOPE, tampered)
    assert result["status"] == "QUARANTINE" and result["witnessDigest"] == accepted["digest"]
    print("PASS stale or altered local replay snapshot is quarantined")

    second = sample(2)
    assert checkpoint_replay_snapshot(adapter, SCOPE, second)["generation"] == 2
    assert reconcile_replay_snapshot(adapter, SCOPE, second)["status"] == "MATCH"
    assert reconcile_replay_snapshot(adapter, SCOPE, first)["status"] == "QUARANTINE"
    print("PASS successor advances high-water; older snapshot cannot be restored as current")

    recovery = LoseAcknowledgementOnce(InMemoryWitnessAdapter())
    recovered = checkpoint_replay_snapshot(recovery, SCOPE, first)
    assert recovered["status"] == "CHECKPOINTED"
    assert checkpoint_replay_snapshot(recovery, SCOPE, first)["status"] == "ALREADY_CHECKPOINTED"
    assert reconcile_replay_snapshot(recovery, SCOPE, first)["status"] == "MATCH"
    print("PASS lost acknowledgement recovers exact committed operation")

    empty = InMemoryWitnessAdapter()
    assert reconcile_replay_snapshot(empty, SCOPE, {})["status"] == "NO_CHECKPOINT_EMPTY_STATE"
    actual_empty_do_snapshot = {
        "version": 1, "senderId": "", "recipientId": "", "scope": "",
        "highestSequence": 0, "seenBySequence": {}, "seenByMessageId": {},
        "outstandingRequests": {}, "consumedNonces": [], "missingSequences": [],
    }
    assert is_empty_replay_snapshot(actual_empty_do_snapshot)
    assert reconcile_replay_snapshot(empty, SCOPE, actual_empty_do_snapshot)["status"] == "NO_CHECKPOINT_EMPTY_STATE"
    assert reconcile_replay_snapshot(empty, SCOPE, first)["status"] == "QUARANTINE"
    print("PASS unanchored non-empty local state quarantines")

    try:
        snapshot_digest({"invalid": float("nan")})
    except ReplayCheckpointError:
        pass
    else:
        raise AssertionError("non-finite JSON number was accepted")
    print("PASS non-canonical JSON values are rejected")

    competing = InMemoryWitnessAdapter()
    checkpoint_replay_snapshot(competing, SCOPE, first)
    stale_head = competing.read_latest(SCOPE)
    candidate_a, candidate_b = sample(2), sample(3)

    class StaleHeadView:
        def read_latest(self, scope):
            return stale_head
        def read_by_operation(self, scope, operation_id):
            return competing.read_by_operation(scope, operation_id)
        def append_if_current(self, value, **kwargs):
            return competing.append_if_current(value, **kwargs)

    assert checkpoint_replay_snapshot(competing, SCOPE, candidate_a)["status"] == "CHECKPOINTED"
    try:
        checkpoint_replay_snapshot(StaleHeadView(), SCOPE, candidate_b)
    except (AppendConflict, ReplayCheckpointError):
        pass
    else:
        raise AssertionError("competing stale successor unexpectedly advanced the same predecessor")
    print("PASS stale competing successor cannot replace witnessed head")
    print("Monitor replay witness checkpoint tests: PASS (in-memory synthetic adapter only)")

if __name__ == "__main__":
    main()
