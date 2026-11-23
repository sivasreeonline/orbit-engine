#!/usr/bin/env python3
"""Provider-neutral immutable witness checkpoints for monitor replay snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785

from validate_m0_witness_provider_adapter_conformance import (
    AmbiguousCommit,
    AppendConflict,
    Checkpoint,
    Scope,
    ZERO_DIGEST,
    load_adapter_factory,
)


class ReplayCheckpointError(RuntimeError):
    pass


REPLAY_PROVIDER_PHASE = "MONITOR_GOSSIP_REPLAY_V1"
CHECKPOINT_PROFILE = "sky-high-fence-witness-v1"
SNAPSHOT_KEYS = {
    "version",
    "senderId",
    "recipientId",
    "scope",
    "highestSequence",
    "seenBySequence",
    "seenByMessageId",
    "outstandingRequests",
    "consumedNonces",
    "missingSequences",
}


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except Exception as error:
        raise ReplayCheckpointError("value is not RFC 8785 canonical JSON data") from error


def canonical_snapshot_bytes(snapshot: dict[str, Any]) -> bytes:
    if not isinstance(snapshot, dict):
        raise ReplayCheckpointError("replay snapshot must be a JSON object")
    if snapshot == {}:
        return b"{}"
    if set(snapshot) != SNAPSHOT_KEYS:
        raise ReplayCheckpointError("replay snapshot has an unexpected field set")
    if (
        snapshot.get("version") != 1
        or not isinstance(snapshot.get("senderId"), str)
        or len(snapshot.get("senderId", "")) > 256
        or not isinstance(snapshot.get("recipientId"), str)
        or len(snapshot.get("recipientId", "")) > 256
        or not isinstance(snapshot.get("scope"), str)
        or len(snapshot.get("scope", "")) > 256
        or type(snapshot.get("highestSequence")) is not int
        or snapshot["highestSequence"] < 0
        or snapshot["highestSequence"] > 9_007_199_254_740_991
        or not isinstance(snapshot.get("seenBySequence"), dict)
        or not isinstance(snapshot.get("seenByMessageId"), dict)
        or not isinstance(snapshot.get("outstandingRequests"), dict)
        or not isinstance(snapshot.get("consumedNonces"), list)
        or not all(isinstance(value, str) and 0 < len(value) <= 256 for value in snapshot["consumedNonces"])
        or len(set(snapshot["consumedNonces"])) != len(snapshot["consumedNonces"])
        or not isinstance(snapshot.get("missingSequences"), list)
        or not all(type(value) is int and 1 <= value <= 9_007_199_254_740_991 for value in snapshot["missingSequences"])
        or len(set(snapshot["missingSequences"])) != len(snapshot["missingSequences"])
    ):
        raise ReplayCheckpointError("replay snapshot fields are malformed")

    is_empty = (
        snapshot["highestSequence"] == 0
        and snapshot["senderId"] == ""
        and snapshot["recipientId"] == ""
        and snapshot["scope"] == ""
        and not snapshot["seenBySequence"]
        and not snapshot["seenByMessageId"]
        and not snapshot["outstandingRequests"]
        and not snapshot["consumedNonces"]
        and not snapshot["missingSequences"]
    )
    if not is_empty and any(
        not value for value in (snapshot["senderId"], snapshot["recipientId"], snapshot["scope"])
    ):
        raise ReplayCheckpointError("non-empty replay state requires sender, recipient and scope")

    for sequence, entry in snapshot["seenBySequence"].items():
        if (
            not isinstance(sequence, str)
            or not sequence
            or any(character not in "0123456789" for character in sequence)
            or sequence.startswith("0")
            or not isinstance(entry, dict)
            or set(entry) != {"messageId", "digest"}
            or not isinstance(entry["messageId"], str)
            or not entry["messageId"]
            or len(entry["messageId"]) > 256
            or not isinstance(entry["digest"], str)
            or len(entry["digest"]) != 64
            or any(character not in "0123456789abcdef" for character in entry["digest"])
            or int(sequence) > snapshot["highestSequence"]
        ):
            raise ReplayCheckpointError("seenBySequence entry is malformed")
        reverse = snapshot["seenByMessageId"].get(entry["messageId"])
        if not isinstance(reverse, dict) or reverse != {
            "sequence": int(sequence),
            "digest": entry["digest"],
        }:
            raise ReplayCheckpointError("replay sequence and message indexes disagree")

    for message_id, entry in snapshot["seenByMessageId"].items():
        if (
            not isinstance(message_id, str)
            or not message_id
            or len(message_id) > 256
            or not isinstance(entry, dict)
            or set(entry) != {"sequence", "digest"}
            or type(entry["sequence"]) is not int
            or entry["sequence"] < 1
            or entry["sequence"] > 9_007_199_254_740_991
            or not isinstance(entry["digest"], str)
            or len(entry["digest"]) != 64
            or any(character not in "0123456789abcdef" for character in entry["digest"])
            or snapshot["seenBySequence"].get(str(entry["sequence"])) != {
                "messageId": message_id,
                "digest": entry["digest"],
            }
        ):
            raise ReplayCheckpointError("replay message and sequence indexes disagree")

    for request_id, request in snapshot["outstandingRequests"].items():
        if (
            not isinstance(request_id, str)
            or request_id not in snapshot["seenByMessageId"]
            or not isinstance(request, dict)
            or set(request) != {"nonce", "expiresAt"}
            or not isinstance(request["nonce"], str)
            or not request["nonce"]
            or len(request["nonce"]) > 256
            or type(request["expiresAt"]) is not int
            or request["expiresAt"] < 0
            or request["expiresAt"] > 9_007_199_254_740_991
            or request["nonce"] in snapshot["consumedNonces"]
        ):
            raise ReplayCheckpointError("outstanding request entry is malformed")

    for missing in snapshot["missingSequences"]:
        if missing > snapshot["highestSequence"] or str(missing) in snapshot["seenBySequence"]:
            raise ReplayCheckpointError("missing sequence conflicts with replay high-water or seen messages")

    normalized = dict(snapshot)
    normalized["consumedNonces"] = sorted(snapshot["consumedNonces"])
    normalized["missingSequences"] = sorted(snapshot["missingSequences"])
    return _canonical_json_bytes(normalized)

def snapshot_digest(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_snapshot_bytes(snapshot)).hexdigest()


def build_checkpoint_artifact(
    scope: Scope,
    snapshot: dict[str, Any],
    *,
    generation: int,
    previous_digest: str,
) -> dict[str, Any]:
    if type(generation) is not int or generation < 1:
        raise ReplayCheckpointError("checkpoint generation must be a positive integer")
    if not isinstance(previous_digest, str) or len(previous_digest) != 64:
        raise ReplayCheckpointError("previous checkpoint digest is malformed")
    if any(character not in "0123456789abcdef" for character in previous_digest):
        raise ReplayCheckpointError("previous checkpoint digest must be lowercase SHA-256 hex")
    for field in ("trust_domain_id", "witness_id", "authority_id", "host_id", "sender_id", "recipient_id", "replay_scope"):
        value = getattr(scope, field, None)
        if not isinstance(value, str) or not value.strip():
            raise ReplayCheckpointError(f"checkpoint scope {field} is malformed")
    if is_empty_replay_snapshot(snapshot):
        raise ReplayCheckpointError("an empty replay state cannot be checkpointed")

    for scope_field, snapshot_field in (
        ("sender_id", "senderId"),
        ("recipient_id", "recipientId"),
        ("replay_scope", "scope"),
    ):
        expected_value = getattr(scope, scope_field, "")
        if expected_value and snapshot.get(snapshot_field) != expected_value:
            raise ReplayCheckpointError(f"replay snapshot {snapshot_field} does not match provider scope")

    digest = snapshot_digest(snapshot)
    operation_id = f"fence-monitor-replay-{digest}"
    operation_descriptor = {
        "phase": REPLAY_PROVIDER_PHASE,
        "operationId": operation_id,
        "generation": generation,
        "previousCheckpointDigest": previous_digest,
        "snapshotDigest": digest,
        "senderId": snapshot.get("senderId", ""),
        "recipientId": snapshot.get("recipientId", ""),
        "replayScope": snapshot.get("scope", ""),
    }
    response_digest = hashlib.sha256(_canonical_json_bytes(operation_descriptor)).hexdigest()
    body = {
        "profile": CHECKPOINT_PROFILE,
        "schemaVersion": 1,
        "authorityId": scope.authority_id,
        "hostId": scope.host_id,
        "generation": generation,
        "phase": "ACCEPTED",
        "operationId": operation_id,
        "previousCheckpointDigest": previous_digest,
        "authorityStateDigest": digest,
        "responseDigest": response_digest,
        "epoch": snapshot.get("highestSequence", 0),
        "recordVersion": snapshot.get("version", 1),
    }
    checkpoint_digest = hashlib.sha256(_canonical_json_bytes(body)).hexdigest()
    return {
        "snapshotDigest": digest,
        "operationId": operation_id,
        "checkpointBody": body,
        "checkpointDigest": checkpoint_digest,
        "providerPhase": REPLAY_PROVIDER_PHASE,
    }


def _assert_record(record: Any, expected: Checkpoint) -> None:
    if record is None or record.checkpoint != expected:
        raise ReplayCheckpointError("witness operation is missing or bound to different replay snapshot")
    receipt = record.receipt
    if (
        receipt.scope != expected.scope
        or receipt.generation != expected.generation
        or receipt.operation_id != expected.operation_id
        or receipt.checkpoint_digest != expected.checkpoint_digest
        or receipt.previous_digest != expected.previous_digest
        or not receipt.consistency_token.strip()
    ):
        raise ReplayCheckpointError("witness receipt does not bind the exact replay checkpoint")


def checkpoint_replay_snapshot(adapter: Any, scope: Scope, snapshot: dict[str, Any]) -> dict[str, Any]:
    digest = snapshot_digest(snapshot)
    operation_id = f"fence-monitor-replay-{digest}"
    prior = adapter.read_by_operation(scope, operation_id)
    if prior is not None:
        value = prior.checkpoint
        _assert_record(prior, value)
        if value.phase != REPLAY_PROVIDER_PHASE or value.snapshot_digest != digest:
            raise ReplayCheckpointError("existing operation is not bound to this canonical replay snapshot")
        current = adapter.read_latest(scope)
        if current is None or current.checkpoint != value:
            raise ReplayCheckpointError("snapshot replay is stale; it is no longer the current witness head")
        return {
            "status": "ALREADY_CHECKPOINTED",
            "generation": value.generation,
            "digest": digest,
            "snapshotDigest": digest,
            "checkpointDigest": value.checkpoint_digest,
            "receipt": prior.receipt,
        }

    latest = adapter.read_latest(scope)
    expected_generation = latest.checkpoint.generation if latest else 0
    expected_digest = latest.checkpoint.checkpoint_digest if latest else ZERO_DIGEST
    generation = expected_generation + 1
    artifact = build_checkpoint_artifact(
        scope,
        snapshot,
        generation=generation,
        previous_digest=expected_digest,
    )
    value = Checkpoint(
        scope,
        generation,
        operation_id,
        REPLAY_PROVIDER_PHASE,
        artifact["checkpointDigest"],
        expected_digest,
        digest,
    )
    try:
        receipt = adapter.append_if_current(
            value,
            expected_generation=expected_generation,
            expected_digest=expected_digest,
            idempotency_key=operation_id,
        )
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
    return {
        "status": "CHECKPOINTED",
        "generation": generation,
        "digest": digest,
        "snapshotDigest": digest,
        "checkpointDigest": artifact["checkpointDigest"],
        "checkpointBody": artifact["checkpointBody"],
        "receipt": receipt,
    }


def is_empty_replay_snapshot(snapshot: dict[str, Any]) -> bool:
    if snapshot == {}:
        return True
    return (
        isinstance(snapshot, dict)
        and snapshot.get("version") == 1
        and snapshot.get("senderId") == ""
        and snapshot.get("recipientId") == ""
        and snapshot.get("scope") == ""
        and snapshot.get("highestSequence") == 0
        and snapshot.get("seenBySequence") == {}
        and snapshot.get("seenByMessageId") == {}
        and snapshot.get("outstandingRequests") == {}
        and snapshot.get("consumedNonces") == []
        and snapshot.get("missingSequences") == []
    )


def reconcile_replay_snapshot(adapter: Any, scope: Scope, local_snapshot: dict[str, Any]) -> dict[str, Any]:
    local_digest = snapshot_digest(local_snapshot)
    latest = adapter.read_latest(scope)
    if latest is None:
        if is_empty_replay_snapshot(local_snapshot):
            return {"status": "NO_CHECKPOINT_EMPTY_STATE", "localDigest": local_digest}
        return {
            "status": "QUARANTINE",
            "reason": "local replay state exists without an independent witness checkpoint",
            "localDigest": local_digest,
        }
    expected = latest.checkpoint
    if expected.phase != REPLAY_PROVIDER_PHASE:
        return {"status": "BLOCKED", "reason": "witness scope head is not a monitor replay checkpoint"}
    if not expected.snapshot_digest:
        return {"status": "BLOCKED", "reason": "witness checkpoint lacks the replay snapshot digest binding"}
    if local_digest != expected.snapshot_digest:
        return {
            "status": "QUARANTINE",
            "reason": "local replay snapshot differs from independently witnessed high-water",
            "localDigest": local_digest,
            "witnessDigest": expected.snapshot_digest,
            "witnessCheckpointDigest": expected.checkpoint_digest,
            "witnessGeneration": expected.generation,
        }
    return {
        "status": "MATCH",
        "localDigest": local_digest,
        "witnessGeneration": expected.generation,
        "witnessOperationId": expected.operation_id,
        "witnessCheckpointDigest": expected.checkpoint_digest,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--trust-domain-id", required=True)
    parser.add_argument("--witness-id", required=True)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--sender-id", default="")
    parser.add_argument("--recipient-id", default="")
    parser.add_argument("--replay-scope", default="")
    parser.add_argument("--reconcile-only", action="store_true")
    args = parser.parse_args()
    factory, adapter_kind = load_adapter_factory()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    scope = Scope(
        args.trust_domain_id,
        args.witness_id,
        args.authority_id,
        args.host_id,
        args.sender_id,
        args.recipient_id,
        args.replay_scope,
    )
    operation = reconcile_replay_snapshot if args.reconcile_only else checkpoint_replay_snapshot
    result = operation(factory(), scope, snapshot)
    print(f"Monitor replay witness result: {result['status']}")
    print(f"Adapter mode: {adapter_kind}")
    print("This result does not establish production witness independence or Cloudflare rollback protection.")


if __name__ == "__main__":
    main()
