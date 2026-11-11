#!/usr/bin/env python3
"""Deterministic synthetic crash/recovery model for FENCE-001 authority protocol.

This validates protocol ordering and recovery decisions only. It is not a
database, provider, cryptographic witness, or production authority.
"""
from __future__ import annotations

import copy
import hashlib
import json


class Conflict(Exception):
    pass


class Denied(Exception):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(value: object) -> str:
    raw = value if isinstance(value, bytes) else canonical(value)
    return hashlib.sha256(raw).hexdigest()


class Witness:
    """Independent monotonic checkpoint; deliberately outside DB snapshots."""

    def __init__(self) -> None:
        self.generation = 0
        self.checkpoint_digest = "0" * 64
        self.checkpoint: dict | None = None
        self.available = True

    def advance(self, intent: dict) -> dict:
        if not self.available:
            raise Denied("external witness unavailable")
        if self.checkpoint and self.checkpoint.get("operation_id") == intent["operation_id"]:
            if self.checkpoint == intent:
                return copy.deepcopy(self.checkpoint)
            raise Conflict("checkpoint operation ID rebound")
        if intent["generation"] != self.generation + 1:
            raise Conflict("witness generation is not the exact successor")
        if intent["previous_checkpoint_digest"] != self.checkpoint_digest:
            raise Conflict("witness compare-and-swap predecessor mismatch")
        if self.checkpoint and intent["epoch"] < self.checkpoint["epoch"]:
            raise Denied("witness epoch high-water mark cannot decrease")
        self.generation = intent["generation"]
        self.checkpoint = copy.deepcopy(intent)
        self.checkpoint_digest = digest(intent)
        return copy.deepcopy(intent)


class AuthorityDB:
    """Transactional-state stand-in. Snapshot/restore excludes the witness."""

    def __init__(self) -> None:
        self.host_id = "host-01"
        self.epoch = 5
        self.instance_id = "vm-old"
        self.version = 1
        self.pending: dict | None = None
        self.nonces: dict[str, dict] = {}
        self.operations: dict[str, dict] = {}
        self.events: list[dict] = []
        self.intent: dict | None = None
        self.anchored_generation = 0
        self.anchored_digest = "0" * 64
        self.published = False
        self.quarantined = False

    def core(self) -> dict:
        return {
            "host_id": self.host_id,
            "epoch": self.epoch,
            "instance_id": self.instance_id,
            "version": self.version,
            "pending": self.pending,
            "nonces": self.nonces,
            "operations": self.operations,
            "events": self.events,
        }

    def state_digest(self) -> str:
        return digest(self.core())

    def snapshot(self) -> dict:
        return copy.deepcopy(self.__dict__)

    def restore(self, snapshot: dict) -> None:
        self.__dict__.clear()
        self.__dict__.update(copy.deepcopy(snapshot))


class Protocol:
    def __init__(self) -> None:
        self.db = AuthorityDB()
        self.witness = Witness()

    def _intent(self, operation_id: str) -> dict:
        return {
            "authority_id": "authority-test",
            "host_id": self.db.host_id,
            "generation": self.witness.generation + 1,
            "previous_checkpoint_digest": self.witness.checkpoint_digest,
            "epoch": self.db.epoch,
            "record_version": self.db.version,
            "operation_id": operation_id,
            "state_digest": self.db.state_digest(),
        }

    def _anchor(self, operation_id: str, *, lose_ack: bool = False,
                crash_after_witness: bool = False) -> None:
        intent = self.db.intent
        if intent is None or intent["operation_id"] != operation_id:
            raise Denied("no matching durable checkpoint intent")
        receipt = self.witness.advance(intent)
        if crash_after_witness:
            raise RuntimeError("CRASH_AFTER_WITNESS_ADVANCE")
        if receipt != intent:
            raise Denied("witness readback differs from exact checkpoint intent")
        self.db.anchored_generation = receipt["generation"]
        self.db.anchored_digest = digest(receipt)
        if lose_ack:
            raise RuntimeError("WITNESS_ACK_LOST")

    def _commit_checkpointed(self, operation_id: str, *, lose_ack: bool = False,
                             crash_after_witness: bool = False) -> None:
        self.db.intent = self._intent(operation_id)
        self._anchor(operation_id, lose_ack=lose_ack,
                     crash_after_witness=crash_after_witness)

    def issue(self, *, operation_id: str, nonce: str, request_digest: str,
              expected_version: int, target: str, fence_confirmed: bool = True,
              crash_before_commit: bool = False, lose_db_ack: bool = False,
              lose_witness_ack: bool = False,
              crash_after_witness: bool = False) -> bytes:
        db = self.db
        if db.quarantined:
            raise Denied("authority is quarantined")
        prior_n = db.nonces.get(nonce)
        prior_o = db.operations.get(operation_id)
        if prior_n or prior_o:
            if not prior_n or not prior_o:
                raise Conflict("nonce and operation indexes disagree")
            if prior_n != prior_o or prior_n["request_digest"] != request_digest:
                raise Conflict("idempotency identity or request digest conflict")
            return prior_n["response_bytes"]
        if expected_version != db.version:
            raise Conflict("authority record CAS mismatch")
        if db.pending and not db.pending["accepted"]:
            raise Denied("one successor is already pending")
        if not fence_confirmed:
            raise Denied("predecessor fence evidence is not confirmed")
        if target == db.instance_id:
            raise Denied("successor must be a distinct provider instance")

        before = db.snapshot()
        response_obj = {
            "host_id": db.host_id, "operation_id": operation_id,
            "nonce": nonce, "request_digest": request_digest,
            "provider_instance_id": target, "incarnation_epoch": db.epoch + 1,
            "predecessor_max_epoch": db.epoch,
        }
        response_bytes = canonical(response_obj)
        db.epoch += 1
        db.instance_id = target
        db.version += 1
        record = {"request_digest": request_digest, "operation_id": operation_id,
                  "response_bytes": response_bytes, "response_digest": digest(response_bytes)}
        db.pending = {"operation_id": operation_id, "target": target,
                      "epoch": db.epoch, "response_digest": digest(response_bytes),
                      "accepted": False}
        db.nonces[nonce] = record
        db.operations[operation_id] = record
        db.events.append({"type": "ISSUANCE_COMMITTED", "version": db.version,
                          "operation_id": operation_id, "response_digest": digest(response_bytes)})
        if crash_before_commit:
            db.restore(before)
            raise RuntimeError("CRASH_BEFORE_COMMIT")
        db.intent = self._intent(operation_id)
        if lose_db_ack:
            raise RuntimeError("DB_COMMIT_ACK_LOST")
        self._anchor(operation_id, lose_ack=lose_witness_ack,
                     crash_after_witness=crash_after_witness)
        return response_bytes

    def publish(self, operation_id: str) -> bytes:
        self.verify()
        if not self.db.pending or self.db.pending["operation_id"] != operation_id:
            raise Denied("no matching issuance")
        if self.db.anchored_generation != self.witness.generation:
            raise Denied("issuance is not externally anchored")
        record = self.db.operations[operation_id]
        self.db.published = True
        return record["response_bytes"]

    def accept(self, operation_id: str, response_bytes: bytes, target: str,
               epoch: int, *, lose_witness_ack: bool = False) -> None:
        self.verify()
        db = self.db
        if not db.pending or db.pending["operation_id"] != operation_id:
            raise Denied("no pending target issuance")
        if not db.published or db.anchored_generation != self.witness.generation:
            raise Denied("response has not been anchored and published")
        record = db.operations[operation_id]
        if response_bytes != record["response_bytes"]:
            raise Denied("acceptance response bytes differ")
        if target != db.pending["target"] or epoch != db.pending["epoch"]:
            raise Denied("acceptance target or epoch mismatch")
        if db.pending["accepted"]:
            return
        db.pending["accepted"] = True
        db.version += 1
        db.events.append({"type": "ACCEPTED", "version": db.version,
                          "operation_id": operation_id,
                          "response_digest": digest(response_bytes)})
        self._commit_checkpointed("accept:" + operation_id, lose_ack=lose_witness_ack)

    def verify(self) -> None:
        db = self.db
        witness = self.witness
        if db.quarantined or not witness.available or witness.checkpoint is None:
            raise Denied("authority cannot establish an external checkpoint")
        cp = witness.checkpoint
        if (cp["host_id"] != db.host_id or cp["epoch"] != db.epoch
                or cp["record_version"] != db.version
                or cp["state_digest"] != db.state_digest()
                or cp["generation"] != witness.generation
                or cp["generation"] != db.anchored_generation
                or digest(cp) != db.anchored_digest):
            raise Denied("database state differs from independent witness anchor")

    def recover(self) -> str:
        db = self.db
        witness = self.witness
        if not witness.available or witness.checkpoint is None:
            db.quarantined = True
            raise Denied("recovery cannot establish witness high-water mark")
        cp = witness.checkpoint
        # A witness may have advanced while the local acknowledgement write
        # was lost. Repair only if the exact state/intent still matches.
        if (db.intent == cp and db.state_digest() == cp["state_digest"]
                and db.version == cp["record_version"] and db.epoch == cp["epoch"]):
            db.anchored_generation = cp["generation"]
            db.anchored_digest = digest(cp)
            db.quarantined = False
            return "RECONCILED_EXACT_CHECKPOINT"
        if (db.state_digest() == cp["state_digest"]
                and db.version == cp["record_version"] and db.epoch == cp["epoch"]):
            db.anchored_generation = cp["generation"]
            db.anchored_digest = digest(cp)
            db.quarantined = False
            return "EXACT_STATE_MATCH"
        db.quarantined = True
        raise Denied("local authority state cannot be reconciled to witness; quarantine")

    def advance_for_test(self) -> None:
        """Advance witness through a legitimate checkpointed no-op audit event."""
        self.db.version += 1
        self.db.events.append({"type": "AUDIT_NOOP", "version": self.db.version})
        self._commit_checkpointed("audit:" + str(self.db.version))


def expect(error: type[BaseException], action, label: str) -> None:
    try:
        action()
    except error:
        return
    raise AssertionError(label)


def scenario_commit_and_lost_db_ack() -> None:
    p = Protocol()
    expect(RuntimeError, lambda: p.issue(operation_id="op-pre", nonce="n-pre",
        request_digest="d-pre", expected_version=1, target="vm-pre",
        crash_before_commit=True), "pre-commit crash must be injected")
    assert p.db.epoch == 5 and not p.db.nonces and p.witness.generation == 0
    expect(RuntimeError, lambda: p.issue(operation_id="op-1", nonce="n-1",
        request_digest="d-1", expected_version=1, target="vm-1",
        lose_db_ack=True), "lost database acknowledgement must be injected")
    assert p.db.epoch == 6 and p.witness.generation == 0
    response = p.issue(operation_id="op-1", nonce="n-1", request_digest="d-1",
        expected_version=1, target="vm-1")
    assert response == p.db.operations["op-1"]["response_bytes"]
    assert p.witness.generation == 1
    assert p.publish("op-1") == response
    assert p.db.epoch == 6


def scenario_witness_lost_ack_and_recovery() -> None:
    p = Protocol()
    expect(RuntimeError, lambda: p.issue(operation_id="op-2", nonce="n-2",
        request_digest="d-2", expected_version=1, target="vm-2",
        crash_after_witness=True), "crash after witness advance must be injected")
    assert p.witness.generation == 1 and p.db.anchored_generation == 0
    assert p.recover() == "RECONCILED_EXACT_CHECKPOINT"
    response = p.publish("op-2")
    assert response == p.db.operations["op-2"]["response_bytes"]


def scenario_restore_and_quarantine() -> None:
    p = Protocol()
    response = p.issue(operation_id="op-3", nonce="n-3", request_digest="d-3",
        expected_version=1, target="vm-3")
    old = p.db.snapshot()
    p.advance_for_test()
    p.verify()
    p.db.restore(old)
    expect(Denied, p.verify, "restored stale DB must fail witness check")
    expect(Denied, p.recover, "witness-ahead state without recoverable log must quarantine")
    assert p.db.quarantined
    expect(Denied, lambda: p.publish("op-3"), "quarantined state must not publish")
    assert response


def scenario_acceptance_and_ack_loss() -> None:
    p = Protocol()
    response = p.issue(operation_id="op-4", nonce="n-4", request_digest="d-4",
        expected_version=1, target="vm-4")
    p.publish("op-4")
    expect(RuntimeError, lambda: p.accept("op-4", response, "vm-4", 6,
        lose_witness_ack=True), "acceptance checkpoint acknowledgement loss injected")
    assert p.witness.generation == 2 and p.db.anchored_generation == 1
    assert p.recover() == "RECONCILED_EXACT_CHECKPOINT"
    p.accept("op-4", response, "vm-4", 6)
    assert p.db.pending["accepted"] and p.witness.generation == 2
    expect(Denied, lambda: p.accept("op-4", response + b" ", "vm-4", 6),
           "altered response must not be accepted")


def scenario_replay_and_witness_fail_closed() -> None:
    p = Protocol()
    response = p.issue(operation_id="op-5", nonce="n-5", request_digest="d-5",
        expected_version=1, target="vm-5")
    assert p.issue(operation_id="op-5", nonce="n-5", request_digest="d-5",
        expected_version=1, target="vm-5") == response
    expect(Conflict, lambda: p.issue(operation_id="op-5", nonce="n-5",
        request_digest="changed", expected_version=2, target="vm-other"),
        "changed request digest must conflict")
    expect(Conflict, lambda: p.issue(operation_id="op-other", nonce="n-5",
        request_digest="d-5", expected_version=2, target="vm-other"),
        "nonce rebinding must conflict")
    p.witness.available = False
    expect(Denied, p.verify, "unavailable witness must fail closed")
    expect(Denied, lambda: p.publish("op-5"), "unavailable witness must block publication")


def scenario_wrong_acceptance_and_pending_successor() -> None:
    p = Protocol()
    response = p.issue(operation_id="op-6", nonce="n-6", request_digest="d-6",
        expected_version=1, target="vm-6")
    expect(Denied, lambda: p.accept("op-6", response, "wrong-vm", 6),
           "wrong target must be denied")
    expect(Denied, lambda: p.issue(operation_id="op-7", nonce="n-7",
        request_digest="d-7", expected_version=2, target="vm-7"),
        "second successor must be blocked while first is pending")
    p.publish("op-6")
    p.accept("op-6", response, "vm-6", 6)
    assert p.db.pending["accepted"]


def self_test() -> None:
    scenario_commit_and_lost_db_ack()
    print("PASS  pre-commit rollback and committed-but-unacknowledged database recovery")
    scenario_witness_lost_ack_and_recovery()
    print("PASS  witness advance with lost local acknowledgement reconciles exact checkpoint")
    scenario_restore_and_quarantine()
    print("PASS  stale database restore and witness-ahead unrecoverable state quarantine")
    scenario_acceptance_and_ack_loss()
    print("PASS  exact-instance acceptance and lost acceptance-checkpoint acknowledgement")
    scenario_replay_and_witness_fail_closed()
    print("PASS  idempotent exact-byte replay, digest conflict, nonce rebinding and witness outage")
    scenario_wrong_acceptance_and_pending_successor()
    print("PASS  wrong target rejection and single-pending-successor serialization")
    print("NOTE  deterministic in-memory fault model only; not PostgreSQL/provider/witness qualification")


if __name__ == "__main__":
    self_test()
