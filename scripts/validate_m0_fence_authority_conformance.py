#!/usr/bin/env python3
"""Synthetic reference state machine for external FENCE-001 epoch authority.

This is a deterministic contract model only. It does not call a provider,
authenticate evidence, implement a database, or qualify an authority.
"""
from __future__ import annotations

import copy
import hashlib
import json


class Conflict(Exception):
    pass


class Denied(Exception):
    pass


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


class Authority:
    """Single-host synthetic authority with an independently retained anchor."""

    def __init__(self, host_id: str, epoch: int, instance_id: str):
        self.host_id = host_id
        self.epoch = epoch
        self.instance_id = instance_id
        self.version = 1
        self.pending: dict | None = None
        self.nonces: dict[str, tuple[str, bytes]] = {}
        self.operations: dict[str, tuple[str, bytes]] = {}
        # Test-only external checkpoint; deliberately excluded from snapshots.
        self.anchor = (self.epoch, self.version, self._state_digest())

    def _state_digest(self) -> str:
        material = {
            "host_id": self.host_id,
            "epoch": self.epoch,
            "instance_id": self.instance_id,
            "version": self.version,
            "pending_response_sha256": (
                sha256(self.pending["bytes"]) if self.pending else None
            ),
        }
        return sha256(canonical_bytes(material))

    def _advance_anchor(self) -> None:
        self.anchor = (self.epoch, self.version, self._state_digest())

    def snapshot(self) -> dict:
        return copy.deepcopy({
            "host_id": self.host_id,
            "epoch": self.epoch,
            "instance_id": self.instance_id,
            "version": self.version,
            "pending": self.pending,
            "nonces": self.nonces,
            "operations": self.operations,
        })

    def restore(self, snapshot: dict) -> None:
        # Model a database/authority restore while an external anchor survives.
        restored = copy.deepcopy(snapshot)
        self.host_id = restored["host_id"]
        self.epoch = restored["epoch"]
        self.instance_id = restored["instance_id"]
        self.version = restored["version"]
        self.pending = restored["pending"]
        self.nonces = restored["nonces"]
        self.operations = restored["operations"]

    def verify_anchor(self) -> None:
        current = (self.epoch, self.version, self._state_digest())
        if current != self.anchor:
            raise Denied("authority state is stale or differs from external anti-rollback anchor")

    def issue(
        self,
        *,
        operation_id: str,
        nonce_digest: str,
        request_digest: str,
        expected_version: int,
        target_instance_id: str,
        predecessor_max_epoch: int,
        fence_bundle_digest: str,
        synthetic_fence_confirmed: bool,
        lose_acknowledgement: bool = False,
    ) -> dict:
        require_digest(nonce_digest, "nonce_digest")
        require_digest(request_digest, "request_digest")
        require_digest(fence_bundle_digest, "fence_bundle_digest")
        self.verify_anchor()

        # Resolve retries before CAS/pending checks: retries return the exact
        # committed bytes and can never allocate a second epoch.
        prior_nonce = self.nonces.get(nonce_digest)
        if prior_nonce:
            if prior_nonce[0] != request_digest:
                raise Conflict("nonce reused with a different request digest")
            return {"result": "ACK_LOST" if lose_acknowledgement else "IDEMPOTENT_REPLAY",
                    "response_bytes": prior_nonce[1]}

        prior_operation = self.operations.get(operation_id)
        if prior_operation:
            if prior_operation[0] != request_digest:
                raise Conflict("operation ID reused with a different request digest")
            raise Conflict("operation ID exists but nonce binding differs")

        if expected_version != self.version:
            raise Conflict("compare-and-swap record version mismatch")
        if self.pending is not None:
            raise Denied("a successor is already issued and not durably accepted")
        if not synthetic_fence_confirmed:
            raise Denied("predecessor fence is not confirmed")
        if predecessor_max_epoch != self.epoch:
            raise Denied("predecessor set does not include the current authority epoch")
        if target_instance_id == self.instance_id:
            raise Denied("successor instance must differ from current instance")

        response = {
            "host_id": self.host_id,
            "operation_id": operation_id,
            "nonce_digest": nonce_digest,
            "request_digest": request_digest,
            "provider_instance_id": target_instance_id,
            "incarnation_epoch": self.epoch + 1,
            "predecessor_max_epoch": predecessor_max_epoch,
            "fence_bundle_sha256": fence_bundle_digest,
            "authority_record_version": self.version + 1,
        }
        response_bytes = canonical_bytes(response)
        self.epoch += 1
        self.instance_id = target_instance_id
        self.version += 1
        self.pending = {
            "response": response,
            "bytes": response_bytes,
            "sha256": sha256(response_bytes),
            "accepted": False,
        }
        self.nonces[nonce_digest] = (request_digest, response_bytes)
        self.operations[operation_id] = (request_digest, response_bytes)
        self._advance_anchor()
        return {"result": "ACK_LOST" if lose_acknowledgement else "ISSUED",
                "response_bytes": response_bytes}

    def accept(self, response_bytes: bytes, instance_id: str, epoch: int) -> str:
        self.verify_anchor()
        if self.pending is None:
            raise Denied("no issued response is awaiting acceptance")
        if self.pending["accepted"]:
            if response_bytes == self.pending["bytes"]:
                return "ALREADY_ACCEPTED"
            raise Conflict("accepted response identity cannot be changed")
        if response_bytes != self.pending["bytes"]:
            raise Denied("acceptance must persist the exact authority response bytes")
        if instance_id != self.instance_id or epoch != self.epoch:
            raise Denied("acceptance target instance/epoch mismatch")
        self.pending["accepted"] = True
        self.version += 1
        self._advance_anchor()
        return "ACCEPTED"


def expect(error, action, label: str) -> None:
    try:
        action()
    except error:
        return
    raise AssertionError(label)


def request(authority: Authority, *, operation: str, nonce: str, request: str,
            expected_version: int, target: str, predecessor_epoch: int,
            fence: str, confirmed: bool = True, lost_ack: bool = False) -> dict:
    return authority.issue(
        operation_id=operation, nonce_digest=nonce * 64, request_digest=request * 64,
        expected_version=expected_version, target_instance_id=target,
        predecessor_max_epoch=predecessor_epoch, fence_bundle_digest=fence * 64,
        synthetic_fence_confirmed=confirmed, lose_acknowledgement=lost_ack,
    )


def self_test() -> None:
    authority = Authority("host-01", 5, "vm-previous")
    old_snapshot = authority.snapshot()

    first = request(authority, operation="op-1", nonce="a", request="b",
                    expected_version=1, target="vm-next", predecessor_epoch=5,
                    fence="c", lost_ack=True)
    assert first["result"] == "ACK_LOST"
    assert authority.epoch == 6 and authority.version == 2

    retry = request(authority, operation="op-1", nonce="a", request="b",
                    expected_version=1, target="vm-next", predecessor_epoch=5,
                    fence="c")
    assert retry["result"] == "IDEMPOTENT_REPLAY"
    assert retry["response_bytes"] == first["response_bytes"]
    expect(Conflict, lambda: request(authority, operation="op-1", nonce="a", request="d",
                                     expected_version=2, target="vm-other",
                                     predecessor_epoch=6, fence="e"),
           "same nonce with changed request must conflict")
    expect(Conflict, lambda: request(authority, operation="op-1", nonce="f", request="7",
                                     expected_version=2, target="vm-other",
                                     predecessor_epoch=6, fence="e"),
           "same operation ID with changed request must conflict")
    expect(Denied, lambda: request(authority, operation="op-2", nonce="8", request="9",
                                   expected_version=2, target="vm-race",
                                   predecessor_epoch=6, fence="a"),
           "second concurrent successor must not issue while first is pending")
    expect(Denied, lambda: request(authority, operation="op-no-fence", nonce="b",
                                   request="c", expected_version=2, target="vm-no-fence",
                                   predecessor_epoch=6, fence="d", confirmed=False),
           "unconfirmed fence must deny issuance")

    response = first["response_bytes"]
    expect(Denied, lambda: authority.accept(response + b" ", "vm-next", 6),
           "altered response bytes must not be accepted")
    expect(Denied, lambda: authority.accept(response, "vm-other", 6),
           "wrong successor instance must not be accepted")
    assert authority.accept(response, "vm-next", 6) == "ACCEPTED"
    assert authority.accept(response, "vm-next", 6) == "ALREADY_ACCEPTED"

    expect(Conflict, lambda: request(authority, operation="op-stale", nonce="e",
                                     request="f", expected_version=2, target="vm-next-2",
                                     predecessor_epoch=6, fence="1"),
           "stale CAS version must conflict after acceptance")
    second = request(authority, operation="op-2", nonce="2", request="3",
                     expected_version=3, target="vm-next-2", predecessor_epoch=6,
                     fence="4")
    assert json.loads(second["response_bytes"])["incarnation_epoch"] == 7

    # Restore an old authority snapshot without rolling back the independent
    # anchor. The authority must refuse all subsequent issuance.
    authority.restore(old_snapshot)
    expect(Denied, authority.verify_anchor,
           "restored stale authority snapshot must fail external anchor check")
    expect(Denied, lambda: request(authority, operation="op-rollback", nonce="5",
                                   request="6", expected_version=1, target="vm-rollback",
                                   predecessor_epoch=5, fence="7"),
           "stale authority snapshot must not issue a successor")

    print("PASS  monotonic epoch issuance and compare-and-swap version fencing")
    print("PASS  lost-ack retry returns exact prior response bytes without a second epoch")
    print("PASS  nonce/request and operation-ID collision/replay rejection")
    print("PASS  pending successor serialization and predecessor-fence precondition")
    print("PASS  exact response/instance/epoch acceptance and idempotent acceptance")
    print("PASS  stale authority snapshot rejected by independent anti-rollback anchor")
    print("NOTE  synthetic in-memory model only; no provider, database, signature or host proof")


if __name__ == "__main__":
    self_test()
