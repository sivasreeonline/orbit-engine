#!/usr/bin/env python3
"""Fail-closed replay and request-correlation model for FENCE-001 monitor gossip.

Cryptographic verification, trusted time, durable storage and transport are
pre-verified/external. This model exercises the receiver-side state machine.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import re

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_TTL_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 30
MAX_SEQUENCE_GAP = 64
REORDER_WINDOW = 64


class Outcome(str, Enum):
    ACCEPTED = "ACCEPTED"
    ACCEPTED_WITH_GAP = "ACCEPTED_WITH_GAP"
    DUPLICATE = "DUPLICATE"
    BLOCKED = "BLOCKED"
    QUARANTINE = "QUARANTINE"


@dataclass(frozen=True)
class Message:
    message_id: str
    sender_id: str
    recipient_id: str
    sequence: int
    canonical_digest: str
    message_type: str
    issued_at: int
    expires_at: int
    signature_status: str
    scope: str
    request_nonce: str | None = None
    response_request_id: str | None = None
    response_nonce: str | None = None


@dataclass(frozen=True)
class ReplayState:
    highest_sequence: int
    seen_by_sequence: dict[int, tuple[str, str]]
    seen_by_message_id: dict[str, tuple[int, str]]
    outstanding_requests: dict[str, tuple[str, int]]
    consumed_request_nonces: frozenset[str]
    missing_sequences: frozenset[int]


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str
    state: ReplayState


def empty_state() -> ReplayState:
    return ReplayState(0, {}, {}, {}, frozenset(), frozenset())


def reject(state: ReplayState, outcome: Outcome, reason: str) -> Decision:
    return Decision(outcome, reason, state)


def receive_message(
    state: ReplayState,
    message: Message,
    *,
    expected_sender: str,
    expected_recipient: str,
    expected_scope: str,
    now: int,
    protected_sequence_high_water: int,
) -> Decision:
    """Validate and atomically model acceptance of one authenticated envelope."""
    if state.highest_sequence < protected_sequence_high_water:
        return reject(state, Outcome.QUARANTINE, "replay store rolled back behind protected sequence high-water")
    if type(now) is not int or now < 0:
        return reject(state, Outcome.QUARANTINE, "trusted receiver time is malformed")
    for value in (message.message_id, message.sender_id, message.recipient_id, message.scope):
        if not isinstance(value, str) or not value.strip():
            return reject(state, Outcome.QUARANTINE, "message identity or scope is malformed")
    if message.sender_id != expected_sender or message.recipient_id != expected_recipient:
        return reject(state, Outcome.QUARANTINE, "message sender or recipient identity substitution detected")
    if message.sender_id == message.recipient_id:
        return reject(state, Outcome.QUARANTINE, "monitor gossip message cannot be self-addressed")
    if message.scope != expected_scope:
        return reject(state, Outcome.QUARANTINE, "message witness scope substitution detected")
    if type(message.sequence) is not int or message.sequence < 1:
        return reject(state, Outcome.QUARANTINE, "sender sequence is malformed")
    if not isinstance(message.canonical_digest, str) or DIGEST_RE.fullmatch(message.canonical_digest) is None:
        return reject(state, Outcome.QUARANTINE, "canonical message digest is malformed")
    if message.signature_status == "INVALID":
        return reject(state, Outcome.QUARANTINE, "message signature is invalid")
    if message.signature_status in ("UNKNOWN_KEY", "TRUST_UNAVAILABLE"):
        return reject(state, Outcome.BLOCKED, "sender signing key cannot currently be trusted")
    if message.signature_status != "VERIFIED":
        return reject(state, Outcome.QUARANTINE, "message signature verification state is invalid")

    prior_message = state.seen_by_message_id.get(message.message_id)
    if prior_message is not None:
        if prior_message == (message.sequence, message.canonical_digest):
            return reject(state, Outcome.DUPLICATE, "exact message replay is idempotent and causes no repeated side effect")
        return reject(state, Outcome.QUARANTINE, "message ID was reused with different sequence or canonical bytes")

    prior_sequence = state.seen_by_sequence.get(message.sequence)
    if prior_sequence is not None:
        if prior_sequence == (message.message_id, message.canonical_digest):
            return reject(state, Outcome.DUPLICATE, "exact sender sequence replay is idempotent")
        return reject(state, Outcome.QUARANTINE, "sender reused a sequence for different message content")

    if message.issued_at > now + MAX_CLOCK_SKEW_SECONDS:
        return reject(state, Outcome.QUARANTINE, "message issue time exceeds allowed trusted-clock skew")
    if message.expires_at <= now:
        return reject(state, Outcome.BLOCKED, "message has expired")
    if message.expires_at <= message.issued_at or message.expires_at - message.issued_at > MAX_TTL_SECONDS:
        return reject(state, Outcome.QUARANTINE, "message lifetime is invalid or exceeds five minutes")

    if message.sequence <= state.highest_sequence:
        if state.highest_sequence - message.sequence >= REORDER_WINDOW:
            return reject(state, Outcome.BLOCKED, "out-of-order message is older than the replay window")
    elif message.sequence - state.highest_sequence > MAX_SEQUENCE_GAP:
        return reject(state, Outcome.BLOCKED, "sender sequence gap exceeds the bounded resynchronization window")

    outstanding = dict(state.outstanding_requests)
    consumed = set(state.consumed_request_nonces)
    if message.message_type == "CONSISTENCY_PROOF_REQUEST":
        nonce = message.request_nonce
        if not isinstance(nonce, str) or not nonce.strip():
            return reject(state, Outcome.QUARANTINE, "consistency request nonce is missing")
        if nonce in consumed or any(value[0] == nonce for value in outstanding.values()):
            return reject(state, Outcome.QUARANTINE, "request nonce was reused")
        outstanding[message.message_id] = (nonce, message.expires_at)
    elif message.message_type == "CONSISTENCY_PROOF_RESPONSE":
        request_id = message.response_request_id
        nonce = message.response_nonce
        if not isinstance(request_id, str) or not isinstance(nonce, str):
            return reject(state, Outcome.QUARANTINE, "proof response lacks request correlation")
        expected = outstanding.get(request_id)
        if expected is None:
            return reject(state, Outcome.QUARANTINE, "proof response does not match an outstanding request")
        if expected[0] != nonce:
            return reject(state, Outcome.QUARANTINE, "proof response nonce does not match its request")
        if now >= expected[1]:
            return reject(state, Outcome.BLOCKED, "originating proof request has expired")
        del outstanding[request_id]
        consumed.add(nonce)
    elif message.message_type not in ("HEAD_ADVERTISEMENT", "EQUIVOCATION_ALERT"):
        return reject(state, Outcome.QUARANTINE, "unsupported monitor gossip message type")
    elif message.request_nonce is not None or message.response_request_id is not None or message.response_nonce is not None:
        return reject(state, Outcome.QUARANTINE, "non-request message carries request-correlation fields")

    seen_sequences = dict(state.seen_by_sequence)
    seen_messages = dict(state.seen_by_message_id)
    missing = set(state.missing_sequences)
    if message.sequence > state.highest_sequence + 1:
        missing.update(range(state.highest_sequence + 1, message.sequence))
    missing.discard(message.sequence)
    seen_sequences[message.sequence] = (message.message_id, message.canonical_digest)
    seen_messages[message.message_id] = (message.sequence, message.canonical_digest)
    highest = max(state.highest_sequence, message.sequence)

    next_state = ReplayState(
        highest,
        seen_sequences,
        seen_messages,
        outstanding,
        frozenset(consumed),
        frozenset(missing),
    )
    if missing:
        return Decision(Outcome.ACCEPTED_WITH_GAP, "message accepted; missing sender sequences remain visible for reconciliation", next_state)
    return Decision(Outcome.ACCEPTED, "message accepted and replay/request state advanced atomically", next_state)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def msg(
    message_id: str = "message-1",
    sequence: int = 1,
    digest: str = "1" * 64,
    **changes: object,
) -> Message:
    values = {
        "message_id": message_id,
        "sender_id": "monitor-a",
        "recipient_id": "monitor-b",
        "sequence": sequence,
        "canonical_digest": digest,
        "message_type": "HEAD_ADVERTISEMENT",
        "issued_at": 9_990,
        "expires_at": 10_100,
        "signature_status": "VERIFIED",
        "scope": "trust-domain-a|witness-a|authority-a|host-a",
        "request_nonce": None,
        "response_request_id": None,
        "response_nonce": None,
    }
    values.update(changes)
    return Message(**values)


def apply(
    state: ReplayState,
    message: Message,
    *,
    protected: int | None = None,
    now: int = 10_000,
) -> Decision:
    return receive_message(
        state,
        message,
        expected_sender="monitor-a",
        expected_recipient="monitor-b",
        expected_scope="trust-domain-a|witness-a|authority-a|host-a",
        now=now,
        protected_sequence_high_water=state.highest_sequence if protected is None else protected,
    )


def expect(name: str, decision: Decision, outcome: Outcome, reason: str | None = None) -> None:
    require(decision.outcome == outcome, f"{name}: expected {outcome}, got {decision.outcome}: {decision.reason}")
    if reason:
        require(reason in decision.reason, f"{name}: unexpected reason: {decision.reason}")


def main() -> None:
    initial = empty_state()
    first = msg()
    accepted = apply(initial, first)
    expect("first message", accepted, Outcome.ACCEPTED)
    expect("exact duplicate", apply(accepted.state, first), Outcome.DUPLICATE)
    expect(
        "message ID content substitution",
        apply(accepted.state, replace(first, canonical_digest="a" * 64)),
        Outcome.QUARANTINE,
        "message ID was reused",
    )
    expect(
        "sequence reuse",
        apply(accepted.state, msg("message-other", 1, "a" * 64)),
        Outcome.QUARANTINE,
        "reused a sequence",
    )
    expect(
        "unknown sender key",
        apply(initial, replace(first, signature_status="UNKNOWN_KEY")),
        Outcome.BLOCKED,
    )
    expect(
        "trust unavailable",
        apply(initial, replace(first, signature_status="TRUST_UNAVAILABLE")),
        Outcome.BLOCKED,
    )
    expect(
        "invalid signature",
        apply(initial, replace(first, signature_status="INVALID")),
        Outcome.QUARANTINE,
    )
    expect(
        "wrong recipient",
        apply(initial, replace(first, recipient_id="monitor-c")),
        Outcome.QUARANTINE,
    )
    expect(
        "wrong sender",
        apply(initial, replace(first, sender_id="monitor-c")),
        Outcome.QUARANTINE,
        "sender or recipient",
    )
    expect(
        "self-addressed message",
        apply(initial, replace(first, sender_id="monitor-b")),
        Outcome.QUARANTINE,
        "self-addressed",
    )
    expect(
        "wrong scope",
        apply(initial, replace(first, scope="other-scope")),
        Outcome.QUARANTINE,
    )
    expect(
        "expired message",
        apply(initial, replace(first, expires_at=9_999)),
        Outcome.BLOCKED,
    )
    expect(
        "excessive lifetime",
        apply(initial, replace(first, expires_at=10_400)),
        Outcome.QUARANTINE,
    )
    expect(
        "future issue time",
        apply(initial, replace(first, issued_at=10_100)),
        Outcome.QUARANTINE,
    )
    gap = apply(initial, msg("message-3", 3, "3" * 64))
    expect("sequence gap visible", gap, Outcome.ACCEPTED_WITH_GAP)
    require(gap.state.missing_sequences == frozenset({1, 2}), "sequence gap was not recorded")
    fill_one = apply(gap.state, msg("message-1", 1, "1" * 64))
    expect("out-of-order gap fill", fill_one, Outcome.ACCEPTED_WITH_GAP)
    require(fill_one.state.missing_sequences == frozenset({2}), "out-of-order gap fill corrupted missing sequence set")
    fill_two = apply(fill_one.state, msg("message-2", 2, "2" * 64))
    expect("gap fully reconciled", fill_two, Outcome.ACCEPTED)
    require(not fill_two.state.missing_sequences, "resolved sequence gap remains recorded")
    old_window_state = ReplayState(100, {}, {}, {}, frozenset(), frozenset())
    expect(
        "old replay outside window",
        apply(old_window_state, msg("old-message", 1, "a" * 64), protected=0),
        Outcome.BLOCKED,
        "older than the replay window",
    )
    expect(
        "oversized sequence jump",
        apply(initial, msg("jump", 100, "a" * 64)),
        Outcome.BLOCKED,
        "gap exceeds",
    )
    expect(
        "replay store rollback",
        apply(accepted.state, msg("new", 2, "2" * 64), protected=2),
        Outcome.QUARANTINE,
        "rolled back",
    )

    request = msg(
        "request-1", 1, "b" * 64,
        message_type="CONSISTENCY_PROOF_REQUEST",
        request_nonce="challenge-nonce-1",
    )
    request_accepted = apply(initial, request)
    expect("proof request accepted", request_accepted, Outcome.ACCEPTED)
    expect(
        "duplicate request is idempotent",
        apply(request_accepted.state, request),
        Outcome.DUPLICATE,
    )
    expect(
        "nonce reuse across request IDs",
        apply(
            request_accepted.state,
            msg("request-2", 2, "c" * 64, message_type="CONSISTENCY_PROOF_REQUEST", request_nonce="challenge-nonce-1"),
        ),
        Outcome.QUARANTINE,
        "nonce was reused",
    )
    response = msg(
        "response-1", 2, "d" * 64,
        message_type="CONSISTENCY_PROOF_RESPONSE",
        response_request_id="request-1",
        response_nonce="challenge-nonce-1",
    )
    response_accepted = apply(request_accepted.state, response)
    expect("matching proof response", response_accepted, Outcome.ACCEPTED)
    require("request-1" not in response_accepted.state.outstanding_requests, "completed request remained outstanding")
    require("challenge-nonce-1" in response_accepted.state.consumed_request_nonces, "response nonce was not consumed")
    expect(
        "response nonce substitution",
        apply(request_accepted.state, replace(response, response_nonce="wrong-nonce")),
        Outcome.QUARANTINE,
        "does not match",
    )
    expect(
        "unsolicited response",
        apply(initial, response),
        Outcome.QUARANTINE,
        "outstanding request",
    )
    expect(
        "expired originating request",
        apply(request_accepted.state, replace(response, expires_at=10_200), now=10_101),
        Outcome.BLOCKED,
        "request has expired",
    )
    expect(
        "duplicate proof response",
        apply(response_accepted.state, response),
        Outcome.DUPLICATE,
    )
    expect(
        "unsupported message type",
        apply(initial, replace(first, message_type="UNKNOWN")),
        Outcome.QUARANTINE,
        "unsupported",
    )

    print("FENCE-001 monitor gossip replay state machine: PASS")
    print("Scenarios: 27 deterministic replay, identity, sequence, expiry and request-correlation cases")
    print("Outcomes exercised: ACCEPTED, ACCEPTED_WITH_GAP, DUPLICATE, BLOCKED, QUARANTINE")
    print("Scope: receiver policy model only; cryptographic verification, durable storage and transport remain external")


if __name__ == "__main__":
    main()
