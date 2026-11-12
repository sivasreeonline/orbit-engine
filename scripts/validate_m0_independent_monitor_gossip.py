#!/usr/bin/env python3
"""Fail-closed reference model for independent FENCE-001 monitor gossip.

This is a deterministic policy model. Signature, trust, Merkle consistency,
clock, and provider-read verification are explicit pre-verified inputs. It
does not implement a network gossip service or authorize execution.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import re
from typing import Sequence

PROFILE = "sky-high-fence-witness-merkle-v1"
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class Outcome(str, Enum):
    AGREED = "AGREED"
    CATCH_UP_REQUIRED = "CATCH_UP_REQUIRED"
    BLOCKED = "BLOCKED"
    QUARANTINE = "QUARANTINE"


@dataclass(frozen=True)
class Scope:
    trust_domain: str
    witness_id: str
    authority_id: str
    host_id: str


@dataclass(frozen=True)
class SignedHead:
    profile: str
    scope: Scope
    generation: int
    digest: str
    previous_digest: str
    key_id: str
    signature_status: str
    proof_from_previous_status: str


@dataclass(frozen=True)
class Monitor:
    monitor_id: str
    operator: str
    account: str
    failure_domain: str
    head: SignedHead
    protected_generation: int
    protected_digest: str
    last_successful_poll: int


@dataclass(frozen=True)
class GossipDecision:
    outcome: Outcome
    reason: str
    catch_up_generation: int | None = None
    catch_up_digest: str | None = None


def valid_digest(value: str) -> bool:
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def validate_head(head: SignedHead) -> GossipDecision | None:
    if head.profile != PROFILE:
        return GossipDecision(Outcome.QUARANTINE, "unexpected witness proof profile")
    for value in (
        head.scope.trust_domain,
        head.scope.witness_id,
        head.scope.authority_id,
        head.scope.host_id,
        head.key_id,
    ):
        if not isinstance(value, str) or not value.strip():
            return GossipDecision(Outcome.QUARANTINE, "signed-head scope or key identity is malformed")
    if type(head.generation) is not int or head.generation < 1:
        return GossipDecision(Outcome.QUARANTINE, "signed-head generation is malformed")
    if not valid_digest(head.digest) or not valid_digest(head.previous_digest):
        return GossipDecision(Outcome.QUARANTINE, "signed-head digest or predecessor is malformed")
    if head.signature_status == "INVALID":
        return GossipDecision(Outcome.QUARANTINE, "signed-head signature is invalid")
    if head.signature_status in ("UNKNOWN_KEY", "TRUST_UNAVAILABLE"):
        return GossipDecision(Outcome.BLOCKED, "signed-head signing key cannot currently be trusted")
    if head.signature_status != "VERIFIED":
        return GossipDecision(Outcome.QUARANTINE, "signed-head signature verification state is invalid")
    if head.generation == 1 and head.previous_digest != "0" * 64:
        return GossipDecision(Outcome.QUARANTINE, "genesis head does not use the defined zero predecessor")
    if head.generation > 1 and head.proof_from_previous_status == "INVALID":
        return GossipDecision(Outcome.QUARANTINE, "signed-head predecessor consistency proof is invalid")
    if head.generation > 1 and head.proof_from_previous_status not in ("VERIFIED", "MISSING"):
        return GossipDecision(Outcome.QUARANTINE, "signed-head predecessor proof state is invalid")
    return None


def validate_monitor(
    monitor: Monitor,
    *,
    now: int,
    max_poll_age: int,
) -> GossipDecision | None:
    for value in (monitor.monitor_id, monitor.operator, monitor.account, monitor.failure_domain):
        if not isinstance(value, str) or not value.strip():
            return GossipDecision(Outcome.QUARANTINE, "monitor identity metadata is malformed")
    if type(monitor.last_successful_poll) is not int or monitor.last_successful_poll < 0:
        return GossipDecision(Outcome.QUARANTINE, "monitor poll timestamp is malformed")
    if monitor.last_successful_poll > now:
        return GossipDecision(Outcome.QUARANTINE, "monitor poll timestamp is in the future")
    if now - monitor.last_successful_poll > max_poll_age:
        return GossipDecision(Outcome.BLOCKED, "independent monitor observation is stale")
    if type(monitor.protected_generation) is not int or monitor.protected_generation < 0:
        return GossipDecision(Outcome.QUARANTINE, "monitor protected high-water generation is malformed")
    if not valid_digest(monitor.protected_digest):
        return GossipDecision(Outcome.QUARANTINE, "monitor protected high-water digest is malformed")

    head_decision = validate_head(monitor.head)
    if head_decision is not None:
        return head_decision
    if monitor.head.generation < monitor.protected_generation:
        return GossipDecision(Outcome.QUARANTINE, "monitor head regressed behind its durable protected high-water")
    if monitor.head.generation == monitor.protected_generation:
        if monitor.head.digest != monitor.protected_digest:
            return GossipDecision(Outcome.QUARANTINE, "monitor head conflicts with its durable protected high-water")
    else:
        if monitor.head.proof_from_previous_status == "MISSING":
            return GossipDecision(Outcome.BLOCKED, "monitor cannot prove extension from its durable protected high-water")
        if monitor.head.proof_from_previous_status != "VERIFIED":
            return GossipDecision(Outcome.QUARANTINE, "monitor high-water extension proof is invalid")
        if monitor.head.generation == monitor.protected_generation + 1:
            if monitor.head.previous_digest != monitor.protected_digest:
                return GossipDecision(Outcome.QUARANTINE, "monitor successor does not name its exact protected predecessor")
    return None


def compare_monitor_views(
    monitors: Sequence[Monitor],
    *,
    now: int,
    max_poll_age: int,
    cross_monitor_consistency_status: str,
) -> GossipDecision:
    """Compare two independently persisted, authenticated monitor views.

    A CATCH_UP_REQUIRED result is deliberately not an authorization result:
    the lagging monitor must verify and persist the newer head, then gossip
    again before the pair can return AGREED.
    """
    if type(now) is not int or now < 0 or type(max_poll_age) is not int or max_poll_age <= 0:
        return GossipDecision(Outcome.QUARANTINE, "gossip evaluation time or freshness policy is malformed")
    if len(monitors) < 2:
        return GossipDecision(Outcome.BLOCKED, "fewer than two monitor observations are available")

    identity_dimensions = (
        [item.monitor_id for item in monitors],
        [item.operator for item in monitors],
        [item.account for item in monitors],
        [item.failure_domain for item in monitors],
    )
    if any(len(set(values)) != len(values) for values in identity_dimensions):
        return GossipDecision(Outcome.BLOCKED, "monitor identities, operators, accounts and failure domains are not independent")

    for monitor in monitors:
        decision = validate_monitor(monitor, now=now, max_poll_age=max_poll_age)
        if decision is not None:
            return decision

    reference_scope = monitors[0].head.scope
    if any(item.head.scope != reference_scope for item in monitors[1:]):
        return GossipDecision(Outcome.QUARANTINE, "monitors returned heads for different witness scopes")

    # Compare every pair. This catches a split view even when more than two
    # independently operated monitors are configured.
    catch_up: tuple[int, str] | None = None
    for index, left in enumerate(monitors):
        for right in monitors[index + 1:]:
            a = left.head
            b = right.head
            if a.generation == b.generation:
                if a.digest != b.digest or a.previous_digest != b.previous_digest:
                    return GossipDecision(Outcome.QUARANTINE, "validly signed monitors observed conflicting heads at the same generation")
                continue

            older, newer = (a, b) if a.generation < b.generation else (b, a)
            if cross_monitor_consistency_status == "MISSING":
                return GossipDecision(Outcome.BLOCKED, "cross-monitor consistency proof is unavailable")
            if cross_monitor_consistency_status != "VERIFIED":
                return GossipDecision(Outcome.QUARANTINE, "cross-monitor consistency proof is invalid")
            if newer.generation == older.generation + 1 and newer.previous_digest != older.digest:
                return GossipDecision(Outcome.QUARANTINE, "newer monitor head does not link to the older monitor head")
            candidate = (newer.generation, newer.digest)
            if catch_up is not None and catch_up != candidate:
                return GossipDecision(Outcome.QUARANTINE, "monitor set does not converge on one highest signed head")
            catch_up = candidate

    if catch_up is not None:
        return GossipDecision(
            Outcome.CATCH_UP_REQUIRED,
            "newer signed head is a verified extension; lagging monitor must persist it and repeat gossip",
            catch_up_generation=catch_up[0],
            catch_up_digest=catch_up[1],
        )
    return GossipDecision(Outcome.AGREED, "all fresh independent monitors agree on the same authenticated witness head")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def scope() -> Scope:
    return Scope("trust-domain-a", "witness-a", "authority-a", "host-a")


def head(
    generation: int = 6,
    digest: str = "6" * 64,
    previous_digest: str = "5" * 64,
    **changes: object,
) -> SignedHead:
    values = {
        "profile": PROFILE,
        "scope": scope(),
        "generation": generation,
        "digest": digest,
        "previous_digest": previous_digest,
        "key_id": "witness-key-1",
        "signature_status": "VERIFIED",
        "proof_from_previous_status": "VERIFIED",
    }
    values.update(changes)
    return SignedHead(**values)


def monitor(
    monitor_id: str,
    generation: int = 6,
    digest: str = "6" * 64,
    previous_digest: str = "5" * 64,
    **changes: object,
) -> Monitor:
    values = {
        "monitor_id": monitor_id,
        "operator": f"operator-{monitor_id}",
        "account": f"account-{monitor_id}",
        "failure_domain": f"failure-domain-{monitor_id}",
        "head": head(generation, digest, previous_digest),
        "protected_generation": generation,
        "protected_digest": digest,
        "last_successful_poll": 9_990,
    }
    values.update(changes)
    return Monitor(**values)


def baseline() -> list[Monitor]:
    return [monitor("monitor-a"), monitor("monitor-b")]


def expect(
    name: str,
    monitors: Sequence[Monitor],
    expected: Outcome,
    *,
    proof: str = "NOT_REQUIRED",
    reason: str | None = None,
    catch_up_generation: int | None = None,
) -> None:
    result = compare_monitor_views(
        monitors, now=10_000, max_poll_age=60,
        cross_monitor_consistency_status=proof,
    )
    require(result.outcome == expected, f"{name}: expected {expected}, got {result}")
    if reason is not None:
        require(reason in result.reason, f"{name}: unexpected reason {result.reason}")
    if catch_up_generation is not None:
        require(result.catch_up_generation == catch_up_generation, f"{name}: wrong catch-up generation")


def main() -> None:
    base = baseline()
    expect("matching independent monitors", base, Outcome.AGREED)
    expect("single monitor", base[:1], Outcome.BLOCKED)
    expect(
        "same-generation validly signed fork",
        [base[0], replace(base[1], head=head(6, "a" * 64))],
        Outcome.QUARANTINE,
        reason="conflicting heads",
    )
    expect(
        "same digest but predecessor disagreement",
        [base[0], replace(base[1], head=head(6, "6" * 64, "a" * 64))],
        Outcome.QUARANTINE,
        reason="conflicting heads",
    )
    expect(
        "different witness scope",
        [base[0], replace(base[1], head=replace(base[1].head, scope=Scope("other", "witness-a", "authority-a", "host-a")))],
        Outcome.QUARANTINE,
        reason="different witness scopes",
    )
    expect(
        "unknown signing key",
        [replace(base[0], head=replace(base[0].head, signature_status="UNKNOWN_KEY")), base[1]],
        Outcome.BLOCKED,
    )
    expect(
        "trust service unavailable",
        [replace(base[0], head=replace(base[0].head, signature_status="TRUST_UNAVAILABLE")), base[1]],
        Outcome.BLOCKED,
    )
    expect(
        "invalid signature",
        [replace(base[0], head=replace(base[0].head, signature_status="INVALID")), base[1]],
        Outcome.QUARANTINE,
    )
    expect(
        "wrong profile",
        [replace(base[0], head=replace(base[0].head, profile="other-profile")), base[1]],
        Outcome.QUARANTINE,
    )
    expect(
        "malformed digest",
        [replace(base[0], head=replace(base[0].head, digest="not-a-digest")), base[1]],
        Outcome.QUARANTINE,
    )
    expect(
        "generation zero",
        [replace(base[0], head=replace(base[0].head, generation=0)), base[1]],
        Outcome.QUARANTINE,
    )
    expect(
        "monitor rollback",
        [replace(base[0], head=head(5, "5" * 64), protected_generation=6, protected_digest="6" * 64), base[1]],
        Outcome.QUARANTINE,
        reason="regressed",
    )
    expect(
        "same-generation protected fork",
        [replace(base[0], protected_digest="a" * 64), base[1]],
        Outcome.QUARANTINE,
        reason="conflicts with its durable",
    )
    expect(
        "missing local extension proof",
        [replace(base[0], head=replace(base[0].head, generation=7, digest="7" * 64, proof_from_previous_status="MISSING")), base[1]],
        Outcome.BLOCKED,
        reason="cannot prove extension",
    )
    expect(
        "invalid local extension proof",
        [replace(base[0], head=replace(base[0].head, generation=7, digest="7" * 64, proof_from_previous_status="INVALID")), base[1]],
        Outcome.QUARANTINE,
    )
    expect(
        "stale monitor poll",
        [replace(base[0], last_successful_poll=9_000), base[1]],
        Outcome.BLOCKED,
        reason="stale",
    )
    expect(
        "future poll timestamp",
        [replace(base[0], last_successful_poll=10_001), base[1]],
        Outcome.QUARANTINE,
        reason="future",
    )
    expect(
        "duplicate monitor identity",
        [base[0], replace(base[1], monitor_id=base[0].monitor_id)],
        Outcome.BLOCKED,
    )
    expect(
        "shared operator",
        [base[0], replace(base[1], operator=base[0].operator)],
        Outcome.BLOCKED,
    )
    expect(
        "shared account",
        [base[0], replace(base[1], account=base[0].account)],
        Outcome.BLOCKED,
    )
    expect(
        "shared failure domain",
        [base[0], replace(base[1], failure_domain=base[0].failure_domain)],
        Outcome.BLOCKED,
    )
    newer = monitor("monitor-b", 7, "7" * 64, "6" * 64, protected_generation=6, protected_digest="6" * 64)
    expect(
        "cross-monitor missing proof",
        [base[0], newer],
        Outcome.BLOCKED,
        proof="MISSING",
    )
    expect(
        "cross-monitor invalid proof",
        [base[0], newer],
        Outcome.QUARANTINE,
        proof="INVALID",
    )
    expect(
        "cross-monitor verified extension",
        [base[0], newer],
        Outcome.CATCH_UP_REQUIRED,
        proof="VERIFIED",
        catch_up_generation=7,
    )
    expect(
        "extension predecessor fork",
        [base[0], replace(newer, head=head(7, "7" * 64, "a" * 64))],
        Outcome.QUARANTINE,
        proof="VERIFIED",
        reason="does not link",
    )
    expect(
        "three-way inconsistent highest heads",
        [base[0], newer, monitor("monitor-c", 7, "a" * 64, "6" * 64, protected_generation=6, protected_digest="6" * 64)],
        Outcome.QUARANTINE,
        proof="VERIFIED",
    )
    caught_up = monitor("monitor-a", 7, "7" * 64, "6" * 64, protected_generation=7, protected_digest="7" * 64)
    expect(
        "catch-up completed and gossiped",
        [caught_up, newer],
        Outcome.AGREED,
    )
    expect(
        "stale replay below durable high-water",
        [replace(base[0], head=head(5, "5" * 64), protected_generation=6, protected_digest="6" * 64), base[1]],
        Outcome.QUARANTINE,
    )
    expect(
        "invalid predecessor proof",
        [replace(base[0], head=replace(base[0].head, proof_from_previous_status="INVALID")), base[1]],
        Outcome.QUARANTINE,
    )

    print("FENCE-001 independent monitor gossip reference model: PASS")
    print("Scenarios: 27 deterministic fail-closed, split-view, freshness and catch-up cases")
    print("Outcomes exercised: AGREED, CATCH_UP_REQUIRED, BLOCKED, QUARANTINE")
    print("Scope: policy model only; no network gossip, signature verifier, provider adapter or production authorization")


if __name__ == "__main__":
    main()
