#!/usr/bin/env python3
"""Fail-closed reference model for FENCE-001 witness restore reconciliation.

This is a deterministic state-machine model. It does not contact a provider,
verify cryptographic proofs, restore a database, or authorize execution.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import re
from typing import Sequence

ZERO_DIGEST = "0" * 64
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class Outcome(str, Enum):
    RECONCILED = "RECONCILED"
    RECOVERED = "RECOVERED"
    BLOCKED = "BLOCKED"
    QUARANTINE = "QUARANTINE"


@dataclass(frozen=True)
class HighWater:
    generation: int
    digest: str


@dataclass(frozen=True)
class Checkpoint:
    generation: int
    digest: str
    previous_digest: str


@dataclass(frozen=True)
class MonitorHead:
    monitor_id: str
    operator: str
    account: str
    failure_domain: str
    generation: int
    digest: str


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str


def valid_digest(value: str) -> bool:
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def decide_reconciliation(
    *,
    local: HighWater,
    protected: HighWater,
    witness: HighWater | None,
    witness_chain: Sequence[Checkpoint],
    monitors: Sequence[MonitorHead],
    latest_read_status: str,
    consistency_proof_status: str,
    local_consistency_proof_status: str,
    checkpoint_chain_verified: bool,
    local_state_replayable: bool,
    trust_generation: int,
    protected_trust_generation: int,
    trust_chain_verified: bool,
    revocation_generation: int,
    protected_revocation_generation: int,
    revocation_state_available: bool,
) -> Decision:
    """Decide whether a restored authority may reconcile with witness high-water.

    Status values are pre-verified inputs from external layers. This model does
    not implement the provider read, signature, trust-bundle or proof verifier.
    """
    if witness is None:
        return Decision(Outcome.BLOCKED, "external witness high-water is unavailable")
    if latest_read_status == "UNAVAILABLE":
        return Decision(Outcome.BLOCKED, "strongly consistent latest read is unavailable")
    if latest_read_status != "VERIFIED":
        return Decision(Outcome.QUARANTINE, "latest read is stale or not proven linearizable")

    for label, state in (("local", local), ("protected", protected), ("witness", witness)):
        if type(state.generation) is not int or state.generation < 0 or not valid_digest(state.digest):
            return Decision(Outcome.QUARANTINE, f"{label} high-water record is malformed")

    if witness.generation < protected.generation:
        return Decision(Outcome.QUARANTINE, "witness is behind protected verifier high-water")
    if witness.generation == protected.generation and witness.digest != protected.digest:
        return Decision(Outcome.QUARANTINE, "witness conflicts with protected verifier digest")
    if witness.generation > protected.generation:
        if consistency_proof_status == "MISSING":
            return Decision(Outcome.BLOCKED, "consistency proof from protected high-water is missing")
        if consistency_proof_status != "VERIFIED":
            return Decision(Outcome.QUARANTINE, "consistency proof is invalid")
    elif consistency_proof_status not in ("VERIFIED", "NOT_REQUIRED"):
        return Decision(Outcome.QUARANTINE, "unexpected consistency-proof state for equal high-water")

    if trust_generation < protected_trust_generation:
        return Decision(Outcome.QUARANTINE, "trust-bundle generation rollback detected")
    if trust_generation > protected_trust_generation and not trust_chain_verified:
        return Decision(Outcome.QUARANTINE, "trust-bundle successor chain is not verified")
    if not revocation_state_available:
        return Decision(Outcome.BLOCKED, "fresh revocation state is unavailable")
    if revocation_generation < protected_revocation_generation:
        return Decision(Outcome.QUARANTINE, "revocation generation rollback detected")

    if len(monitors) < 2:
        return Decision(Outcome.BLOCKED, "fewer than two independent monitor observations")
    dimensions = (
        [item.monitor_id for item in monitors],
        [item.operator for item in monitors],
        [item.account for item in monitors],
        [item.failure_domain for item in monitors],
    )
    if any(len(set(values)) != len(values) for values in dimensions):
        return Decision(Outcome.BLOCKED, "monitor identities, operators, accounts and failure domains must be distinct")
    for item in monitors:
        if not valid_digest(item.digest) or type(item.generation) is not int or item.generation < 0:
            return Decision(Outcome.QUARANTINE, "monitor supplied a malformed signed-head summary")
    for index, left in enumerate(monitors):
        for right in monitors[index + 1:]:
            if left.generation == right.generation and left.digest != right.digest:
                return Decision(Outcome.QUARANTINE, "monitors observed conflicting heads at the same generation")
    for item in monitors:
        if item.generation > witness.generation:
            return Decision(Outcome.QUARANTINE, "monitor has observed a head newer than the claimed latest witness head")
        if item.generation < witness.generation:
            return Decision(Outcome.BLOCKED, "one or more independent monitors have not caught up to witness high-water")
        if item.digest != witness.digest:
            return Decision(Outcome.QUARANTINE, "monitor head conflicts with witness high-water")

    if local.generation > witness.generation:
        return Decision(Outcome.QUARANTINE, "restored authority claims a generation ahead of witness")
    if local.generation == protected.generation and local.digest != protected.digest:
        return Decision(Outcome.QUARANTINE, "authority conflicts with protected verifier digest")
    if local.generation > protected.generation and local.generation < witness.generation:
        if local_consistency_proof_status == "MISSING":
            return Decision(Outcome.BLOCKED, "consistency proof from protected high-water to restored authority is missing")
        if local_consistency_proof_status != "VERIFIED":
            return Decision(Outcome.QUARANTINE, "restored authority is not proven to descend from protected high-water")
    if local.generation == witness.generation:
        if local.digest != witness.digest:
            return Decision(Outcome.QUARANTINE, "authority and witness disagree at the same generation")
        if witness_chain:
            return Decision(Outcome.QUARANTINE, "unexpected recovery chain when authority already matches witness")
        return Decision(Outcome.RECONCILED, "authority, protected high-water, witness and independent monitors agree")

    # The witness is ahead of the restored database. Recovery is allowed only
    # when every missing checkpoint is present and independently verified.
    expected_generation = local.generation + 1
    expected_predecessor = local.digest
    if len(witness_chain) != witness.generation - local.generation:
        return Decision(Outcome.QUARANTINE, "recovery chain is incomplete or contains extra checkpoints")
    for checkpoint in witness_chain:
        if (
            type(checkpoint.generation) is not int
            or checkpoint.generation != expected_generation
            or not valid_digest(checkpoint.digest)
            or not valid_digest(checkpoint.previous_digest)
            or checkpoint.previous_digest != expected_predecessor
        ):
            return Decision(Outcome.QUARANTINE, "recovery checkpoint chain has a gap, malformed digest or predecessor fork")
        expected_generation += 1
        expected_predecessor = checkpoint.digest
    if expected_generation - 1 != witness.generation or expected_predecessor != witness.digest:
        return Decision(Outcome.QUARANTINE, "recovery chain does not terminate at witness high-water")
    if local.generation < protected.generation:
        protected_checkpoint = next(
            (item for item in witness_chain if item.generation == protected.generation),
            None,
        )
        if protected_checkpoint is None or protected_checkpoint.digest != protected.digest:
            return Decision(Outcome.QUARANTINE, "recovery chain does not intersect the protected verifier high-water")
    if not checkpoint_chain_verified:
        return Decision(Outcome.QUARANTINE, "recovery checkpoint artifacts or signatures are not verified")
    if not local_state_replayable:
        return Decision(Outcome.QUARANTINE, "authority state cannot be deterministically replayed from verified artifacts")
    return Decision(Outcome.RECOVERED, "complete verified witness chain can rebuild restored authority state; admission remains disabled until commit and re-readback")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def base_case() -> dict:
    local = HighWater(5, "5" * 64)
    protected = HighWater(6, "6" * 64)
    witness = HighWater(6, "6" * 64)
    monitors = [
        MonitorHead("monitor-a", "operator-a", "account-a", "region-a", 6, "6" * 64),
        MonitorHead("monitor-b", "operator-b", "account-b", "region-b", 6, "6" * 64),
    ]
    return {
        "local": local,
        "protected": protected,
        "witness": witness,
        "witness_chain": [Checkpoint(6, "6" * 64, "5" * 64)],
        "monitors": monitors,
        "latest_read_status": "VERIFIED",
        "consistency_proof_status": "NOT_REQUIRED",
        "local_consistency_proof_status": "NOT_REQUIRED",
        "checkpoint_chain_verified": True,
        "local_state_replayable": True,
        "trust_generation": 4,
        "protected_trust_generation": 4,
        "trust_chain_verified": True,
        "revocation_generation": 8,
        "protected_revocation_generation": 8,
        "revocation_state_available": True,
    }


def expect(case: str, changes: dict, expected: Outcome, reason_fragment: str | None = None) -> None:
    values = base_case()
    values.update(changes)
    decision = decide_reconciliation(**values)
    require(decision.outcome == expected, f"{case}: expected {expected}, got {decision}")
    if reason_fragment:
        require(reason_fragment in decision.reason, f"{case}: unexpected reason {decision.reason}")


def main() -> None:
    expect("verified witness-ahead recovery", {}, Outcome.RECOVERED)
    expect(
        "already reconciled",
        {
            "local": HighWater(6, "6" * 64),
            "witness_chain": [],
        },
        Outcome.RECONCILED,
    )
    expect("missing witness", {"witness": None}, Outcome.BLOCKED)
    expect("latest read unavailable", {"latest_read_status": "UNAVAILABLE"}, Outcome.BLOCKED)
    expect("latest read stale", {"latest_read_status": "STALE"}, Outcome.QUARANTINE)
    expect("missing consistency proof", {"consistency_proof_status": "MISSING"}, Outcome.BLOCKED)
    expect("invalid consistency proof", {"consistency_proof_status": "INVALID"}, Outcome.QUARANTINE)
    expect(
        "witness advanced beyond protected high-water",
        {
            "witness": HighWater(7, "7" * 64),
            "witness_chain": [
                Checkpoint(6, "6" * 64, "5" * 64),
                Checkpoint(7, "7" * 64, "6" * 64),
            ],
            "monitors": [
                MonitorHead("monitor-a", "operator-a", "account-a", "region-a", 7, "7" * 64),
                MonitorHead("monitor-b", "operator-b", "account-b", "region-b", 7, "7" * 64),
            ],
            "consistency_proof_status": "VERIFIED",
        },
        Outcome.RECOVERED,
    )
    expect(
        "witness rollback",
        {"witness": HighWater(5, "5" * 64)},
        Outcome.QUARANTINE,
        "behind protected",
    )
    expect(
        "protected digest fork",
        {"witness": HighWater(6, "a" * 64)},
        Outcome.QUARANTINE,
        "conflicts with protected",
    )
    expect(
        "authority ahead",
        {"local": HighWater(7, "7" * 64), "witness_chain": []},
        Outcome.QUARANTINE,
        "ahead of witness",
    )
    expect(
        "same-generation authority fork",
        {
            "local": HighWater(6, "a" * 64),
            "witness_chain": [],
        },
        Outcome.QUARANTINE,
        "protected verifier digest",
    )
    expect(
        "local chain misses protected high-water",
        {"witness_chain": [Checkpoint(6, "a" * 64, "5" * 64)]},
        Outcome.QUARANTINE,
        "does not intersect",
    )
    expect(
        "missing protected-to-local proof",
        {
            "local": HighWater(6, "6" * 64),
            "witness": HighWater(7, "7" * 64),
            "witness_chain": [Checkpoint(7, "7" * 64, "6" * 64)],
            "monitors": [
                MonitorHead("monitor-a", "operator-a", "account-a", "region-a", 7, "7" * 64),
                MonitorHead("monitor-b", "operator-b", "account-b", "region-b", 7, "7" * 64),
            ],
            "consistency_proof_status": "VERIFIED",
            "local_consistency_proof_status": "MISSING",
        },
        Outcome.BLOCKED,
    )
    expect(
        "invalid protected-to-local proof",
        {
            "local": HighWater(6, "6" * 64),
            "witness": HighWater(7, "7" * 64),
            "witness_chain": [Checkpoint(7, "7" * 64, "6" * 64)],
            "monitors": [
                MonitorHead("monitor-a", "operator-a", "account-a", "region-a", 7, "7" * 64),
                MonitorHead("monitor-b", "operator-b", "account-b", "region-b", 7, "7" * 64),
            ],
            "consistency_proof_status": "VERIFIED",
            "local_consistency_proof_status": "INVALID",
        },
        Outcome.QUARANTINE,
        "not proven to descend",
    )
    expect(
        "chain gap",
        {"witness_chain": [Checkpoint(7, "6" * 64, "5" * 64)]},
        Outcome.QUARANTINE,
        "gap",
    )
    expect(
        "chain predecessor fork",
        {"witness_chain": [Checkpoint(6, "6" * 64, "a" * 64)]},
        Outcome.QUARANTINE,
        "predecessor fork",
    )
    expect(
        "chain digest does not reach witness",
        {"witness_chain": [Checkpoint(6, "a" * 64, "5" * 64)]},
        Outcome.QUARANTINE,
        "does not terminate",
    )
    expect(
        "unverified checkpoint chain",
        {"checkpoint_chain_verified": False},
        Outcome.QUARANTINE,
        "not verified",
    )
    expect(
        "non-replayable authority state",
        {"local_state_replayable": False},
        Outcome.QUARANTINE,
        "cannot be deterministically replayed",
    )
    expect(
        "trust rollback",
        {"trust_generation": 3},
        Outcome.QUARANTINE,
        "trust-bundle generation rollback",
    )
    expect(
        "unverified trust successor",
        {"trust_generation": 5, "protected_trust_generation": 4, "trust_chain_verified": False},
        Outcome.QUARANTINE,
        "successor chain",
    )
    expect(
        "revocation unavailable",
        {"revocation_state_available": False},
        Outcome.BLOCKED,
    )
    expect(
        "revocation rollback",
        {"revocation_generation": 7},
        Outcome.QUARANTINE,
        "revocation generation rollback",
    )
    expect(
        "single monitor",
        {"monitors": base_case()["monitors"][:1]},
        Outcome.BLOCKED,
        "fewer than two",
    )
    duplicate_monitor = MonitorHead("monitor-b", "operator-a", "account-a", "region-a", 6, "6" * 64)
    expect(
        "non-independent monitors",
        {"monitors": [base_case()["monitors"][0], duplicate_monitor]},
        Outcome.BLOCKED,
        "must be distinct",
    )
    conflicting = MonitorHead("monitor-c", "operator-c", "account-c", "region-c", 6, "c" * 64)
    expect(
        "monitor equivocation",
        {"monitors": base_case()["monitors"] + [conflicting]},
        Outcome.QUARANTINE,
        "conflicting heads",
    )
    stale = replace(base_case()["monitors"][1], generation=5, digest="5" * 64)
    expect(
        "monitor lag",
        {"monitors": [base_case()["monitors"][0], stale]},
        Outcome.BLOCKED,
        "not caught up",
    )
    ahead = replace(base_case()["monitors"][1], generation=7, digest="7" * 64)
    expect(
        "monitor ahead of latest read",
        {"monitors": [base_case()["monitors"][0], ahead]},
        Outcome.QUARANTINE,
        "newer than the claimed latest",
    )

    print("FENCE-001 restore/reconciliation reference model: PASS")
    print("Scenarios: 28 fail-closed and recovery cases")
    print("Outcomes exercised: RECONCILED, RECOVERED, BLOCKED, QUARANTINE")
    print("Scope: deterministic state-machine model only; no provider, database restore or execution authorization")


if __name__ == "__main__":
    main()
