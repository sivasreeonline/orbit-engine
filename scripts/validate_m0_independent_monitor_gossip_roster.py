#!/usr/bin/env python3
"""Require a complete, independently configured monitor roster before gossip.

The underlying comparison model detects split views only among observations
that reach it. This gate prevents omission or identity substitution from
silently turning a partial monitor set into an AGREED result.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations
from typing import Sequence

from validate_m0_independent_monitor_gossip import (
    GossipDecision,
    Monitor,
    Outcome,
    compare_monitor_views,
)


@dataclass(frozen=True)
class MonitorIdentity:
    monitor_id: str
    operator: str
    account: str
    failure_domain: str


@dataclass(frozen=True)
class RosterDecision:
    outcome: Outcome
    reason: str
    comparison: GossipDecision | None = None


def compare_configured_roster(
    expected: Sequence[MonitorIdentity],
    observed: Sequence[Monitor],
    *,
    now: int,
    max_poll_age: int,
    cross_monitor_consistency_status: str,
) -> RosterDecision:
    """Fail closed unless every configured monitor contributes one exact view."""
    if len(expected) < 2:
        return RosterDecision(Outcome.BLOCKED, "configured roster has fewer than two monitors")
    dimensions = (
        [item.monitor_id for item in expected],
        [item.operator for item in expected],
        [item.account for item in expected],
        [item.failure_domain for item in expected],
    )
    if any(not isinstance(value, str) or not value.strip() for group in dimensions for value in group):
        return RosterDecision(Outcome.QUARANTINE, "configured monitor identity contains an empty field")
    if any(len(set(group)) != len(group) for group in dimensions):
        return RosterDecision(Outcome.QUARANTINE, "configured monitor roster reuses an identity, operator, account or failure domain")

    observed_ids = [item.monitor_id for item in observed]
    if len(set(observed_ids)) != len(observed_ids):
        return RosterDecision(Outcome.QUARANTINE, "duplicate monitor observation detected")
    expected_ids = {item.monitor_id for item in expected}
    actual_ids = set(observed_ids)
    if actual_ids - expected_ids:
        return RosterDecision(Outcome.QUARANTINE, "unconfigured monitor attempted to participate")
    if expected_ids - actual_ids:
        return RosterDecision(Outcome.BLOCKED, "configured monitor observation is missing; partial agreement is not admission")

    expected_by_id = {item.monitor_id: item for item in expected}
    for item in observed:
        identity = expected_by_id[item.monitor_id]
        if (item.operator, item.account, item.failure_domain) != (
            identity.operator, identity.account, identity.failure_domain
        ):
            return RosterDecision(Outcome.QUARANTINE, "monitor identity, operator, account or failure-domain substitution detected")

    comparison = compare_monitor_views(
        observed,
        now=now,
        max_poll_age=max_poll_age,
        cross_monitor_consistency_status=cross_monitor_consistency_status,
    )
    return RosterDecision(comparison.outcome, comparison.reason, comparison)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    a = MonitorIdentity("monitor-a", "operator-a", "account-a", "failure-a")
    b = MonitorIdentity("monitor-b", "operator-b", "account-b", "failure-b")
    c = MonitorIdentity("monitor-c", "operator-c", "account-c", "failure-c")
    roster = (a, b, c)

    from validate_m0_independent_monitor_gossip import head, monitor

    honest_a = monitor("monitor-a")
    honest_b = monitor("monitor-b")
    honest_c = monitor("monitor-c")
    forked_c = monitor(
        "monitor-c", 6, "a" * 64, "5" * 64,
        protected_generation=6, protected_digest="a" * 64,
    )

    def evaluate(observations: Sequence[Monitor], proof: str = "NOT_REQUIRED") -> RosterDecision:
        return compare_configured_roster(
            roster, observations, now=10_000, max_poll_age=60,
            cross_monitor_consistency_status=proof,
        )

    baseline = evaluate((honest_a, honest_b, honest_c))
    require(baseline.outcome == Outcome.AGREED, "complete matching roster should agree")

    # No permutation may turn a minority fork into a majority-vote acceptance.
    for ordering in permutations((honest_a, honest_b, forked_c)):
        decision = evaluate(ordering)
        require(decision.outcome == Outcome.QUARANTINE, "minority split view was accepted for an ordering")

    require(evaluate((honest_a, honest_b)).outcome == Outcome.BLOCKED,
            "omitting a configured monitor must block even if remaining views agree")
    require(evaluate((honest_a, honest_b, honest_c, monitor("monitor-x"))).outcome == Outcome.QUARANTINE,
            "unconfigured monitor must be quarantined")
    require(evaluate((honest_a, honest_b, monitor("monitor-c", operator="operator-a"))).outcome == Outcome.QUARANTINE,
            "operator substitution must be quarantined")
    require(evaluate((honest_a, honest_b, monitor("monitor-c", account="account-a"))).outcome == Outcome.QUARANTINE,
            "account substitution must be quarantined")
    require(evaluate((honest_a, honest_b, monitor("monitor-c", failure_domain="failure-a"))).outcome == Outcome.QUARANTINE,
            "failure-domain substitution must be quarantined")
    require(evaluate((honest_a, honest_b, honest_c, honest_c)).outcome == Outcome.QUARANTINE,
            "duplicate observation must be quarantined")

    shared_operator_roster = (
        a, MonitorIdentity("monitor-b", "operator-a", "account-b", "failure-b"), c
    )
    invalid = compare_configured_roster(
        shared_operator_roster, (honest_a, honest_b, honest_c),
        now=10_000, max_poll_age=60,
        cross_monitor_consistency_status="NOT_REQUIRED",
    )
    require(invalid.outcome == Outcome.QUARANTINE, "non-independent configured operators must be rejected")

    newer_c = monitor(
        "monitor-c", 7, "7" * 64, "6" * 64,
        protected_generation=6, protected_digest="6" * 64,
    )
    require(evaluate((honest_a, honest_b, newer_c), "VERIFIED").outcome == Outcome.CATCH_UP_REQUIRED,
            "complete roster with a proven extension must require catch-up, not agree")
    require(evaluate((honest_a, honest_b, newer_c), "MISSING").outcome == Outcome.BLOCKED,
            "missing cross-monitor proof must block")

    print("FENCE-001 configured monitor roster gate: PASS")
    print("Scenarios: complete-roster agreement, all 6 observation permutations, minority split view, omission, injection, substitution, duplicate and catch-up")
    print("Security boundary: roster completeness gate only; identity authentication, signatures, proofs, durable state and transport remain external")


if __name__ == "__main__":
    main()
