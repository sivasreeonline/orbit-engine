# FENCE-001 configured monitor roster and anti-omission gate

**Status:** Deterministic policy gate and synthetic test vectors; not a deployed monitor control plane or production authorization mechanism.

## Problem

The independent gossip comparator can detect a split view only among observations it receives. If a caller silently omits the monitor that observed a fork, the remaining monitors may agree and produce an apparently healthy result. A majority vote is not a safe substitute: one minority observation of a validly signed conflicting head is sufficient to quarantine the witness scope.

## Required roster binding

The comparison caller must obtain the expected monitor roster from independently governed configuration, not from the gossip message or the witness being evaluated. Each configured entry binds:

- stable monitor ID;
- independent operator identity;
- independent cloud/account identity;
- independent failure-domain identity.

Before comparing heads, the gate requires exactly one observation from every configured monitor. It rejects duplicate observations, unknown monitor IDs, and changes to the configured operator/account/failure-domain tuple. A missing configured monitor returns BLOCKED; it never silently shrinks the comparison set. Reuse of any independence dimension in the configured roster is quarantined.

## Decision composition

After roster completeness and identity binding, the gate delegates to the existing pairwise monitor comparator. It does not convert CATCH_UP_REQUIRED into AGREED. A newer head must be independently verified and durably persisted by every lagging monitor, followed by a fresh complete-roster gossip round.

Any pair of validly signed heads at the same generation with different digest or predecessor is a split view and must quarantine the scope, even if all other monitors agree with one side. A verified extension remains CATCH_UP_REQUIRED until the full roster converges.

## Synthetic validation

`scripts/validate_m0_independent_monitor_gossip_roster.py` exercises:

- complete-roster agreement;
- all six permutations of a three-monitor set where one monitor sees a conflicting signed head;
- omission of a configured monitor;
- injection of an unconfigured monitor;
- duplicate observations;
- operator, account and failure-domain substitution;
- non-independent configured roster;
- missing cross-monitor consistency proof;
- verified extension requiring catch-up.

## Security boundaries and remaining qualification

The roster is an input and must itself be distributed/authenticated through independent governance. This gate does not authenticate monitor identities, verify signatures or Merkle proofs, provide durable monitor replay state, establish trusted time, guarantee network delivery, or prevent a malicious operator from suppressing messages. The comparator's verification statuses are pre-verified inputs, not cryptographic evidence.

Production anti-equivocation still requires independently administered monitors, authenticated replay-resistant transport, durable per-peer sequence/high-water state outside the authority restore domain, complete-roster polling, alerting, signed fork evidence retention, partition/compromise/restore exercises, and independent qualification of roster governance. No execution/admission authorization is created by this gate.
