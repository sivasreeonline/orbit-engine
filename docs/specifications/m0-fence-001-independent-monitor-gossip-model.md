# FENCE-001 independent monitor gossip reference model

**Status:** Test-only policy model; not a deployed gossip service or production anti-equivocation mechanism.  
**Purpose:** Specify how independently operated monitors compare signed witness heads without treating one monitor's local view as authoritative.

## Comparison protocol

`scripts/validate_m0_independent_monitor_gossip.py` models a minimum two-monitor comparison and supports more than two monitors. Each observation carries a witness scope, signed-head summary, local protected high-water, operator/account/failure-domain identity and last successful poll time.

Before comparing views, the model requires:
- two or more monitors with distinct monitor IDs, operators, accounts and failure domains;
- fresh poll observations, with future timestamps rejected;
- exact witness scope agreement;
- an authenticated head under the pinned profile;
- valid generation/digest/predecessor fields;
- no regression or same-generation conflict against each monitor's own durable protected high-water;
- a verified extension proof whenever a monitor advances beyond its protected high-water.

Pairwise comparison has four outcomes:

| Outcome | Meaning |
|---|---|
| `AGREED` | All fresh, independent monitors report the same generation, digest and predecessor |
| `CATCH_UP_REQUIRED` | A newer head is proven to extend the older one; the lagging monitor must persist it and gossip again |
| `BLOCKED` | A monitor is missing/stale, trust is unavailable, or a required consistency proof is missing |
| `QUARANTINE` | A signature/proof is invalid, a head regresses, scope differs, or conflicting signed heads are observed |

A `CATCH_UP_REQUIRED` outcome is never an admission decision. The lagging monitor must independently verify and durably persist the newer head, then the monitor set must repeat gossip and reach `AGREED`.

## Security boundaries

The model receives signature and proof verification outcomes as inputs. It does not implement Ed25519 verification, RFC 9162 parsing, Merkle proof verification, trusted-time acquisition, durable monitor storage, identity authentication, or a network gossip protocol. A boolean/status supplied by a test fixture is not evidence that a real monitor has authenticated another monitor.

The model detects a split view only if incompatible signed heads reach the comparison operation. It cannot prove that all monitors receive every fork or that an operator cannot suppress gossip. Production qualification still requires:
- independently administered monitor deployments and credentials;
- authenticated, replay-resistant monitor-to-monitor transport;
- durable per-scope high-water storage outside the authority restore domain;
- bounded polling and gossip intervals with tested alert delivery;
- signed evidence bundles for both conflicting heads and consistency proofs;
- network-partition, monitor-compromise, stale-key, stale-revocation and delayed-gossip exercises;
- independent verification of the provider, monitor topology and incident response.

RFC 9162 explicitly describes gossip as an active area of research rather than a fully specified protocol and warns that a log can present inconsistent views to isolated clients. Its Merkle consistency proof verifies an append-only relation between two presented tree heads; it does not itself provide global view agreement. See [RFC 9162 Sections 8.3 and 11.3](https://www.rfc-editor.org/rfc/rfc9162.html).

No runtime path imports this reference model as an authorization decision. No provider, monitor deployment, production key, host admission or execution authorization is created by this change.
