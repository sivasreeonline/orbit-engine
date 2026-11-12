# FENCE-001 Merkle transparency proof reference model

**Status:** Test-only reference model; no transparency-log provider or production profile selected.  
**Standard reference:** [RFC 9162, Sections 2.1.1–2.1.4](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1).  
**Important status note:** RFC 9162 is published as an Experimental Protocol, not an Internet Standards Track specification. This repository does not silently adopt it as the production witness protocol.

## What is implemented

`scripts/validate_m0_fence_witness_merkle_proofs.py` implements a small independent reference model for:

- RFC 9162 Merkle Tree Hash with leaf/node domain separation (`SHA-256(0x00 || leaf)`, `SHA-256(0x01 || left || right)`);
- inclusion proof generation and verification;
- consistency proof generation and verification;
- strict 32-byte digest/path-node checks and tree-size/index bounds;
- deterministic minimal-path comparison against the published fixture;
- negative cases for altered leaf/node, truncated/overlong proof, invalid index, reversed sizes, conflicting same-size roots and rewritten prefixes;
- exhaustive generated proof checks for all inclusion indices and all old/new tree-size pairs through 40 leaves.

The fixed fixture is `docs/test-vectors/fence-witness-v1-004-merkle-transparency.json`. It is marked `testOnly`; it contains seven ordered synthetic checkpoint labels and roots/proofs for tree sizes 3, 4, 6 and 7.

## Security boundary

This model proves only that the implemented proof algorithms accept valid test proofs and reject the tested mutations. It does not authenticate a Signed Tree Head, bind a head to a trust bundle or authority scope, establish trusted time, prove provider durability/linearizability, or establish that independent monitors observe the same heads.

In particular, a valid consistency proof establishes that one presented tree is an append-only extension of another presented tree. It does not stop a provider from presenting two different but internally consistent histories to isolated clients. Independent monitors must exchange and compare signed heads over a separate gossip channel, and conflicting heads must trigger quarantine.

A production adapter may adopt RFC 9162 only after an explicit profile decision, independent review of algorithm/encoding interoperability, trust-bundle key-purpose design, provider API qualification, monitor topology evidence and operational recovery testing. No runtime path imports this reference model as an authorization decision.
