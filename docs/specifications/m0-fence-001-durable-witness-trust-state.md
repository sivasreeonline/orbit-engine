# FENCE-001 Durable Witness Trust State

## Status

Adds a gateway-owned Cloudflare Durable Object and typed adapter for storing
verified trust-bundle and signed tree-head state. PR #197 wires this store into
the private `verifyEvidence` RPC path so verification uses persisted trust and
prior-head state.

## State model

Each Durable Object is scoped by the adapter's stable name:

`trustDomainId:witnessId`

The stored snapshot contains:

- trust-bundle generation and canonical body digest;
- the accepted root-signed trust-bundle envelope;
- the last accepted signed tree-head envelope and its canonical envelope digest;
- the trust-bundle digest and exact root-signed trust-bundle envelope under which
  that tree head was verified.

The empty state is generation zero with the all-zero predecessor digest and no
accepted tree head.

## Atomic trust-bundle transition

`advanceTrustBundle` uses one Durable Object storage transaction and a
compare-and-set contract:

- caller supplies expected generation and digest;
- next generation must be exactly current generation + 1;
- the envelope predecessor digest must equal the current digest;
- the canonical RFC 8785 body digest must equal `bundleDigest`;
- stale concurrent updates are rejected;
- exact retries are idempotent.

Cryptographic root signature verification and key semantics must happen in the
gateway before the update method is called. The DO enforces the state
transition, not the cryptographic trust decision.

## Atomic signed tree-head transition

`advanceTreeHead` also uses one storage transaction:

- first observation requires an empty prior-head slot;
- later observations must compare-and-set the digest of the current stored head;
- witness, authority, host and log identity cannot change;
- tree size must strictly increase;
- exact retries are idempotent;
- stale writers, rollbacks and log substitution are rejected.

The gateway must verify the signed tree head and RFC 9162 consistency proof
before calling this method. The DO does not independently verify Ed25519
signatures or Merkle proofs.

## Recovery and trust rotation

The accepted tree head records the trust-bundle digest under which it was
verified. This preserves the historical verification context across trust
bundle rotations. A future gateway integration must not blindly re-verify an
old tree-head signature against a newer trust bundle if the old signing key has
since been retired or revoked.

## Qualification boundary

- The Durable Object is private to the gateway Worker; its HTTP handler returns 404.
- This PR does not wire the DO into `verifyWitnessEvidence` or the gateway RPC.
- It does not implement provider append/readback or the monitor replay
  pending-intent/finalize/recovery protocol.
- No production root pins, signing keys, external writes or deployments are used.
- Local Durable Object tests demonstrate transactional state behavior only;
  they do not establish an external provider's durability or independent
  anti-equivocation guarantees.
