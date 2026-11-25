# FENCE-001 provider-neutral monitor replay checkpoint coordinator

## Status

This slice adds a TypeScript provider-neutral adapter contract and a deterministic
monitor replay snapshot checkpoint coordinator in the private witness gateway.
It is a protocol implementation and synthetic test layer; it does not select,
deploy or qualify an external provider.

## Adapter contract

A provider adapter must expose:

- `appendIfCurrent`: atomic compare-and-append against the exact expected
  generation and predecessor digest;
- `readLatest`: a strongly consistent read of the current checkpoint;
- `readByOperation`: immutable lookup by deterministic operation ID.

The append must bind the idempotency key to the complete checkpoint, including
scope, generation, phase, digest, predecessor and canonical snapshot bytes.
Changed-content reuse of an idempotency key or operation ID is a conflict.

The returned `consistencyToken` is opaque metadata. It is not a signature,
Merkle proof, consistency proof or durability attestation.

## Canonical snapshot and operation identity

The coordinator:

1. Accepts only a plain JSON object and serializes it using RFC 8785.
2. Bounds canonical snapshot size to 512 KiB.
3. Computes SHA-256 over the exact canonical UTF-8 bytes.
4. For legacy callers without a persisted predecessor, retains the original
   snapshot-digest operation ID for compatibility. For the durable-intent path,
   derives the operation ID from canonical witness scope, the exact persisted
   predecessor generation/digest, and snapshot digest.
5. In the durable-intent path, requires the provider's latest generation/digest
   to equal the persisted predecessor exactly; it never rebases a pending intent.
6. Requests one immutable successor with phase
   `MONITOR_GOSSIP_REPLAY_V1`.

Object key insertion order does not affect the snapshot digest. In the durable-intent
path, the operation ID is stable across retries of the same scope, predecessor
and snapshot, and differs when any of those bindings differ.

## Verified checkpoint identity versus transparency tree head

The API finalization record keeps two distinct digests:

- `checkpointDigest` is the digest signed into the witness receipt for the
  checkpoint body. The receipt also binds operation ID, generation and
  previous checkpoint digest.
- `treeHeadDigest` is the root hash of the signed transparency tree head that
  contains the receipt leaf. It is not the checkpoint digest and must never be
  copied into the checkpoint predecessor field.

The private gateway returns these values only after verifying the trust bundle,
receipt signature and checkpoint binding, signed tree head, receipt inclusion,
and tree-head consistency. It also returns the verified scope, operation ID,
generation and predecessor. The API finalizer compares those values with the
persisted intent and requires the checkpoint body's `authorityStateDigest`
to equal the exact pending snapshot digest.

On finalization, `ReplayWitnessHead.digest` stores the checkpoint digest;
`ReplayWitnessHead.treeHeadDigest` stores the transparency root. A receipt for
another scope, operation, predecessor, generation or snapshot is rejected.

## Ambiguous acknowledgement and readback

If append reports an ambiguous acknowledgement, the coordinator queries the
same deterministic operation ID. It never generates a new operation ID for
that snapshot. The recovered record must bind the exact scope, canonical
snapshot bytes, generation, predecessor and receipt fields.

After append or recovery, the coordinator performs both immutable operation
lookup and latest-head readback. It returns `CHECKPOINTED` only when both
identify the exact submitted record and receipt. An existing operation that
is no longer the current head returns a stale-operation error; it is not
reported as current.

A stale predecessor conflict is propagated. The coordinator never rebases a
candidate automatically after another writer advances the head.

## Test coverage and limits

Unit tests use an in-memory synthetic adapter to cover canonicalization,
deterministic retries, lost acknowledgement recovery, stale operation
rejection, competing successors, invalid snapshots, malformed receipt
readback and stale latest-read behavior.

These tests establish the coordinator's exercised logic only. They do not
establish that any external adapter implements linearizable compare-and-append,
strong reads, immutable operation lookup, durability, independent failure
domains or split-view resistance.

## Next integration gate

The next slice must implement a gateway-owned durable pending-intent /
finalize / recovery state machine around the existing `GossipReplayStateDO`.
It must keep external provider calls outside Durable Object transactions,
block competing successors while an intent is pending, preserve exact
operation bytes across retries, and reconcile restored local state against
the independently verified witness head.

Only after that lifecycle is integrated should a concrete provider adapter be
wired behind this interface. Production provider qualification remains a
separate evidence gate.
