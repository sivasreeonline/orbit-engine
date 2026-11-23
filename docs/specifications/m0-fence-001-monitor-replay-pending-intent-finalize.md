# FENCE-001 Monitor Replay Pending-Intent / Finalize / Recovery

## Status

The Durable Object now stages replay state as a pending intent and commits it
only after an independently verified witness checkpoint is finalized. This PR
implements the state machine and local runtime tests; it does not yet wire the
API Worker to a concrete provider adapter.

## State model

Three durable keys define the lifecycle:

- `replay-state-v1`: the last replay snapshot whose witness checkpoint was
  verified and finalized;
- `pending-checkpoint-intent-v1`: the next validated replay snapshot, its
  deterministic operation ID, snapshot digest, expected predecessor generation
  and expected predecessor checkpoint digest;
- `checkpoint-state-v1`: the last finalized witness generation, checkpoint
  artifact digest, snapshot digest, operation ID, receipt digest, trust-bundle
  digest, tree-head digest/size and receipt leaf hash.

## Prepare

`prepareCheckpointIntent(message, trustedNow)` performs the existing replay
validation and builds the next replay state inside one Durable Object storage
transaction. It then:

1. canonicalizes the complete normalized snapshot using RFC 8785;
2. computes `snapshotDigest`;
3. derives `fence-monitor-replay-${snapshotDigest}` as the operation ID;
4. records the expected current witness generation and predecessor artifact
   digest;
5. persists the pending intent without changing `replay-state-v1`.

While an intent is pending, additional messages are blocked. The committed
snapshot remains unchanged and `readPendingCheckpointIntent()` exposes the
exact data required for recovery.

The compatibility method `acceptVerifiedMessage` now stages a pending intent;
it no longer commits replay state directly.

## Finalize

After the private gateway has verified the provider receipt, trust bundle,
signed tree head, receipt inclusion and prior-head consistency, the internal
caller supplies the verified attestation and checkpoint artifact body to
`finalizeCheckpointIntent`.

The Durable Object independently checks that:

- operation ID, snapshot digest, generation and predecessor match the pending
  intent;
- the canonical checkpoint-body digest equals the supplied
  `checkpointDigest`;
- the body binds the pending snapshot through `authorityStateDigest`;
- the body phase, operation ID, generation, previous digest, epoch and record
  version match the pending snapshot;
- the gateway verification attestation contains valid trust/tree/leaf digests.

Only then does one storage transaction write the pending snapshot as committed
replay state, write the finalized checkpoint metadata, and delete the pending
intent. Repeated exact finalization is idempotent.

## Recovery

If the Worker crashes after provider append but before local finalization, the
pending intent remains durable. Recovery reads that exact intent, reuses its
operation ID, and asks the provider coordinator to recover by immutable
operation lookup. It must not generate a new operation ID. After the gateway
re-verifies the provider record, the same finalization operation can complete.

If the provider is unavailable or the outcome is ambiguous, the pending intent
remains and new replay messages stay blocked. There is no unsafe timeout-based
auto-clear or blind retry with a new idempotency key.

## Legacy-state gate

A non-empty replay state without a finalized checkpoint is quarantined. The
system does not silently create a first checkpoint over pre-existing local
state, because that would retroactively bless potentially rolled-back state.
Committed state is also checked against its locally stored snapshot digest
before a new intent can be prepared.

## Qualification boundary

- Workers runtime tests use a synthetic verification attestation and locally
  generated checkpoint artifacts.
- The API-to-gateway/provider orchestration is a subsequent integration slice.
- No external provider append, production credentials, deployment, host
  execution or student-code execution is performed by this PR.
