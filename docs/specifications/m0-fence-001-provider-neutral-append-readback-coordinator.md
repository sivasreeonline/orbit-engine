# FENCE-001 Provider-Neutral Append/Readback Coordinator

## Status

The TypeScript provider-neutral coordinator is implemented as a pure orchestration
module. It is not yet wired to a production Service Binding or external provider.
Tests use an in-memory synthetic adapter only.

## Adapter contract

A provider adapter must implement:

- `appendIfCurrent(checkpoint, expectedGeneration, expectedDigest, idempotencyKey)`
  as one atomic compare-and-append transaction;
- immutable `readByOperation(scope, operationId)`;
- strongly consistent `readLatest(scope)`.

The provider namespace is scoped by trust domain, witness, authority, host,
sender, recipient and replay scope. The operation id is deterministic from the
canonical replay `snapshotDigest`.

The provider checkpoint carries both:
- `snapshotDigest`: complete replay snapshot digest;
- `checkpointDigest`: digest of the signed FENCE-001 checkpoint body.

The provider's predecessor compare-and-append uses the previous
`checkpointDigest`, never the snapshot digest.

## Coordinator algorithm

1. Canonicalize the replay snapshot and build its existing-profile checkpoint
   artifact.
2. Look up the deterministic operation ID. If present, verify the exact
   artifact and signed receipt, then require the strong latest record to be the
   same immutable operation. A historical operation that is no longer latest
   is stale and cannot be treated as a successful retry.
3. Read and verify the current latest record to obtain expected generation and
   predecessor checkpoint digest.
4. Call atomic `appendIfCurrent` with the next generation, exact predecessor
   digest and deterministic operation ID as idempotency key.
5. If acknowledgement is ambiguous, recover only through immutable
   `readByOperation`; never issue a second operation ID.
6. Read by operation and then perform a strong latest read. Both must match the
   exact checkpoint artifact and receipt.
7. A successful result is returned only after the injected evidence verifier
   has accepted the provider record.

## Failure behavior

- Compare-and-append conflict: fail closed; caller must refresh state and retry
  through the same operation ID.
- Ambiguous acknowledgement: immutable operation lookup; if absent, report
  provider unavailable/unknown outcome and do not invent success.
- Missing operation readback after acknowledged append: integrity failure.
- Receipt mismatch, artifact digest mismatch, scope substitution, or latest
  readback mismatch: integrity failure.
- Provider unavailable: no local success is reported.

## Qualification boundary

- Unit tests use an in-memory fake provider and a synthetic record verifier.
- The coordinator does not itself prove an adapter's atomicity or strong-read
  guarantees; each concrete adapter must pass the provider conformance suite.
- No external provider binding, append, deployment, production key, or live
  witness write is configured by this PR.
- The Durable Object pending-intent/finalize/recovery protocol is a separate
  integration gate and must be implemented before replay-state advancement can
  be treated as externally checkpointed.
