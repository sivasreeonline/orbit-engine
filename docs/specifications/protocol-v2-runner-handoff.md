# Protocol v2 queue-to-runner handoff contract

Status: proposed design for PR #202. This document does not authorize v2 publication,
runner claims, artifact retrieval, or student-code execution.

## Current v1 contract (preserve unchanged)

The execution outbox publishes a metadata-only envelope:

```json
{
  "executionId": "<uuid>",
  "attemptId": "<uuid>",
  "protocolVersion": "v1"
}
```

The queue consumer accepts exactly those three keys. The PostgreSQL handoff repository
then locks the authoritative execution job and verifies the attempt, execution-outbox
attempt, and protocol version before creating one durable dispatch intent. The
runner-dispatch outbox carries protocol version and correlation ID. Existing v1
dispatch and Go runner behavior must remain byte-for-byte compatible at the message
boundary.

## Proposed v2 envelope

Use the same three-key envelope shape, with only the protocol discriminator changed:

```json
{
  "executionId": "<uuid>",
  "attemptId": "<uuid>",
  "protocolVersion": "v2"
}
```

Do not place source code, test contents, policy limits, cancellation references,
runtime image digests, or serialized request bytes on the queue. The immutable
`execution_protocol_requests` row is keyed by `execution_id`; it is the sole
authoritative source for the complete v2 request. The queue is only a wake-up signal.

The API must not interpret a queue message's IDs as authority. For v2, the handoff
transaction must lock and verify all of the following before creating a dispatch:

1. The execution job's current attempt equals the envelope attempt.
2. The matching `execution_outbox` event is `EXECUTION_REQUESTED`, and its
   execution ID, attempt ID, and protocol version match the envelope.
3. Exactly one immutable `execution_protocol_requests` row exists for the execution.
4. That row's attempt ID and protocol version match the authoritative job/outbox.
5. The request's correlation ID matches the authoritative outbox correlation ID.
6. The persisted request deadline has not expired at handoff time.

Any mismatch is a permanent integrity rejection; it must never fall back to v1 or
rebuild a v2 request from current policy. A duplicate delivery may be acknowledged
only when the existing dispatch intent matches the same execution, attempt, version,
and correlation identity.

## Required coordinated rollout

Do not widen the v1-only database constraints or queue parser in isolation. The
following capabilities must land as one coordinated, tested change:

- Intake creates the v2 request and inserts its exact bytes and SHA-256 in the same
  transaction as source snapshot, attempt, job, and outbox.
- The v2 publication gate defaults off. A v2 outbox row cannot be published while
  the queue consumer, handoff repository, authenticated artifact endpoint, dispatch
  transport, and Go consumer are not all v2-capable.
- Queue parsing is an exact discriminated union. Unknown versions and extra keys are
  rejected; v1 remains accepted without added fields.
- Handoff persistence validates the v2 request row as described above.
- Dispatch leases preserve protocol version and correlation ID end-to-end. A
  v2 lease is not claimable by a v1-only dispatcher.
- The authenticated artifact endpoint returns the persisted request bytes, not a
  reconstructed object. The Go client verifies the bytes/digest and strictly decodes
  the complete v2 schema.
- Unsupported v2 is rejected or held behind the disabled publication gate. It is
  never coerced to v1.

## Failure and replay semantics

| Condition | Required behavior |
| --- | --- |
| Queue send succeeds, publisher acknowledgement is lost | Redelivery is expected; durable handoff is idempotent |
| Same v2 envelope is delivered more than once | Return the existing matching dispatch intent |
| Same execution arrives with another attempt/version/correlation | Reject as integrity mismatch |
| Persisted request is missing or expired | Fail closed; do not create a v2 dispatch |
| v2 arrives while publication/consumer capability is disabled | Do not publish; do not downgrade; retain controlled retry/dead-letter policy |
| Runner or artifact service does not support v2 | No claim or artifact fetch for v2 |
| Policy changes after request persistence | Replay the original immutable bytes; never rebuild |

## Current implementation boundary

At the current PR head, opt-in intake persists the exact v2 request bytes, digest,
policy revision and UUID correlation identity in the same transaction as the
execution records and metadata-only v2 outbox row. The opt-in flag defaults off.

The execution-outbox publisher explicitly claims v1 rows only. A PostgreSQL-backed
integration test proves v2 execution-outbox rows remain `PENDING` without a lease.
The queue consumer accepts the exact three-field v1/v2 discriminator union and
acknowledges a duplicate only after the durable handoff resolves. The handoff
repository verifies v2 against the immutable request row: attempt and correlation
identity, request SHA-256, fatal UTF-8/JSON decoding, exact top-level field set,
exact limits field set, persisted deadline equality and unexpired deadline.
PostgreSQL-backed concurrent delivery coverage proves twelve simultaneous v2
deliveries create one durable dispatch intent and eleven duplicates.

Migration `0015_runner_dispatch_protocol_v2.sql` permits a validated v2 dispatch
intent. Every dispatch lease query remains explicitly v1-only; a PostgreSQL-backed
test proves v2 dispatch intents remain pending and unleased. The authenticated
private artifact endpoint returns the original persisted v2 request bytes and
digest. A same-job CI bridge passes the actual PostgreSQL-backed artifact through
the Go runner client's signed `FetchArtifact` method, which strictly validates
the v2 request and all artifact/dispatch bindings. The queue consumer's lost-ack
test proves a redelivery can safely acknowledge an already-recorded v2 intent.

V2 execution remains disabled: the intake flag defaults off, the v1 publisher
cannot claim v2 execution-outbox rows, and the current v1 runner-dispatch claim
path cannot lease v2 intents. These tests establish the proposal-stage custody and
handoff boundary only; they do not authorize production execution or sandbox use.

The remaining coordinated rollout work is the authenticated v2 claim/lease path,
a version-aware runner dispatch contract, and qualification of the approved
isolated sandbox. Those pieces must remain gated until identity, cancellation,
artifact authorization and M0 isolation criteria are met.


## Authenticated v2 claim boundary (stacked follow-up)

The stacked authenticated-claim slice introduces a distinct `POST /internal/v2/runner/claim`
route. It uses the existing Ed25519 runner request signature and one-time nonce
authentication, but is disabled unless `PROTOCOL_V2_CLAIMS_ENABLED=true` is
explicitly configured. The existing `/internal/v1/runner/claim` route remains
v1-only and is not widened.

The shared PostgreSQL claim transaction accepts a protocol discriminator for
candidate selection. The v1 wrapper selects v1 only; the separately named v2
wrapper selects v2 only. The active lease count intentionally has no protocol
filter, so a runner's two active slots are shared across v1 and v2. Both paths
continue to acquire the global fair-scheduler lock and per-runner advisory lock
before reading capacity and claiming. V2 therefore participates in the same
least-served student-lane scheduler, but cannot consume a slot already occupied
by a v1 lease.

This is a claim-boundary integration only. It does not establish v2 sandbox
qualification, cancellation semantics, artifact authorization parity, runner
protocol support, or permission to enable v2 claims in production. Keep the
configuration gate false until those independent release gates are satisfied.


## Runner protocol qualification registry

Migration `0016_runner_protocol_capabilities.sql` adds an explicit,
control-plane-managed capability record per runner and protocol. New runners
receive no protocol capability rows by default. A runner cannot self-register
or self-upgrade through the authenticated claim request. V2 claim requires an
active, non-revoked `v2` capability row with a qualification reference. The
API checks the row after request authentication and nonce consumption and
before acquiring a dispatch lease. Revocation is observed by the next claim.
Provisioning a capability is an administrative qualification action, not a
runner API operation. V2 remains behind the separate default-off claims gate.
