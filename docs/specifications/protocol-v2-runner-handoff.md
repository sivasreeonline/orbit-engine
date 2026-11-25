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

At the current PR head, the queue consumer and handoff repository explicitly accept
v1 only, and migration `0005_runner_dispatch_outbox.sql` constrains dispatch rows to
v1. Migration `0014_execution_protocol_v2_requests.sql` adds the proposal-stage
immutable request table but is not yet connected to intake or dispatch. These are
intentional fail-closed boundaries and must not be relaxed until the coordinated
rollout and integration tests above are ready.

Required integration tests include v1 regression, v2 valid handoff, missing request,
wrong attempt, wrong correlation, expired deadline, duplicate delivery, concurrent
duplicate delivery, lost queue acknowledgement, disabled publication gate, and
proof that no v2 request can reach a v1-only runner.
