# FENCE-001 monitor replay-state witness checkpoint

**Status:** Provider-neutral checkpoint contract and synthetic integration. The monitor replay Durable Object does not yet call a deployed witness service. No production qualification is claimed.

## Purpose

The monitor gossip replay Durable Object stores sender/recipient/scope bindings, accepted message IDs and digests, sequence high-water, unresolved gaps, outstanding proof requests and consumed nonces. Its local storage is not an independent anti-rollback authority. A restore of that object to an older snapshot must not be accepted as current replay state.

This slice adds a provider-neutral immutable witness checkpoint for a canonical replay-state snapshot. Each sender/recipient/scope relationship uses a distinct witness scope. The checkpoint digest commits to the entire canonical snapshot, not just the highest sequence.

## Checkpoint protocol

1. Serialize the complete replay state using canonical JSON (UTF-8, sorted object keys, compact separators, no NaN/Infinity).
2. Hash the canonical bytes with SHA-256.
3. Read the witness's strongly consistent latest checkpoint.
4. If an operation with the deterministic snapshot operation ID already exists, require exact checkpoint and receipt equality and allow replay only while it remains the current head.
5. Otherwise append the snapshot as exactly the next immutable generation, naming the exact previous checkpoint digest.
6. On ambiguous acknowledgement, recover the exact operation by ID; never issue a new operation ID for the same snapshot.
7. Read the operation and latest head back and require exact checkpoint/receipt equality.

The provider adapter must supply atomic compare-and-append, immutable operation lookup, strong latest reads, idempotency bound to exact content, and an externally qualified consistency receipt. The in-memory fixture proves logic only.

## Restore reconciliation

- MATCH: the local canonical snapshot digest equals the latest independent witness checkpoint.
- QUARANTINE: local state differs from the latest witness checkpoint. This includes rollback to an older snapshot, unanchored local advancement, or tampering.
- NO_CHECKPOINT_EMPTY_STATE: no witness checkpoint exists and the local replay state is empty.
- BLOCKED: witness state is unavailable or the witness result cannot be validated.

A mismatch is never repaired by trusting the local Durable Object state or automatically overwriting the witness head. Recovery requires independently authenticated replay evidence and a separately governed reconciliation procedure.

## Integration boundary and sequencing

This PR establishes the provider-neutral state-checkpoint operation and restore decision. It does **not** yet wire a Cloudflare Worker service binding to a separately deployed witness gateway. That bridge must preserve authenticated service identity, verify witness receipts and consistency evidence, and keep the witness failure domain independent from the Cloudflare Durable Object restore domain. Until that bridge and its failure-injection tests exist, the Durable Object must not claim rollback protection.

The snapshot contains monitor replay metadata only. It contains no student source code or execution output. No live AWS calls, credentials, production roots, host execution or student-code execution are used.
