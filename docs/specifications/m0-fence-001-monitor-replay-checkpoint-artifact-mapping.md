# FENCE-001 Monitor Replay Checkpoint Artifact Mapping

## Purpose

Bind the complete Cloudflare monitor replay Durable Object snapshot to the
existing FENCE-001 signed checkpoint/receipt profile without creating a second
cryptographic receipt format.

## Canonical replay snapshot

`GossipReplayStateDO.readSnapshot()` exports the complete state:

- version, sender, recipient and replay scope;
- highest accepted sequence;
- sequence-to-message and message-to-sequence indexes;
- outstanding consistency-proof requests;
- consumed request nonces;
- missing sequence numbers.

Set-like arrays are sorted before canonicalization. Both the TypeScript and
Python reference implementations use RFC 8785 canonical JSON.

`snapshotDigest = SHA256(canonicalSnapshotBytes)`

The deterministic provider operation identifier is:

`fence-monitor-replay-${snapshotDigest}`

## Existing cryptographic checkpoint body

The snapshot is mapped into the existing `sky-high-fence-witness-v1`
checkpoint-body profile:

| Field | Mapping |
|---|---|
| `authorityId`, `hostId` | Configured witness scope |
| `generation` | Next witness generation |
| `phase` | `ACCEPTED` |
| `operationId` | Deterministic operation ID above |
| `previousCheckpointDigest` | Previous cryptographic checkpoint artifact digest |
| `authorityStateDigest` | Complete replay `snapshotDigest` |
| `responseDigest` | SHA-256 of the canonical replay operation descriptor |
| `epoch` | Replay `highestSequence` |
| `recordVersion` | Replay snapshot version |

`checkpointDigest = SHA256(RFC8785(checkpointBody))`

The provider adapter's `phase` remains `MONITOR_GOSSIP_REPLAY_V1`; that is the
provider operation type, not the cryptographic checkpoint body's phase.

## Two digest rules

- `snapshotDigest` identifies the complete replay state and determines the
  idempotent operation ID.
- `checkpointDigest` identifies the signed checkpoint artifact. It is the
  value signed by the witness receipt and chained as the predecessor digest.

The provider's immutable operation record stores both. Reconciliation compares
the local canonical snapshot digest with the stored `snapshotDigest`. Receipt
verification compares the receipt's `checkpointDigest` with the artifact
digest. The values are not interchangeable.

## Safety requirements

- Provider append must be atomic compare-and-append against the expected
  generation and previous **checkpoint artifact digest**.
- The idempotency key is the deterministic operation ID.
- Ambiguous acknowledgements must be resolved by immutable operation lookup.
- A strong latest read must confirm the exact artifact and receipt after append.
- Restore must quarantine non-empty local state when the witness checkpoint is
  missing or its snapshot digest differs.
- This mapping does not itself implement provider append, external durability,
  or the Durable Object pending-intent/finalize/recovery state machine.
