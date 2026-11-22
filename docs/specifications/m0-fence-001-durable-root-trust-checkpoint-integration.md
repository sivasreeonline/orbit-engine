# FENCE-001 durable root-trust checkpoint integration

**Status:** Provider-neutral integration over the existing witness adapter contract. Synthetic CI only; no witness provider is selected or qualified.

## Problem closed

PR #177 requires an externally supplied expected generation and predecessor digest. A stateless caller could supply stale values. This integration obtains the high-water from the witness adapter's strongly consistent latest read and advances it with atomic compare-and-append.

## Acceptance flow

The new checkpoint command:

1. Resolves a witness scope from explicit trust-domain, witness, authority and host identifiers.
2. Checks for an exact prior operation to recover a lost acknowledgement. Exact replay is idempotent only while that checkpoint remains current.
3. Reads the durable witness head; genesis is generation zero and the all-zero digest.
4. Verifies the root signature, pinned root, trust domain, exact next generation, predecessor and manifest signer authorization against that head.
5. Appends one immutable checkpoint with a deterministic operation/idempotency key.
6. On ambiguous acknowledgement, reconciles by the same operation ID and exact checkpoint content.
7. Reads the operation and current head back; both must match the exact checkpoint and receipt.

The checkpoint digest is the root-signed trust bundle's canonical body digest. Scope includes trust domain, witness, authority and host. A concurrent successor race has one winner; a loser receives a conflict and must re-read/re-verify. The integration never chooses a fork.

## Storage and rollback boundary

The implementation reuses the existing provider-neutral witness interface and DynamoDB witness adapter's transactional immutable-generation, operation, idempotency and head records. The existing local DynamoDB conformance path can exercise the provider API shape. The in-memory CI fixture proves only integration logic; it is not durable.

A local JSON file, process memory, the authority database's ordinary restore domain, or a checkpoint copied from the bundle is not an acceptable high-water source. Production requires an independently protected witness whose atomic append, strongly consistent read, retention, restore and failure-domain properties have been externally qualified. Live AWS writes remain disabled absent the existing explicit disposable qualification approval.

## Recovery and failure behavior

- Crash before append: retry reads the same predecessor and may attempt the same successor.
- Commit followed by lost acknowledgement: retry finds the exact operation and returns the original receipt if still current.
- Different content under the same operation key: rejected.
- Stale predecessor, fork, generation gap or concurrent winner: rejected; no automatic branch selection.
- Missing operation readback, mismatched receipt, or latest-head mismatch: fail closed.
- Replay after a later successor: rejected as stale, even if the old signature remains valid.

## Production qualification gates

This integration is not proof of anti-equivocation. Production still requires independent monitor gossip, authenticated consistency/inclusion proofs, provider-specific semantics, durable high-water outside the authority restore domain, backup/restore and partition testing, independent operators/accounts/failure domains, trusted time and independent security review.

No production root, private key, AWS credential, live provider call, host execution or student-code execution is included. Production qualification remains false / required.
