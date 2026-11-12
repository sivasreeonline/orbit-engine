# FENCE-001 restore and witness reconciliation reference model

**Status:** Test-only state-machine model; not a production restore implementation.  
**Purpose:** Make the post-restore comparison between authority state, protected verifier high-water, external witness high-water and independent monitor observations executable.

## Decision model

`scripts/validate_m0_witness_restore_reconciliation_model.py` models four outcomes:

- `RECONCILED`: restored authority, protected high-water, witness and monitors agree.
- `RECOVERED`: witness is ahead, but a complete contiguous checkpoint chain is available, independently verified and sufficient to deterministically replay authority state. This is not permission to admit hosts; the recovery commit and independent readback must still complete.
- `BLOCKED`: required external evidence is unavailable or a monitor has not caught up. No issuance or execution may proceed.
- `QUARANTINE`: contradictory or invalid state is observed, including rollback, digest fork, broken predecessor chain, invalid proof, unverified trust successor, stale revocation state, authority-ahead state or monitor equivocation.

## Invariants exercised

- The witness must not be behind the independently protected verifier high-water.
- Same-generation heads must have the same digest.
- A witness-ahead recovery chain must contain every generation exactly once and link each checkpoint to the exact predecessor.
- The chain must terminate at the witness's exact high-water digest.
- Checkpoint artifacts/signatures and deterministic state replay are separate required inputs.
- At least two monitors must have distinct identities, operators, accounts and failure domains; their heads must agree with the claimed latest witness head.
- Trust-bundle and revocation generations cannot roll back.
- Missing strong reads, proofs, revocation state or monitor catch-up block progress; contradictory evidence quarantines.

The model assumes its `VERIFIED` booleans/statuses were produced by independent provider, signature and proof verifiers. It does not implement those verifiers. It does not restore PostgreSQL, reconstruct real authority state, authenticate monitor identities, or test a real provider. Synthetic fixtures are not external evidence.

A successful `RECOVERED` model outcome means only that the modeled prerequisites are satisfied. The production procedure must keep admission disabled until the rebuilt authority transaction commits, the witness is re-read through the qualified strong-read path, independent monitors agree, and an independent reviewer accepts the evidence.
