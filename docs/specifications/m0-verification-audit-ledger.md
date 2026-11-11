# M0 verification audit ledger contract

The verification report produced by the evidence verifier is an in-process
result. This contract defines how a future caller can seal that result into a
hash-linked audit record and append it through a backend-neutral ledger port.

## Record and chain

Each record contains a monotonically increasing sequence, caller-provided
record ID, UTC/RFC3339Nano recording timestamp, full verification report,
previous-record SHA-256, and its own SHA-256. The digest is computed over the
typed JSON record with only its own digest field blank. Both successful and
failed verification decisions may be recorded.

The first record has sequence 1 and an empty predecessor digest. Every later
record must reference the exact digest of sequence N-1. Validation checks
sequence continuity, predecessor links, required identity fields, and each
record digest.

## Atomic append contract

A future durable adapter must implement `VerificationAuditLedger`. Its
`Append` operation must atomically compare the complete expected head and
append exactly one record, or append nothing. Concurrent writers using the
same expected head must yield at most one successful append; losers must
re-read the head and construct a new record. The adapter must not silently
rewrite, reorder, or replace an existing record.

The in-memory test fake exercises only the interface contract. It is not a
durable adapter, concurrency proof, tamper-resistant store, or backup system.

## Trust limitations and required external controls

A hash chain detects changed records and broken links when compared with a
trusted checkpoint. It cannot independently detect deletion of a valid suffix,
replacement of the entire chain with a new fork, or rollback to an older valid
prefix. Those attacks require independently retained checkpoints, protected
storage, external replication/transparency publication, and a separately
governed signing/key lifecycle.

This contract does not select a signing algorithm or key owner and does not
embed signing keys. It does not claim WORM/immutable storage, trusted time,
independent checkpoint custody, or deployment authority. Production use
requires a separately reviewed checkpoint-signing and retention design.
