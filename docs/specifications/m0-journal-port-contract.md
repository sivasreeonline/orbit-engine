# M0 Journal Port Contract

- Status: **Backend-neutral interface contract — no storage adapter selected or enabled.**
- Implementation: `services/execution-runner/internal/journal`.
- Governing design: `docs/specifications/m0-supervisor-journal-implementation-contract.md`.

## Purpose

The runner lifecycle needs a durable local journal, but the storage engine, driver, filesystem, durability mode, backup path, and host are still unapproved. This package defines the Go boundary without selecting SQLite or another backend.

The port is not a journal implementation. No process should report a durable acknowledgement until an independently qualified adapter implements and passes the transaction and host fault-injection requirements.

## Transaction contract

`Store.WithTransaction` provides one backend transaction:

1. Begin a transaction with the selected backend's approved isolation and durability settings.
2. Expose a transaction-scoped `Transaction` implementation to the callback.
3. Roll back on callback error or any validation/constraint failure.
4. Commit only after the callback returns nil.
5. Return nil only after the backend confirms successful commit under the configured durability contract.

A callback must not perform external side effects. Containerd calls, process control, evidence-object publication, network operations, and other non-transactional work must be represented as durable intent records and executed outside the database transaction using the prescribed reconciliation protocol.

## Operations and mandatory adapter behavior

| Port operation | Required adapter guarantee |
|---|---|
| `InsertAttempt` | Insert a new immutable logical attempt at `REQUESTED`, state version 1; enforce unique logical attempt identity and parameterized values |
| `CompareAndSwapAttempt` | Match expected state/version plus supervisor and attempt generations; apply only a contract-approved forward transition; verify exactly one affected row |
| `AppendTrigger` | Append immutable trigger identity and sequence; reject duplicate ID/sequence, stale generations, and invalid primary/secondary/late disposition |
| `SealTriggerStream` | Monotonically seal the stream once, bind the immutable watermark and final output snapshot, and reject any later watermark/output rewrite |
| `CompareAndSwapBranch` | Match supervisor generation, attempt generation, branch generation, and expected branch state version in one conditional update |
| `InsertOperation` | Insert the immutable operation identity and sequence at `INTENT_DURABLE` version 1 before any external side effect; enforce unique operation ID and `(attempt_id, operation_sequence)` |
| `CompareAndSwapOperation` | Advance only through the closed operation phase machine; match operation phase version and supervisor/attempt generations; reconciliation retries require authoritative exact-identity absence, original deadline, and current authorization |
| `CommitTerminal` | In one transaction, verify sealed contiguous triggers, frozen output, both current durable branch dispositions, and all generation/version fences; insert one immutable terminal result and transition the attempt from `FINALIZING` atomically |

Recovery reads must expose the exact operation record and enumerate all non-terminal operations for an attempt; recovery must inspect before retrying and must never create a new operation ID to hide uncertainty.

A zero-row compare-and-set is a conflict, not success. Unexpected multiple-row effects are corruption. The adapter must not use replace/upsert semantics for immutable terminal results.

## Command validation

The Go command validators reject incomplete identity, non-canonical SHA-256 digests, invalid UTC/deadline values, illegal lifecycle transitions, stale/missing generation values, invalid branch kinds/dispositions, trigger sequence misuse, unsealed output, inconsistent output counters, and terminal snapshots that do not match the requested transaction fences.

These are early boundary checks only. The adapter must repeat all mutable predicates inside its database transaction. In-memory validation cannot prevent races or establish durability.

## Error contract

- `ErrConflict`: expected state/version/generation no longer matches.
- `ErrNotFound`: referenced attempt or branch does not exist.
- `ErrCorrupt`: persisted data or a command violates an invariant; caller must not silently repair or reinterpret it.
- `ErrNotConfigured`: no qualified durable adapter is enabled.

A production adapter must preserve the distinction between conflict, missing data, corruption, and unavailable/unconfigured storage.

## Explicit exclusions

This contract does not select or install a database driver, open a journal file, create tables, configure filesystem permissions, acquire the supervisor kernel lock, implement migrations/backups, or prove crash/power-loss durability. No host or workload execution is authorized by this interface.


## External operation reconciliation

The `internal/operations` package defines the operation phases `INTENT_DURABLE`, `DISPATCH_POSSIBLE`, `OBSERVED`, `COMPLETED`, and `RECONCILIATION_REQUIRED`. A new operation is durably inserted as `INTENT_DURABLE` before external dispatch. The supervisor persists `DISPATCH_POSSIBLE` before making the external call.

A crash, timeout, lost response, daemon restart, or uncertain commit after dispatch moves the operation to reconciliation. The deterministic resource name is a bounded SHA-256-derived identifier over host instance, proof run, fixture, attempt, operation, request digest, and profile digest. The name is only a lookup key: reconciliation must independently inspect the resource and compare all immutable metadata and current generations.

A retry from `RECONCILIATION_REQUIRED` to `DISPATCH_POSSIBLE` is accepted only with an authoritative inspection proving the exact deterministic resource identity absent, current generations, the original deadline still valid, and the attempt still authorized. An exact resource found can be recorded as `OBSERVED`; ambiguous or conflicting state is rejected and must be quarantined by the supervisor. No phase transition may leave `COMPLETED`.
