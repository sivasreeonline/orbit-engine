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


## Scoped idempotency and replay protection

The `internal/idempotency` contract scopes a key by owner, client, and route. The journal stores only a canonical SHA-256 digest of the caller's key, the canonical request digest, the original attempt ID, and response-descriptor metadata; it must not store the raw idempotency key or raw response body.

The journal adapter must atomically claim the unique `(owner_id, client_id, route_id, key_digest)` tuple with the original attempt identity. A duplicate claim resolves as follows:

| Existing scoped key | Request digest | Resolution |
|---|---|---|
| No record | New request | Insert one claim and return CREATED |
| Existing record | Same digest, descriptor available | Return REPLAY with the original attempt and descriptor |
| Existing record | Same digest, descriptor not yet committed | Return PENDING with the original attempt; recover it, never create another |
| Existing record | Different digest | Return CONFLICT; preserve the original claim |
| Tombstoned record | Same digest | Return TOMBSTONE; response is unavailable and key remains reserved |
| Tombstoned record | Different digest | Return CONFLICT; key remains reserved |

A lost acknowledgement is recovered by reading the existing scoped claim. The adapter must not translate an uncertain insert/commit into a fresh attempt. The unique scoped-key constraint and attempt insertion must be one transaction, and a duplicate-key race must resolve by reading and classifying the winner.

A response descriptor is metadata only: version plus canonical digest. The adapter attaches it through an exact claim/request/attempt compare-and-set in the same durable transaction as terminal-result commitment; this is the only transition from PENDING to replayable. It may identify an immutable response artifact through a separately authorized mechanism, but this contract never retains the raw response body. Pruning response data must be an exact compare-and-set against scope, key digest, request digest, descriptor version, and descriptor digest. Pruning retains the claim and records a UTC tombstone timestamp. No key-reuse horizon is approved; therefore this contract has no expiry or key-reuse transition. Tombstones must not be deleted or recycled by ordinary retention cleanup.

The pure resolver returns REPLAY, CONFLICT, PENDING, or TOMBSTONE. PENDING is a recovery signal, not permission to dispatch a duplicate operation. A backend adapter must enforce all unique-key, transaction, and compare-and-set predicates durably; these validators alone do not provide idempotency or durability.

No database schema, adapter, response-body storage, retention worker, or endpoint integration is implemented by this contract.


## Atomic idempotency transaction boundaries

The journal port exposes two compound operations rather than requiring callers to coordinate independent claim and attempt writes:

- `ClaimIdempotentAttempt` accepts an `IdempotentAttemptCommand`. The adapter must atomically insert the unique scoped-key claim and its `REQUESTED` attempt, or insert neither. It must validate that claim owner, request digest, and attempt ID match the attempt record. A concurrent duplicate-key loser must read the winning claim and attempt inside a consistent transaction/snapshot and classify it as REPLAY, CONFLICT, PENDING, or TOMBSTONE. It must never return CREATED for a claim it did not insert.
- `CommitTerminalWithIdempotency` accepts the terminal-result command and response descriptor command. The adapter must atomically verify the attempt's current terminal fences, verify the persisted scoped claim still maps to that attempt and request digest, insert the immutable terminal result, attach the response descriptor, and transition the attempt to its terminal state. Any failed predicate rolls back all effects.

The adapter must treat uncertain commit acknowledgement as an unknown outcome, not as proof of rollback. The caller recovers by reading the scoped key and original attempt. If the record is absent after an authoritative read, only then may a new claim transaction be attempted; if the outcome remains uncertain, the caller must return a retryable/unknown result and must not dispatch a new attempt.

The port does not prescribe a specific isolation level or database primitive. A future backend must demonstrate equivalent behavior under concurrent same-key/same-digest and same-key/different-digest races, process termination at each transaction boundary, and lost commit acknowledgements. Tests against an in-memory fake are not evidence of database isolation or durability.


## Backend qualification and fault-injection contract

The package `internal/journal` contains a stable, backend-neutral catalog in `qualification.go`. It defines 25 acceptance scenarios across concurrency, atomicity, process crashes, acknowledgement loss, storage faults, corruption, recovery, backup/restore, and power-loss durability. Catalog validation checks stable unique IDs, category coverage, and explicit fault/invariant/evidence requirements.

The catalog is a specification and review aid only. It does not execute faults, test a storage adapter, or constitute evidence that a backend has passed. A future adapter qualification package must map every scenario ID to a reproducible backend-specific test, record the exact adapter version and storage configuration, preserve raw test output, and retain before/after durable-state snapshots where required.

### Mandatory acceptance principles

1. **Atomicity:** claim plus initial attempt is all-or-nothing. Terminal result, response descriptor, and terminal state are all-or-nothing.
2. **Unknown outcomes:** a lost acknowledgement is not rollback evidence. Resolve the original claim/attempt by authoritative read; never create a replacement attempt while outcome remains uncertain.
3. **Crash recovery:** terminate the process at each listed write/commit boundary and verify that restart yields a valid pre-commit or post-commit state, never a partial logical transaction.
4. **Storage faults:** disk-full, short-write, sync/fsync, checkpoint/WAL, and read-only failures must not be acknowledged as durable success.
5. **Corruption:** torn writes, checksum failures, missing immutable records, and inconsistent tombstones must be surfaced distinctly. Do not fabricate absence, silently repair identity, or permit workload dispatch.
6. **Backup and restore:** backups must represent a consistent transaction boundary. Restore qualification must prove scoped-key tombstones and reservations survive. A restored journal is not proof that predecessor hosts were fenced.
7. **Power-loss durability:** the adapter must declare its acknowledgement barrier and supported power-loss model. Every acknowledged commit must survive the declared failure model. The profile is a qualification input, not a default assumption; no backend or durability mode is selected here.

### Evidence required before an adapter can be enabled

- Completed scenario-to-test mapping for every `JQ-*` identifier, with no waivers hidden as skipped tests.
- Reproducible concurrency and fault-injection output from the actual selected backend, not an in-memory fake.
- Exact backend/driver versions, schema/migration revision, filesystem and mount configuration, sync/WAL/checkpoint settings, and host/storage topology.
- Raw crash/power-cut traces, recovery integrity reports, and durable-state snapshots.
- Backup manifest, consistency proof, restore test output, and tombstone inventory comparison.
- Independent review of the evidence package and explicit approval of the declared durability profile.

Until those conditions are met, the journal remains unconfigured for durable execution. This catalog does not authorize host deployment, privileged supervisor operation, or student workload execution.


## Machine-readable qualification evidence manifest

The schema at `docs/schemas/m0-journal-qualification-evidence.schema.json` defines the evidence package for a future journal adapter qualification. The Go model and validator live in `internal/journal/evidence_manifest.go`.

A manifest binds every catalog scenario to exactly one result record and requires:

- Exact adapter and driver names/versions.
- Operating system, kernel, architecture, filesystem, mount options, and storage topology.
- Explicit acknowledgement barrier, power-loss model, sync policy, and WAL/checkpoint policy.
- A unique test-run identifier, exact test command, RFC 3339 start/completion timestamps, and one or more evidence references per scenario.
- Relative evidence paths, SHA-256 digests, and media types; traversal and absolute paths are rejected.
- An independent-review status, reviewer identity, timestamp, and attestation reference.

The validator checks manifest structure and complete catalog coverage. `QualificationEvidenceReady` returns true only when every scenario is PASS and review status is APPROVED. FAIL, BLOCKED, and SKIPPED records may be structurally represented for audit, but none can satisfy readiness.

**Verification boundary:** this code does not read evidence files, recompute their hashes, verify cryptographic signatures, prove reviewer independence, or authorize deployment. Those require a separate evidence-verification process and trusted identity/key policy. The schema's 25-item array bound does not itself enforce unique IDs or exact catalog membership; the Go validator performs those checks. A manifest is evidence metadata, not evidence of its own truth.

No adapter or backend is selected by this work. No production qualification, host deployment, or workload execution is authorized.
