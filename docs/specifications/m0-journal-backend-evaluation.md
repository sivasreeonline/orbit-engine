# M0 Host Journal Backend Evaluation

- Status: **PROPOSED — NOT APPROVED; no implementation authorized.**
- Scope: disposable M0 proof host's candidate-specific supervisor journal only.

Before implementation, use `docs/specifications/m0-supervisor-journal-implementation-contract.md` for the generation/fencing model, logical journal records, transaction ordering, watchdog failure domains, and recovery matrix. This does not approve SQLite or any host-specific backend.

- Related: `m0-runtime-proof-harness-design.md`, `m0-proof-resource-profile-v1.md`, `m0-host-preflight-and-proof-runbook.md`, ADR-0019.
- Decision owner: pending independent architecture and security review.

## 1. Decision summary

**Preferred candidate for the single-host M0 proof: SQLite in rollback-journal mode with `journal_mode=DELETE` and `synchronous=EXTRA`, behind one supervisor process and one serialized database writer.**

This is a candidate, not a locked decision. It must not be implemented or used for a host proof until the exact SQLite build, local filesystem, storage device, durability behavior, lock behavior, recovery procedure, and fault-injection results have been reviewed.

The choice is deliberately not SQLite WAL by default. The current M0 design requires one candidate-specific host supervisor to serialize all containerd access, not a multi-host journal or a high-concurrency read service. WAL's reader/writer concurrency therefore has no demonstrated M0 requirement, while it introduces a separate WAL file, shared-memory index, checkpoint lifecycle, and additional recovery/backup concerns. SQLite's `EXTRA` synchronous mode is specifically intended to add directory synchronization after rollback-journal deletion in DELETE mode; that is relevant to a durable host-side operation journal. Benchmark the candidate, but do not weaken durability settings to improve throughput.

If measured performance or operational requirements invalidate this candidate, reopen the decision. Do not silently switch to WAL, NORMAL/OFF synchronous mode, a network filesystem, or a remote database.

## 2. Decision boundary and alternatives

The journal is local host control-plane state. It is not the Sky High application database, a queue, an evidence store, or a place to persist student source code.

| Candidate | Strengths for M0 | Material risks / mismatch | Current disposition |
|---|---|---|---|
| SQLite, DELETE journal + EXTRA | ACID transactions and uniqueness/CAS in one local file; simple single-host deployment; no remote service dependency; EXTRA adds directory sync on journal deletion | Durability still depends on filesystem, kernel, device and truthful sync completion; filesystem/locking and power-loss behavior must be proven; single writer | Preferred candidate; unapproved |
| SQLite WAL + FULL | ACID durability in WAL mode with FULL; readers can proceed while a writer appends | Extra -wal/-shm lifecycle, checkpointing and checkpoint starvation; WAL requires same-host shared memory and is unsupported across network filesystems; no demonstrated need for concurrent readers; pin a fixed, reviewed SQLite version | Viable fallback only if a measured concurrency need justifies it |
| Custom append-only journal | Can make record format and fsync protocol explicit | Must correctly implement torn-write detection, checksums, framing, compaction, snapshots, indexes, replay, idempotency, concurrency and migrations; larger bespoke correctness burden | Reject for M0 unless SQLite is disproven |
| Remote PostgreSQL / managed database | Mature transactions, constraints, operational tooling, remote access | Adds network and remote-service availability to a host-local privileged safety boundary; host may be unable to reconcile or safely launch/clean up during outage; database lease alone cannot fence a paused process from containerd | Not selected for M0 host journal |
| Application database (Neon/MySQL) | Already relevant to product/control-plane data | Not a substitute for the host-local journal; network partition and control-plane availability must not determine whether the host can safely terminate/reconcile an existing sandbox | Explicitly out of scope |

The durable host journal must remain available to the host cleanup/recovery path even when the API, queue, Cloudflare control plane, evidence object store, or external network is unavailable. The journal stores only the minimum metadata needed for operation intent, reconciliation, ownership, state transitions and evidence references.

## 3. Required SQLite operating profile (proposed)

If SQLite is approved, the initial implementation must meet all of these conditions:

1. **Local storage only.** Place the database on a dedicated, root-owned local filesystem on the disposable VM. Do not use NFS, SMB, FUSE/network mounts, object storage mounts, or a shared volume mounted by multiple hosts. Record filesystem type, mount options, device identity, block/cache characteristics where available, and directory ownership/mode.
2. **Durability settings.** Require and verify `PRAGMA journal_mode=DELETE` and `PRAGMA synchronous=EXTRA` on every opened connection. Read back the effective values; fail startup if they differ. Do not rely on library defaults.
3. **One writer / one process.** The selected host supervisor is the only process allowed to open the journal for writes. Serialize all journal mutations through one writer path. Do not add a second supervisor, independent maintenance writer, external CLI writer, or background checkpoint process. Database locking is not the supervisor fencing mechanism.
4. **Kernel process lock is separate.** Before accepting work or making any candidate-approved containerd call, acquire a host-wide kernel lock using a stable lock file under a host-protected directory. Candidate A requires root ownership; Candidate B requires ownership by its dedicated non-root supervisor identity, with no runner/workload write access. Hold it for the entire supervisor process lifetime. Never unlink, rename, or recreate the lock file as a handoff technique. A replacement must not proceed until the old process has exited and released the kernel lock. Acquire a new durable generation and reconcile all non-terminal attempts before accepting work. If lock ownership is lost or cannot be proven, fail-stop. Prevent lock-FD inheritance by child processes.
5. **Transactions.** Use short, bounded transactions. Claim the idempotency key and logical attempt tuple, allocate the initial attempt_generation and operation_sequence, record supervisor_generation, and insert the operation ID and first operation intent atomically. Enforce uniqueness in the database, not only in application code. Use state-version compare-and-set updates; terminal results are immutable. Never hold a database transaction open while calling containerd, draining pipes, waiting for a process, publishing evidence, or performing network I/O.
6. **No exactly-once claim.** SQLite cannot atomically commit with containerd. Persist intent before each external side effect; after an uncertain result inspect actual host/containerd state and reconcile before retry. The protocol remains at-least-once with deterministic identities and idempotent recovery.
7. **Bounded database growth.** Set an explicit maximum journal size, free-space low-watermark and retention policy in a reviewed host profile. Do not delete active or audit-required records to recover space. If the database or filesystem reaches the limit, reject new work and quarantine the host; existing termination and cleanup must continue through an independent controller.
8. **No payloads or secrets.** Persist IDs, immutable request digests, approved profile/image digests, operation/trigger/state records, bounded response descriptors, measured timestamps/deadlines, cleanup/evidence dispositions, and opaque evidence references. Never persist student source, hidden tests, expected outputs, credentials, raw environment values, arbitrary stdout/stderr, or private artifact URLs in the journal.
9. **Migrations.** Version the schema. Migrations run only while holding the host lock, before accepting work, and must be transactional, backward-compatible with the documented recovery path, and tested with a copy of every supported prior schema. Unknown/newer schema versions fail closed.
10. **Integrity on startup.** Verify database identity, schema version, effective pragmas, file ownership/mode, and SQLite integrity before accepting work. Any corruption, malformed journal state, ambiguous migration, or failed recovery quarantines the host. Do not automatically delete, recreate, or repair a corrupt journal and then resume execution.
11. **Error handling.** Treat SQLITE_FULL, SQLITE_IOERR, SQLITE_CORRUPT, SQLITE_NOTADB, SQLITE_BUSY beyond a bounded policy, failed fsync/sync, and uncertain commit outcomes as fail-closed infrastructure conditions. Do not retry a possibly committed external side effect blindly. Re-open/reconcile by operation ID and canonical digest before deciding whether an intent committed. If a terminal commit response is lost, query the unique terminal row and matching attempt state; never issue a second insert or replace the committed result.
12. **Filesystem and hardware assumptions.** SQLite can only request synchronization; it cannot prove that the filesystem, kernel, hypervisor, controller, or storage device truthfully persisted the bytes. The exact disposable VM/storage configuration must pass abrupt power-loss and reboot tests. A successful process-kill test is not a power-loss durability test.

### 3.1 SQLite version floor

The SQLite WAL-reset corruption bug is not directly a reason to use WAL; it is a reason to pin and audit the SQLite library regardless of mode. The upstream SQLite documentation records the WAL-reset fix in 3.51.3 and later, and the 3.53.0 release notes also identify the fix. For any WAL-mode fallback, require a reviewed build at or above 3.53.0 and verify the exact source ID. For the proposed DELETE-journal profile, still use a maintained, security-reviewed SQLite release and record its exact version, source ID, package provenance and build configuration. Re-check upstream release/security notes at implementation time; do not assume this document's version floor is the newest release.

### 3.2 Why DELETE + EXTRA is the starting candidate

M0's journal is a low-volume, single-host state machine with a single host-supervisor writer. The design already requires serialization around containerd and durable intent/result transitions; it does not currently require multiple readers to proceed during writes. WAL's concurrency advantage therefore does not justify adding its WAL-index, checkpoint and multi-file backup/recovery surface as the default.

In DELETE mode, SQLite uses a rollback journal. EXTRA adds a directory sync after the rollback journal is unlinked during commit, beyond FULL's sync behavior. This is the strongest SQLite synchronous setting for this rollback-journal mode. The candidate still requires empirical validation on the exact host filesystem and storage stack. If the driver/runtime does not reliably apply EXTRA, or the target filesystem/storage does not pass abrupt power-loss testing, reject this candidate.

## 4. Minimum logical data model

The schema is a starting outline; it requires a separate reviewed migration and implementation design.

| Record | Required fields / constraints |
|---|---|
| `host_meta` | Schema version, host identity, durable supervisor generation, approved profile revision, last clean shutdown marker |
| `attempts` | Unique `(proof_run_id, fixture_id, attempt_id)`; canonical immutable request digest; authenticated owner; profile IDs/revisions and image digest; original API intake UTC timestamp and absolute end-to-end deadline; intake boot/clock metadata; deterministic sandbox identity; lifecycle state and state version; current `supervisor_generation` and `attempt_generation`; active operation ID; trigger-stream seal state (`trigger_stream_sealed`) and immutable `terminalization_trigger_watermark` once sealed; final output-accounting snapshot (`stdout_observed_bytes`, `stderr_observed_bytes`, `stdout_retained_bytes`, `stderr_retained_bytes`, `combined_retained_bytes`, overflow flags, final output disposition and finalized timestamp); terminal classification if committed. The trigger seal and final output snapshot are committed durably before terminal CAS; post-seal triggers are recorded as late incidents and cannot alter the watermark or output snapshot. |
| `idempotency_keys` | Unique key; canonical digest; operation_id; attempt identity; bounded response descriptor; committed state |
| `operations` | Unique operation_id; attempt_id; operation type; supervisor_generation; attempt_generation; operation_sequence; phase (`INTENT_DURABLE`, `DISPATCH_POSSIBLE`, `OBSERVED`, `COMPLETED`, `RECONCILIATION_REQUIRED`); expected state/version; desired state; deterministic external identity; immutable request digest; durable intent/dispatch/observation timestamps; observed outcome; completion disposition |
| `triggers` | Unique trigger_id; attempt_id; supervisor_generation; attempt_generation; trigger type/time; trigger_sequence; primary/secondary classification; immutable winner |
| `finalization_branches` | Unique (attempt_id, branch, branch_generation); explicit supervisor_generation and attempt_generation; branch_state_version; cleanup/evidence branch disposition; bounded error class; durable completion time |
| `terminal_results` | Unique immutable result per attempt (`attempt_id`); immutable terminal classification; terminal state version; winning trigger ID/cause; current supervisor/attempt generations; cleanup/evidence branch generations and state versions plus durable dispositions; sealed trigger watermark; final output disposition; terminal commit timestamp; bounded response descriptor digest. Insert exactly once; append-only; no update, upsert, replacement, or delete. |
| `evidence_references` | Attempt-scoped opaque object key/version, SHA-256, byte count and verification disposition; no raw content or private URL |
| `quarantine_records` | Host/attempt identity; quarantine reason and uncertainty class; originating supervisor/attempt generations; observed resource inventory; creation time; operator/recovery disposition; immutable evidence reference. Unresolved records are retained and prevent host readiness. |

Required database constraints include foreign keys, CHECK constraints for enumerated states/phases, unique keys for logical attempt and idempotency identity, a unique terminal_results.attempt_id, and conditional updates that succeed only when the expected state version and generation match. Terminal commit must insert the immutable terminal_results row and transition the attempt in one transaction; exactly one row of each operation must be affected or the transaction rolls back. Install database-level guards (for SQLite, reviewed triggers) that reject UPDATE and DELETE on terminal_results; never use INSERT OR REPLACE or UPSERT for terminal rows. A branch update must compare supervisor_generation, attempt_generation, branch_generation, and branch_state_version together. The application must check affected-row counts and treat zero/multiple unexpected rows as a conflict or corruption condition. Use strict typed values and bounded lengths; never build SQL from caller-provided identifiers. Every finalization-branch mutation must compare supervisor_generation, attempt_generation, branch_generation, and branch_state_version together in one conditional update; a stale owner or branch version is a conflict, never a last-write-wins update. Terminal commit must additionally compare the sealed trigger watermark, verify contiguous durable trigger records through that watermark, and require both current branch generations/state versions in the same transaction. Database-level guards must make `trigger_stream_sealed` monotonic (false to true only), require a non-null watermark at sealing, and reject later watermark changes; post-seal triggers are append-only late incidents. Output counters must be monotonic before finalization, retained bytes cannot exceed observed bytes, and `combined_retained_bytes` must equal retained stdout plus stderr. Setting `output_finalized_at` freezes the complete output snapshot exactly once; database-level guards reject later changes, and terminal commit requires that finalized snapshot.

## 5. Backup, restore and retention

- Use SQLite's Online Backup API (or an equivalently reviewed, quiesced snapshot procedure) to produce a consistent backup. Never copy only the main database file while it is live and assume that it includes the current committed state.
- Backups are not part of the live transaction path. They must not block cancellation, termination, cleanup, or deadline enforcement.
- Encrypt backups at rest if they leave the host; restrict access to the host/security operators; retain immutable version and checksum metadata.
- Test restore onto an isolated disposable host with the exact approved SQLite build and schema migration path. Verify integrity, record counts, unique constraints, generation state, and reconciliation behavior before the restored host can accept work.
- A restored database must never cause a second launch for an already-issued attempt. Reconcile every non-terminal attempt against actual host resources; if the original host state cannot be authoritatively inspected, quarantine rather than adopt.
- Define retention and secure deletion only after evidence/audit requirements are agreed. Never prune records for active attempts or unresolved cleanup/evidence branches.

## 6. Required fault-injection and acceptance matrix

All tests below are mandatory before approval. Test both process crash and abrupt VM power-off where applicable. Repeat across clean boot, unclean shutdown, filesystem recovery, and database restore. Capture the exact SQLite source ID, filesystem, mount options, VM image, storage device class and test harness revision.

| Fault | Required outcome |
|---|---|
| Kill supervisor before transaction commit | No partial intent; restart reconciles and does not launch |
| Kill supervisor immediately after commit but before response | Same idempotency key/digest returns the committed operation; no duplicate side effect |
| Hard power-off immediately after commit acknowledgement | After reboot, acknowledged intent/result is present; if not, candidate fails durability gate |
| Power-off during journal write, rollback, journal unlink or directory sync | Database recovers to a valid old or new transaction state; no ambiguous partial state is treated as success |
| Disk full during intent, completion, branch disposition and terminal CAS | No false acknowledgement; host quarantines; independent cleanup continues |
| SQLITE_BUSY / lock contention | Bounded behavior; no unbounded retry loop, duplicate side effect, or bypass of host lock |
| SQLITE_IOERR / failed sync | Fail closed; no success acknowledgement; reconcile uncertain commits before any retry |
| Database or journal corruption / invalid header | Host quarantines; no automatic recreation or execution |
| Interrupted schema migration | Restart either observes the complete old schema or complete new schema; never mixed/partially migrated state |
| Supervisor pause (SIGSTOP) then replacement attempt | Replacement cannot acquire the kernel lock or issue privileged calls while the old process still owns it |
| Supervisor crash after containerd create/start but before observed-result commit | Deterministic inspect/reconcile; no blind create/start retry |
| Trigger-seal/output-finalization/terminal-CAS race or crash | Reconcile a durable contiguous trigger stream through the immutable watermark, the final output-accounting snapshot, and each branch independently; post-seal events remain append-only incidents; one immutable terminal result only |
| Backup during concurrent journal activity | Backup is a consistent snapshot; source continues safely; backup integrity is verified |
| Restore from backup with non-terminal attempts | No duplicate sandbox; host remains quarantined until actual resource reconciliation is complete |
| Long-lived reader / maintenance task | No unbounded transaction or filesystem exhaustion; if WAL is ever selected, test checkpoint starvation and WAL growth explicitly |

**Acceptance rule:** no host proof or execution enablement until every mandatory fault test passes on the exact disposable host/storage stack, the results are independently reviewed, and the cleanup deadline is approved in the versioned resource profile. A passing SQLite unit test on a developer workstation is not sufficient.

## Host qualification execution record

The exact-host, provider-neutral sequence and deterministic test catalogue are defined in `docs/specifications/m0-host-and-journal-qualification-protocol.md`. Use `docs/schemas/m0-host-qualification-record.schema.json` and its blank template to record one host incarnation, exact backend/build/filesystem/storage identity, per-case injection/results, evidence references and independent review.

The protocol distinguishes storage-only SQLite candidate testing on an isolated scratch database from post-implementation integrated journal/lifecycle fault injection. Neither is authorized by this document or by CI; each requires its own disposable-host authorization and independent review.

## 7. Open decisions and blockers

The following are deliberately unresolved:

- Exact cloud provider, region, VM size, storage class and cost authorization.
- Exact local filesystem, mount options and storage write-cache/power-loss guarantees.
- SQLite library version/build source ID and Go driver/library choice.
- Database path, owner/mode, encryption-at-rest requirements and storage quota.
- Maximum database size, low-watermark, backup cadence, retention and restore RTO.
- Numeric cleanup deadline and its reboot/clock semantics.
- Independent security review of the candidate-specific host supervisor and kernel-lock boundary.
- Empirical power-loss, disk-full, corruption, lock-contention and recovery results.

No provider, VM, disk, paid service, package, database engine, or spend is authorized by this proposal.

## 8. References

- SQLite WAL documentation: https://www.sqlite.org/wal.html
- SQLite PRAGMA documentation (`synchronous`, `journal_mode`): https://www.sqlite.org/pragma.html
- SQLite corruption and filesystem-locking guidance: https://www.sqlite.org/howtocorrupt.html
- SQLite Online Backup API: https://www.sqlite.org/backup.html
- SQLite release 3.51.3 (WAL-reset fix): https://www.sqlite.org/releaselog/3_51_3.html
- SQLite release history: https://www.sqlite.org/changes.html
