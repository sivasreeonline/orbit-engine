# M0 Supervisor, Journal, and Watchdog Implementation Contract

- Status: **Design contract only — implementation not authorized.**
- Scope: M0 disposable-host proof harness; not the Sky High production execution service.
- Related: ADR-0019, `m0-runtime-proof-harness-design.md`, `m0-journal-backend-evaluation.md`, `m0-proof-resource-profile-v1.md`, and the M0 security review packet.
- Safety boundary: `UnconfiguredExecutor` remains the only runner executor. No containerd client, privileged supervisor, journal driver, queue consumer, public execution endpoint, host provisioning, or student workload is authorized by this document.

## 1. Purpose and decision status

This document turns the existing supervisor and journal proposals into a reviewable implementation contract. It resolves naming, transaction, generation, watchdog, and recovery ambiguities before any privileged code is written.

It does **not** approve the rootful supervisor ADR, SQLite, a Go SQLite driver, a filesystem, a cloud provider, a cleanup deadline, an evidence-finalization reserve, or a host. Those remain independent review and empirical gates.

### 1.1 Existing design direction

- The Go runner remains unprivileged and has no direct containerd socket access.
- If Candidate A is selected by an independently accepted ADR-0019 decision, one dedicated host supervisor is the only application principal permitted to issue rootful containerd operations. Candidate B must retain its separate dedicated non-root daemon/supervisor boundary.
- A local host journal is the intended source of truth for logical attempts and recovery, but SQLite DELETE journal + EXTRA remains an unapproved candidate.
- The 10-minute intake deadline, 60-second workload wall limit, cleanup deadline, and evidence/terminal-finalization reserve are distinct budgets. The cleanup deadline and finalization reserve remain unset pending Phase A evidence and review.
- Phase A calibration and Phase B full M0 proof remain separately authorized; neither authorizes student or production execution.

## 2. Non-negotiable invariants

1. One logical `(proof_run_id, fixture_id, attempt_id)` maps to at most one accepted attempt and one immutable terminal result.
2. The runner never receives rootful containerd authority, host paths, arbitrary OCI configuration, or a general command interface.
3. Every ordinary external side effect has a durable operation intent before it is issued; the observed result is inspected and committed after the side effect.
4. Termination is the deliberate exception to waiting for journal durability: capture the earliest host-observed trigger and request termination immediately. Journal persistence proceeds independently.
5. Repeated and secondary triggers never reset the original cleanup clock. If original trigger timing cannot be reconstructed after failure, the attempt is expired/quarantined, never granted a fresh cleanup interval.
6. Containerd and the journal are separate failure domains. There is no cross-system exactly-once transaction.
7. A stale supervisor or stale lifecycle worker cannot issue a privileged side effect or overwrite a newer branch disposition.
8. Cleanup and evidence finalization are independently supervised. Evidence failure never delays process termination or resource removal.
9. Terminal success requires durable, current cleanup and evidence dispositions, independent verification of all resource absence, and one durable terminal compare-and-set fenced by the current supervisor/attempt generations and both current branch generations.
10. Uncertain ownership, clock state, journal state, or cleanup means quarantine. Quarantine is not success and does not return the host to a ready pool.
11. The outer VM safety cutoff is containment only. Firing it invalidates the calibration sample and quarantines or destroys the VM; it is not proof of successful sandbox cleanup.
12. No numeric cleanup timeout or finalization reserve may be inferred from a developer workstation, average, percentile, or synthetic CI run.

## 3. Watchdog hierarchy and authority boundaries

The phrase **external watchdog** is too ambiguous for implementation. M0 must distinguish three roles. Their identities, failure domains, privileges, observed signals, and permitted actions are separate.

### 3.1 Per-attempt deadline and cleanup controller

**Owner:** the host supervisor's lifecycle subsystem, operating outside the gVisor sandbox and independently of the HTTP request/runner connection.

**Responsibilities:**
- Observe the host-side deadline, cancellation, output/resource breach, natural-exit final-drain outcome, and infrastructure trigger sources.
- Atomically capture the first host-observed termination trigger in a host-owned event arbiter, including event sequence, boot identity, and monotonic timestamp.
- Issue process-tree/cgroup termination immediately; do not wait for journal fsync, client acknowledgement, pipe EOF, evidence storage, or remote services.
- Reconcile and remove the workload process tree, containerd task/container, shim, namespaces, cgroup, scratch, temporary mounts, and attempt-scoped network-policy state.
- Run independent host-side absence checks and persist a cleanup disposition when the journal is available.

**Authority:** only the selected candidate's approved host supervisor may issue containerd lifecycle operations. Candidate A's supervisor is the sole rootful caller; Candidate B's supervisor must remain within its dedicated non-root daemon/user-namespace boundary. The controller may request only the five typed supervisor operations in the runtime harness design; it must not expose generic containerd, shell, file, OCI, or command APIs.

**Failure behavior:** if the journal is unavailable, the controller still issues termination and continues best-effort cleanup. It stops new admissions, marks the host/attempt unsafe for success, and requests supervisor recovery. If the original trigger or disposition cannot be reconstructed after restart, treat the cleanup budget as expired and quarantine. Never restart the cleanup interval.

### 3.2 Supervisor liveness and recovery watchdog

**Owner:** a separately supervised host service or equivalent independently reviewed host mechanism, not a goroutine, timer, request handler, or health check inside the supervisor process it monitors.

**Responsibilities:**
- Monitor a bounded supervisor heartbeat and the age of in-flight host operations using a read-only, bounded status channel.
- Detect process exit, missed heartbeat, deadlock/pause, expired operation progress, or inability to reconcile the host journal.
- Request fail-stop of the exact supervisor service instance and allow the operating system to release its kernel process lock before a replacement may proceed.
- The watchdog may control only one preconfigured supervisor systemd unit through narrowly scoped service-manager authorization (for example, a polkit rule limited to `StopUnit`/`StartUnit` for that exact unit). It must not invoke `systemctl` through a shell, accept a unit name from a request, manage arbitrary units, edit unit/drop-in files, change properties, or invoke generic commands.
- Pin and verify the supervisor unit identity before each action: unit name, unit-file/drop-in digests, executable digest, configured UID/GID, expected cgroup path, boot ID, and service-manager instance. Stop/restart decisions must use the exact unit and cgroup identity, not a reusable PID or process name. Any mismatch is an integrity failure: stop admission and escalate to the outer VM watchdog.
- Require the service manager to terminate the complete supervisor cgroup and independently prove process exit and kernel-lock release before starting one replacement. The host-specific plan must pin and test `KillMode`, stop escalation behavior, start limits, restart policy, and timeout settings; implicit automatic restart must not race the watchdog's recovery decision.
- Permit one replacement supervisor to acquire the host lock, allocate a new supervisor generation, and reconcile every non-terminal attempt before accepting new work.
- Escalate to the outer VM safety watchdog if the supervisor cannot be stopped/replaced safely or if the recovery path cannot establish ownership and deadlines.

**Prohibited authority:** it must not become a second unrestricted containerd caller, a generic root command broker, an alternate journal writer, or a bypass around the host lock. Any narrow authority required to stop/restart the named supervisor service must be explicitly enumerated and independently reviewed. It must not mutate attempt terminal results.

**Failure behavior:** if the watchdog itself is unavailable, cannot prove supervisor ownership, or cannot perform bounded recovery, no new work is admitted. The outer VM safety watchdog is the final containment authority. A watchdog restart does not prove cleanup and does not reset any attempt deadline.

### 3.3 Outer VM safety watchdog

**Owner:** a control plane, hypervisor, or other mechanism outside the disposable VM's supervisor/journal/containerd failure domain.

**Responsibilities:** enforce the separately approved outer VM CPU, memory, PID, disk, and wall-time safety envelope; isolate, stop, or rebuild the disposable VM if the in-VM recovery path is no longer trustworthy.

**Prohibited interpretation:** a VM hard-stop is not successful cleanup of an individual sandbox. A fired cutoff produces a failed/unverified calibration sample, host quarantine/destruction, and no terminal-success acknowledgement.

**Open deployment dependency:** the provider/control-plane mechanism cannot be selected until the host/provider decision is approved. No provider, region, VM size, or spend is selected here.

### 3.4 Supervisor socket authentication and authorization

The private Unix-domain socket is an authentication boundary, not merely a local transport choice. Before implementation, the host-specific plan must freeze the socket type/framing, path, service identity, runner identity, and kernel credential mechanism.

- Place the socket below a directory that the selected supervisor identity controls and that the runner/workload cannot write, rename, mount over, or traverse through a symlink. Candidate A requires a root-owned directory; Candidate B must prove an equivalent protected publication mechanism for its dedicated non-root service identity (for example, a reviewed service-manager socket-activation arrangement). If that boundary cannot be established without granting the runner directory-write access, Candidate B fails this control. Validate the directory chain without following symlinks and pin the expected device/inode identity for the service lifetime.
- At bind and before accepting connections, verify the socket is the expected socket inode with the approved owner, group, and mode. Refuse startup or stop admission if the path is replaced, the parent identity changes, or permissions drift. Do not unlink an unexpected path as an automatic recovery action.
- Authenticate every accepted connection from kernel-supplied peer credentials (Linux SO_PEERCRED or an independently reviewed equivalent). Compare the exact configured runner UID and GID; do not trust UID/GID, role, or service-name fields supplied in the request. Filesystem permissions are defense in depth, not a substitute for per-connection peer authentication.
- After peer authentication, authorize each operation against the durable proof-run, fixture, attempt, profile, deadline, and idempotency records. Authentication does not imply authorization for an arbitrary attempt.
- Bound framing, message bytes, concurrent connections, per-operation duration, and queued work. Reject malformed UTF-8/JSON, duplicate decoded keys, unknown fields, trailing bytes, and unexpected ancillary data/file descriptors. Never pass received descriptors or caller-controlled paths to containerd.
- Keep the runner outside every group that grants containerd access. The supervisor socket must not be mounted or exposed inside a guest workload. No TCP listener, generic RPC proxy, shell, or arbitrary command operation is permitted.
- Test unauthorized UID/GID, same-UID wrong-attempt, stale attempt, socket replacement, symlink substitution, permission drift, malformed framing, descriptor passing, connection floods, and service restart behavior on the exact host.

The host qualification record must retain sanitized socket path/inode/owner/mode observations, the configured peer identity, negative authorization results, and the exact service/configuration digests. Never record secrets or raw privileged process environments.

### 3.5 Failure-domain matrix

| Failure | Per-attempt cleanup controller | Supervisor recovery watchdog | Outer VM safety watchdog | Required disposition |
|---|---|---|---|---|
| Runner/client disconnect | Continues independently | No action unless supervisor unhealthy | No action | Same attempt remains owned; no implicit cancel |
| Evidence store unavailable | Continues termination/removal | No action unless supervisor blocked | No action | Cleanup may succeed; evidence incomplete; never passed |
| Journal BUSY/FULL/IOERR | Issues termination; bounded journal retry only off cleanup path | Detects failure/stall; stops new work and recovers supervisor if needed | Escalates only if in-VM recovery fails | Quarantine if durable state/trigger cannot be reconciled |
| Supervisor SIGSTOP/deadlock | Cannot assume in-process progress | Uses exact pre-authorized service-manager unit action; verifies unit/cgroup identity, complete cgroup exit and lock release before one replacement | Stops/rebuilds VM if safe replacement cannot be established | No fresh deadline; reconcile or quarantine |
| Supervisor unit file, executable or cgroup identity changes | Treat as host-integrity failure | No start/restart on an unverified identity; no generic service-manager action | Stops/rebuilds VM | Admission stopped; host quarantined |
| Watchdog service-manager authorization fails or watchdog is unavailable | No in-VM recovery authority is assumed | No alternate shell/systemctl/root-broker path | Outer VM safety watchdog | VM stopped/rebuilt; no replacement supervisor |
| Supervisor SIGKILL/crash | Existing workload may remain until replacement reconciles | Starts replacement only after old process exits and releases lock | Final containment if replacement cannot recover | Inspect actual resources; never blind create/start |
| Containerd unavailable | Attempts safe termination through available host controls; no false absence claim | Restarts/reconciles supervisor after daemon recovery | Contains VM if host state is unsafe | Stop new launches; quarantine ambiguous resources |
| Host suspend/resume | Original elapsed budget must include suspend | Re-arm using approved suspend-aware clock and original trigger | Enforces outer wall limit | Expired/uncertain deadline means quarantine |
| VM reboot/snapshot restore | Old-boot monotonic value is not reused | Requires trusted clock + host incarnation + journal reconciliation | Stops/rebuilds if identity/clock trust is uncertain | Expire budget and quarantine if not reconstructible |

**Acceptance gate:** the concrete OS/service mechanism, exact unit allowlist, service-manager authorization, unit/executable/cgroup digests, identities, privileges, heartbeat format, stop/restart action, kill/timeout/restart policy, lock-release proof, and outer hard-stop interface must be named in the host-specific implementation plan and reviewed before privileged implementation. The watchdog must have no generic root command or containerd authority.

## 4. Identity, generation, and fencing model

Do not overload one `generation` field. The following values have different owners and lifetimes.

| Value | Scope | Allocated by | Changes when | Enforced by |
|---|---|---|---|---|
| `host_instance_id` | One disposable VM incarnation | Trusted provider/control-plane enrollment; never caller-supplied | New VM incarnation or restore that cannot prove continuity | Host identity verification and evidence manifest |
| `host_incarnation_epoch` | Monotonic anti-rollback/fencing epoch for one enrolled VM incarnation, anchored outside the guest journal | Trusted external control-plane/host-enrollment authority after it has fenced or powered off every prior incarnation/clone | Every restore, clone, rollback, or replacement that could duplicate or roll back guest state | External epoch proof plus provider-level old-incarnation stop/fence; guest journal value alone is insufficient |
| `supervisor_generation` | One supervisor process ownership epoch on a host instance | Supervisor after acquiring the exclusive host lock and validating the current external host-incarnation epoch | Every accepted supervisor replacement/restart | Host lock + journal CAS + external epoch self-check |
| `attempt_generation` | Ownership/recovery epoch for one logical attempt | Current supervisor under journal transaction | Attempt ownership is transferred during restart/reconciliation | Attempt row CAS; checked on every operation |
| `operation_sequence` | Ordered operations within one attempt | Journal transaction | Every newly claimed lifecycle operation | Unique `(attempt_id, operation_sequence)` and operation ID |
| `state_version` | Attempt state row | Journal transaction | Every accepted state transition | Compare-and-set expected version |
| `branch_generation` | One cleanup or evidence branch | Journal transaction | Branch ownership is reclaimed/restarted | Branch-specific compare-and-set |
| `trigger_sequence` | Host-observed trigger stream for one attempt | One host-owned event arbiter | Each accepted trigger observation | Atomic event ordering and immutable trigger records |

All values are distinct from the immutable external `attempt_id`, `operation_id`, `trigger_id`, and `correlation_id` identifiers.

### 4.1 Ownership handoff

1. The supervisor must acquire a stable kernel process lock before opening the journal for writes or issuing any candidate-approved containerd operation. Candidate A requires a root-owned lock file; Candidate B requires a lock file owned by its dedicated non-root supervisor identity in a directory the runner/workload cannot modify. The selected owner, path, permissions, and kernel primitive must be qualified for the exact candidate.
2. A replacement must not start privileged work until the previous supervisor process has exited and the kernel has released the lock. A database lease alone is not a fence against a paused process.
3. After lock acquisition, the replacement validates host identity, boot identity, journal identity/schema/durability settings, and the last committed generation.
4. In one durable transaction, allocate a new `supervisor_generation`, then reclaim each non-terminal attempt by incrementing its `attempt_generation` and the affected branch generations using expected-version compare-and-set.
5. Before every external side effect, the supervisor verifies the host lock, current supervisor generation, current attempt generation, operation sequence, expected state/version, and deterministic resource identity.
6. An old process or worker that observes lock/generation mismatch must fail-stop before any further side effect or journal mutation.
7. If a restored/replicated VM cannot prove a unique trusted `host_instance_id`, it is not eligible to accept work. A restored journal does not itself prove host incarnation or fencing.

Do not claim that an arbitrary generation integer fences containerd. Containerd does not consume this application generation; exclusivity must be proven at the host process/lock boundary.

### 4.2 Stable kernel lock-file contract

The lock is the exclusion primitive for the selected supervisor's containerd lifecycle authority. A database lease, PID file, heartbeat, or generation integer is not a substitute.

- Use one fixed lock-file path below a host-protected directory that untrusted users and workloads cannot modify. Candidate A uses a root-owned directory/file. Candidate B uses a dedicated non-root supervisor-owned directory/file, with no runner or workload write access. The host-specific plan must select and document the exact Linux kernel lock primitive and its process/descriptor semantics before implementation; do not silently switch primitives.
- Open the file relative to a trusted directory descriptor with no-follow semantics and close-on-exec. Require a regular file, the candidate-approved owner (root for Candidate A; dedicated supervisor UID for Candidate B), restrictive mode, and exactly one hard link. Reject symlinks, device changes, unexpected link counts, ownership/mode drift, and path substitution.
- Never unlink, rename, or recreate the lock file as a handoff mechanism. Record and verify its device/inode identity. A replacement must open and lock the same stable inode; a new inode is a host-integrity failure requiring quarantine.
- Hold the kernel lock for the entire lifetime of the selected supervisor's containerd lifecycle authority. The supervisor must not fork after acquiring it. Lock descriptors must not be inherited by helper processes; use close-on-exec and verify descriptor ownership/closure for every child-launch path.
- A replacement may proceed only after the old supervisor has exited and the kernel has released the lock. A watchdog must identify and stop the exact service instance using a reviewed service-manager/cgroup identity, not a reusable PID alone; it must independently establish process exit and lock availability before restart.
- Before every privileged side effect, revalidate lock ownership and the pinned lock-file identity together with current supervisor and attempt generations. Loss or uncertainty causes immediate fail-stop, admission stop, and quarantine; it must never trigger automatic lock-file repair.
- Qualification must inject pause/SIGSTOP, SIGKILL, abrupt process crash, child-process descriptor inheritance, lock-file replacement, symlink substitution, and concurrent replacement attempts. Evidence must prove that no two live processes can issue privileged operations concurrently.

The lock primitive, service-manager stop/restart authority, and exact host filesystem semantics remain implementation gates; this contract does not select them or claim they have been tested.

## 5. Lifecycle state and trigger contract

### 5.1 Attempt states

Use a closed, versioned state enumeration. The exact result classification is separate from lifecycle state.

| State | Meaning | Allowed next states |
|---|---|---|
| `REQUESTED` | Authenticated logical attempt accepted | `VALIDATING`, `REJECTED`, `EXPIRED` |
| `VALIDATING` | Authorization, profile, digest, and budget checks | `QUEUED`, `REJECTED`, `EXPIRED`, `QUARANTINED` |
| `QUEUED` | Admitted but no sandbox resource created | `CREATING`, `EXPIRED`, `REJECTED`, `QUARANTINED` |
| `CREATING` | Durable create intent exists; resource creation/reconciliation in progress | `STARTING`, `TERMINATING`, `FINALIZING`, `QUARANTINED` |
| `STARTING` | Durable start intent exists; workload start/reconciliation in progress | `RUNNING`, `TERMINATING`, `FINALIZING`, `QUARANTINED` |
| `RUNNING` | Host observed workload start | `TERMINATING`, `FINALIZING`, `QUARANTINED` |
| `TERMINATING` | First trigger captured; termination/cleanup initiated | `FINALIZING`, `QUARANTINED` |
| `FINALIZING` | Cleanup and evidence branches execute independently | Terminal state only after both dispositions durable; `QUARANTINED` on uncertainty |
| `QUARANTINED` | Host/attempt cannot safely continue or claim cleanup success | Operator-controlled reconciliation only |

Terminal classifications are immutable and include the applicable student result or infrastructure result. Infrastructure states such as cleanup failure, host failure, evidence incomplete, and expiry must never be remapped to a successful student verdict.

### 5.2 Trigger arbitration

- All trigger sources feed one host-owned arbitration point. The arbiter captures a strictly ordered `trigger_sequence`, `CLOCK_BOOTTIME` value, boot ID, UTC audit timestamp, authenticated source, and trigger type before requesting termination.
- The first arbiter-accepted termination trigger fixes the immutable primary cause. Later triggers are retained as secondary causes; they never overwrite the primary cause.
- The cleanup deadline anchor is the earliest accepted host-observed trigger timestamp, not the later journal commit, client acknowledgement, pipe EOF, evidence write, or containerd response.
- For an attempt in `CREATING`, `STARTING`, or `RUNNING`, the winning trigger and its corresponding transition to `TERMINATING` are one serialized arbitration decision. These are the only resource-bearing states that enter the cleanup-controller termination path. An attempt still in `REQUESTED`, `VALIDATING`, or `QUEUED` has no authorized create intent; a pre-create cancellation/deadline must resolve through the existing `REJECTED` or `EXPIRED` admission outcome and must not fabricate cleanup work. If create dispatch may already have occurred, the attempt is in `CREATING` and must use the termination/reconciliation path. If trigger ordering cannot be proven because the arbiter or clock is unavailable, the attempt is quarantined and its cleanup budget is treated as expired.
- Termination is requested immediately after capturing the trigger. The request must not wait for a journal write or remote call.
- Trigger persistence is attempted asynchronously and durably. If it fails, the controller still cleans up, new admissions stop, and the host is quarantined. If recovery cannot reconstruct the exact trigger anchor, the budget is expired; no new interval is granted.
- Natural exit is provisional until descendants are gone, stdout/stderr drain is complete or boundedly failed, final output counters are reconciled, and any late policy breach is durably retained.
- A cancellation arriving after natural exit has been observed or after finalization begins is late and cannot rewrite the primary cause or terminal result.
- A policy/output breach observed during mandatory final draining remains sticky and prevents success even if the direct child exited earlier.

### 5.3 Cleanup and evidence branches

Each branch has its own generation, owner, state, timestamps, bounded error classification, and durable disposition.

Cleanup success requires independently verified absence of the process tree, containerd task/container, shim, namespaces, cgroup, scratch, temporary mounts, and attempt-scoped network-policy state. Evidence success requires immutable objects and the final manifest to be published, read back, hashed, and independently verified.

Neither branch waits for the other to start or progress. A terminal compare-and-set is permitted only after both branch dispositions are durable and current. A successful terminal classification additionally requires both dispositions successful. Any failed, timed-out, stale, or uncertain branch is incomplete/infrastructure-failed and quarantined.

## 6. Journal logical schema contract

The journal is a local host control-plane record store. It is not the Sky High application database, queue, evidence object store, or a place to persist source code, hidden tests, credentials, raw output, environment values, or private URLs.

The following logical records are mandatory regardless of the backend. They are a schema contract, not executable DDL.

| Record | Required fields and invariants |
|---|---|
| `host_meta` | Schema version; trusted host instance ID; boot ID; current supervisor generation; approved host/profile/journal configuration digests; last clean shutdown marker; quarantine state and reason. |
| `attempts` | Unique `(proof_run_id, fixture_id, attempt_id)`; canonical immutable request digest; authenticated owner; profile IDs/revisions and image digest; original API intake UTC timestamp and absolute end-to-end deadline; intake boot/clock metadata; deterministic sandbox identity; lifecycle state and state version; current `supervisor_generation` and `attempt_generation`; active operation ID; trigger-stream seal state (`trigger_stream_sealed`) and immutable `terminalization_trigger_watermark` once sealed; final output-accounting snapshot (`stdout_observed_bytes`, `stderr_observed_bytes`, `stdout_retained_bytes`, `stderr_retained_bytes`, `combined_retained_bytes`, overflow flags, final output disposition and finalized timestamp); terminal classification if committed. The trigger seal and final output snapshot are committed durably before terminal CAS; post-seal triggers are recorded as late incidents and cannot alter the watermark or output snapshot. |
| `idempotency_keys` | Unique scoped idempotency-key digest; canonical request digest; attempt and operation IDs; bounded versioned response descriptor; current durable disposition. Same scope/key + same digest returns the same logical operation; changed digest is a conflict. |
| `operations` | Unique operation ID; unique `(attempt_id, operation_sequence)`; host/attempt generations; operation type; phase (`INTENT_DURABLE`, `DISPATCH_POSSIBLE`, `OBSERVED`, `COMPLETED`, or `RECONCILIATION_REQUIRED`); expected prior state/version; target state; deterministic external resource identity; immutable request digest; durable intent/dispatch/observation timestamps; observed external result; bounded error class; completion disposition. |
| `triggers` | Unique trigger ID; attempt ID; explicit `supervisor_generation` and `attempt_generation`; trigger sequence; trigger type; authenticated source; boot ID; BOOTTIME observation; UTC audit timestamp; primary/secondary/late disposition; termination-request timestamp; durable persistence disposition. |
| `finalization_branches` | Unique `(attempt_id, branch, branch_generation)`; branch kind `cleanup` or `evidence`; current `supervisor_generation`; current `attempt_generation`; `branch_generation`; branch state version; state; disposition; bounded error class; start/completion timestamps; independent verification reference. |
| `terminal_results` | Unique immutable result per attempt (`attempt_id`); immutable terminal classification; terminal state version; winning trigger ID/cause; current supervisor/attempt generations; cleanup/evidence branch generations and state versions plus durable dispositions; sealed trigger watermark; final output disposition; terminal commit timestamp; bounded response descriptor digest. Insert exactly once; append-only; no update, upsert, replacement, or delete. |
| `evidence_references` | Opaque attempt-scoped object key/version; SHA-256; byte count; evidence-root ID; `acquired_by_id` principal; independent verifier ID; verification status/time/note; redaction disposition. The acquirer, verifier, host owner and security reviewer are distinct principals. No raw content or private URL. |
| `quarantine_records` | Host/attempt identity; quarantine reason code; observed resources/uncertainty class; originating `supervisor_generation` and `attempt_generation`; timestamp; operator/recovery disposition; evidence reference. Never delete unresolved quarantine records during ordinary retention. |

### 6.1 Required database constraints

- Primary keys on every logical record and foreign keys from child records to the authoritative attempt/host records.
- Unique constraint on logical attempt identity `(proof_run_id, fixture_id, attempt_id)`.
- Unique constraint on scoped idempotency key digest and unique operation ID.
- Unique `(attempt_id, operation_sequence)` for operation order.
- Unique trigger ID and unique trigger sequence within an attempt.
- Unique `(attempt_id, branch, branch_generation)` and unique terminal result per attempt.
- CHECK constraints for every state, operation, trigger, branch, disposition, and error-class enumeration.
- Bounded lengths and canonical encoding for all IDs, digests, object references, and response descriptors.
- Foreign-key enforcement and transaction isolation verified on every connection; effective database durability settings read back at startup.
- Trigger-stream sealing is monotonic: `trigger_stream_sealed` may transition only from false to true; sealing requires a non-null watermark; the watermark is immutable afterward; and terminal CAS verifies every trigger sequence through it is present exactly once. Post-seal triggers are appended only as late incidents.
- Output accounting is monotonic before finalization: observed/retained counters cannot decrease, retained bytes cannot exceed observed bytes, and `combined_retained_bytes` must equal the sum of retained stdout and stderr bytes. Setting `output_finalized_at` freezes the complete output snapshot exactly once; database-level guards reject later changes. Terminal CAS requires that finalized snapshot.
- All state changes use expected state version and generation predicates. A finalization-branch mutation must compare the current `supervisor_generation`, `attempt_generation`, `branch_generation`, and expected branch state version in one conditional update. The implementation checks affected-row counts; zero or unexpected multiple rows are conflicts/corruption, not success.
- Indexes support lookup by logical attempt, idempotency scope/key digest, operation ID, deterministic sandbox identity, non-terminal attempts, pending branch dispositions, and quarantine state.
- SQL identifiers are constants from the implementation. Caller-controlled values are parameters only; caller input never constructs SQL, table names, or query fragments.

### 6.2 Retention and backup invariants

- Active attempts, non-terminal operations, unresolved branches, terminal results needed for idempotency, and unresolved quarantine records cannot be pruned.
- Backup/restore runs outside the cleanup critical path. Use the backend's reviewed consistent snapshot API; do not copy a live database file and assume it is consistent.
- A restored journal does not authorize work. The host remains quarantined until host identity, schema, integrity, generation, and all non-terminal attempts are reconciled against actual resources.
- A corrupt or unknown/newer schema fails closed. Do not automatically delete, recreate, or “repair” a journal and resume execution.
- Exact journal size ceiling, free-space low-watermark, separately protected cleanup/containment reserve, backup target capacity/cadence, retention duration, secure-deletion method, and restore RTO remain open until a host/storage profile is approved. The cleanup reserve must not be allocatable to journal, evidence staging, logs, or backup growth; size it from measured worst-case cleanup/reconciliation/quarantine needs. Low-watermark or reserve pressure stops new admission; hard-capacity exhaustion quarantines the host. Cleanup and outer containment must remain operable without journal writes. No emergency pruning, live VACUUM, or ad-hoc journal manipulation is permitted.

## 7. Transaction boundaries and side-effect ordering

### 7.1 Admission and create/start operations

1. Authenticate peer identity and authorize the exact proof run, fixture, attempt, immutable profile, and operation.
2. Validate the canonical request digest and original intake deadline. Do not accept caller-supplied timestamps, cleanup deadlines, resource limits, OCI settings, or host resource names.
3. In one short durable transaction, claim the scoped idempotency key, claim the logical attempt, allocate the operation ID and operation sequence, record the current supervisor/attempt generations, verify the expected state/version, and insert the first operation intent.
4. Commit the transaction before any create/start side effect. Do not hold a transaction open while calling containerd, waiting on a process, draining pipes, publishing evidence, or using the network.
5. Issue the typed external operation using deterministic supervisor-owned resource identity and fixed root-owned profiles.
6. Inspect actual host/containerd state independently; do not infer success from a command return or in-memory callback.
7. In a second short transaction, persist the observed result and completion disposition using the expected state version and all current generations.
8. Acknowledge only after the relevant journal transition and bounded response descriptor are durable.

### 7.2 Immediate termination exception

Termination cannot wait for journal fsync. The required order is:

1. Capture the earliest host-observed trigger at the single host-owned arbiter, including BOOTTIME, boot ID, trigger sequence, authenticated source, and cause.
2. Immediately issue complete workload termination through the cleanup controller.
3. Concurrently attempt to persist the trigger record, primary/secondary classification, transition to `TERMINATING`, and cleanup-branch intent. Do not block process termination on this transaction.
4. If journal persistence fails, keep terminating, stop new admission, signal the independent supervisor recovery watchdog, and quarantine the host/attempt. Do not acknowledge success.
5. On recovery, reconcile the original trigger anchor from durable trigger data or the independently retained watchdog incident evidence. If the original anchor cannot be proven, treat the cleanup budget as expired and quarantine; never grant a new cleanup interval.
6. Persist verified cleanup disposition when the journal is healthy again. If it cannot be made durable, the host stays quarantined even if resources appear absent.

This exception is limited to beginning termination and best-effort cleanup. It is not permission to skip durable branch disposition, terminal compare-and-set, or independent absence verification.

### 7.3 Containerd operation reconciliation

Every create/start/stop/delete operation follows a durable phase machine: `INTENT_DURABLE` is committed before dispatch; `DISPATCH_POSSIBLE` is committed before making the external call; `OBSERVED` records independently inspected host/containerd state; `COMPLETED` records the verified result. A crash, timeout, lost response, daemon restart, or uncertain journal commit from `DISPATCH_POSSIBLE` onward moves the operation to `RECONCILIATION_REQUIRED` on recovery.

- Reconcile by deterministic supervisor-owned identity containing the trusted host-instance ID, proof-run/fixture/attempt IDs, operation ID, immutable request digest, and approved profile/image digests. Verify those values against containerd metadata and independent host observations; a caller-selected name or guest-controlled label is never ownership proof.
- Inspect containerd object, task, shim, process tree, cgroup, namespace, mount, and network-policy state as applicable. A partial or conflicting resource set, mismatched digest/generation, unknown owner, or uninspectable daemon is ambiguous and requires quarantine; never adopt it.
- If the exact intended resource exists, persist the observed result and reattach only when the complete identity and current generations match. Do not issue a second create/start.
- Retry the same logical operation only after authoritative inspection proves the intended resource absent, the same operation remains authorized and within its original deadline, the attempt is non-terminal/non-quarantined, and the current supervisor/attempt generations and operation sequence still match. Reuse the same operation ID and deterministic identity; never create a new logical attempt to mask uncertainty.
- A start operation may attach to an already-running exact owned task, but must never issue a second start. A delete/stop retry must verify absence or continue idempotent cleanup; it must not erase journal, trigger, or evidence records.

### 7.4 Terminal-result commit and immutability

The host-owned trigger arbiter serializes final output-drain completion and the decision to seal terminalization. It records a durable `trigger_stream_sealed` marker and `terminalization_trigger_watermark` for the attempt. Every arbiter-accepted trigger at or below that watermark must be durably persisted and reconciled before terminal commit. Events observed after the seal are retained as late incident events and cannot rewrite the result; a post-seal policy/integrity breach invalidates the proof run and quarantines the host through a separate append-only incident record, never by mutating the terminal result.

The terminal commit is one short journal transaction. Its conditional predicate must verify: the attempt is `FINALIZING` at the expected state version; current `supervisor_generation` and `attempt_generation` match; the trigger stream is sealed and every sequence through the watermark is present; final output counters/disposition are durable with no success-disqualifying breach; both cleanup/evidence branches are current at their expected `branch_generation` and branch state versions with durable dispositions; no unresolved operation or quarantine condition remains; and the terminal classification is consistent with those dispositions. Success additionally requires both branches successful and independent absence/evidence verification complete. A fully known failure may commit only a non-success infrastructure classification; unresolved or uncertain state remains quarantined without a success result.

In that same transaction, insert exactly one `terminal_results` row under a unique attempt constraint and conditionally transition the attempt to its terminal lifecycle state/result pointer. Require exactly one inserted row and exactly one affected attempt row; any conflict rolls back the entire transaction. The terminal row is append-only: no update, upsert, replacement, or delete is permitted. A retry after commit returns the exact stored terminal result and response descriptor without repeating side effects. Corrections or post-seal incidents use a separate append-only adjudication/incident record linked to the immutable result; they never rewrite it.

### 7.5 No exactly-once claim

The journal and containerd do not share one atomic transaction. The protocol guarantee is durable intent, deterministic identity, exclusive privileged ownership, inspect-before-retry reconciliation, idempotent operation handling, and one durable logical terminal result. If an external side-effect outcome is ambiguous, quarantine instead of blindly repeating create/start.

## 8. Deadline and clock contract

### 8.1 Within-boot clock

Use an explicitly selected, suspend-aware monotonic clock for in-VM elapsed execution, trigger, cleanup, and supervisor-liveness deadlines. The recommended Linux candidate is `CLOCK_BOOTTIME`: Linux documents that it includes time spent suspended, whereas `CLOCK_MONOTONIC` does not. The implementation must use an explicit audited clock API and must not assume that a language runtime's default monotonic clock has the required suspend semantics. This guest clock does not govern the outer VM safety watchdog: that watchdog must use an independently operated control-plane/hypervisor time source and must not trust guest wall-clock or monotonic-clock values to enforce its hard cutoff.

Use the kernel boot ID as one boot-identity input and record the trusted host-instance identity separately. Persist clock IDs and raw nanosecond values as bounded integer fields; never compare monotonic values across different boot IDs.

### 8.2 Cross-reboot and snapshot behavior

- Persist the original trigger UTC timestamp, boot ID, host-instance identity, and last trusted clock synchronization evidence.
- After reboot, derive remaining time only from a trusted synchronized wall clock with recorded uncertainty. Calculate conservatively and subtract the maximum known uncertainty.
- If wall-clock trust, host incarnation, timestamp integrity, or remaining budget cannot be established, treat the budget as expired, quarantine, and continue best-effort cleanup.
- VM snapshot/restore, clone, rollback, suspend/resume, NTP loss, clock steps, and time rollback are explicit fault-injection cases. A clone or restore cannot reuse a stale host instance identity or supervisor generation.
- The host proof image should prohibit administrative suspend/snapshot during a calibration run unless the exact recovery path is part of that approved test.

### 8.3 Budget composition and admission

The 10-minute API-intake budget is the absolute end-to-end terminalization budget. Before sandbox creation, admission reserves:

`maximum 60-second execution + approved cleanup deadline + independently bounded evidence/terminal-finalization reserve`

Queue wait, retries, recovery, cleanup, evidence verification/publication, and terminal commit consume the same original intake budget. If the remaining time is insufficient, reject before creating a sandbox. The cleanup stop boundary is the earlier of the approved cleanup deadline and the original intake deadline. At either boundary, unresolved cleanup/evidence is incomplete and quarantined; independent best-effort cleanup continues.

The numeric cleanup deadline and evidence reserve remain unset until Phase A measurements and independent review are complete. Do not choose a value in this contract.

## 9. Recovery algorithm and verification matrix

### 9.1 Supervisor startup/recovery algorithm

1. Start in `RECOVERY_ONLY`; accept no new work and register no execution endpoint.
2. Acquire the stable host-wide kernel lock. If acquisition fails or lock identity/ownership is uncertain, fail-stop.
3. Verify trusted host-instance identity, boot ID, supervisor binary digest, journal identity/schema, file ownership/mode, backend durability configuration, and integrity.
4. Allocate and durably commit a new supervisor generation.
5. Enumerate all non-terminal attempts, pending operations, triggers, branch dispositions, terminal results, and quarantine records.
6. For each attempt, reconcile deterministic supervisor-owned identities against actual containerd tasks/containers, shim processes, process trees, cgroups, namespaces, mounts, scratch, network-policy state, evidence staging, immutable evidence objects, and manifests.
7. Increment attempt/branch generations under compare-and-set before reclaiming any branch. Stale workers fail closed.
8. Re-arm original deadlines from the original trigger/intake anchor. If the original anchor cannot be proven, expire and quarantine.
9. Persist observed state and bounded dispositions. Never issue create/start until absence is proven and the same logical operation is still authorized.
10. Mark the host healthy for new work only after every non-terminal attempt has been reconciled, the watchdog is healthy, the journal is healthy, and the independent host inventory has no unknown/unowned resources.

### 9.2 Required fault-injection matrix

| Failure injection | Required durable expectation | Allowed side effect | Recovery owner | Required outcome/evidence |
|---|---|---|---|---|
| Before admission transaction commit | No accepted attempt or acknowledged operation | None | Supervisor | Retry with same key; inventory proves no sandbox |
| After intent commit, before create | Intent exists; no observed result | Create only after inspect proves absence | Replacement supervisor | One logical operation; no duplicate task |
| After create/start, before observed-result commit | Durable intent only; external outcome uncertain | Inspect/reconcile; no blind repeat | Replacement supervisor | Exact owned resource or proven absence; otherwise quarantine |
| After result commit, before response | Operation/result/response descriptor durable | Return recorded response only | Supervisor | Retry returns same operation and no repeated side effect |
| Same idempotency key, changed digest | Original key/digest unchanged | None | Supervisor | Conflict; no new resource |
| Supervisor SIGSTOP while holding lock | Existing lock remains held | No replacement privileged call | Recovery watchdog | Stop old unit; prove exit/lock release before replacement |
| Supervisor SIGKILL | Pending operation may be uncertain | No blind create/start | Recovery watchdog + replacement | New generation; reconcile actual host state |
| WD-001 — Watchdog SIGSTOP/deadlock | Watchdog heartbeat expires; supervisor remains fenced by its own lock | No second watchdog or replacement may issue containerd calls | Outer VM safety watchdog | Admission remains stopped; outer containment fires if watchdog recovery cannot be proven |
| WD-002 — Watchdog service-manager authorization denied | No authorized StopUnit/StartUnit result | No shell, systemctl, sudo, or alternate root broker | Outer VM safety watchdog | Host quarantined; no replacement supervisor |
| WD-003 — Supervisor unit/drop-in or executable digest substitution | Pinned identity mismatch | No stop/start against an unverified unit identity | Outer VM safety watchdog | Stop admission; preserve mismatch evidence; stop/rebuild VM |
| WD-004 — Supervisor cgroup path or membership mismatch | Complete-cgroup identity cannot be established | No replacement start and no claim of old-process termination | Outer VM safety watchdog | Host quarantined; VM containment required |
| WD-005 — systemd automatic-restart race | Restart policy conflicts with watchdog ownership protocol | No concurrent automatic and watchdog-directed replacement | Recovery watchdog | Fail qualification; require pinned restart policy and proven single-owner recovery |
| WD-006 — Service manager reports stop complete but process/lock remains | Independent process-exit or kernel-lock-release proof is absent | No replacement supervisor start | Outer VM safety watchdog | Admission stopped; retain lock/process evidence; contain VM |
| WD-007 — Watchdog unit unavailable or watchdog process exits | Independent recovery authority is absent | No in-VM fallback authority | Outer VM safety watchdog | VM stopped/rebuilt; no alternate privileged path |
| Journal BUSY/FULL/IOERR during termination | Trigger may be missing/uncertain; no false terminal record | Termination proceeds immediately | Cleanup controller + recovery watchdog | Quarantine; original budget never resets |
| Journal corruption/unknown schema | Integrity failure visible | No new work | Supervisor/reviewer | Host quarantined; no auto-recreate |
| Containerd outage after intent | Intent durable, side-effect status uncertain | No retry until daemon and resource identity verified | Replacement supervisor | Reconcile or quarantine |
| Evidence store unavailable during cleanup | Cleanup branch may complete; evidence branch incomplete | Termination/removal continues | Independent branches | No passed result; evidence incomplete |
| Cleanup branch worker stale generation | Current branch generation durable | Stale update rejected | Journal CAS | No stale overwrite |
| Crash/race around trigger-stream seal, output finalization, and terminal CAS | Database guards enforce false-to-true-only sealing, immutable watermark, contiguous durable triggers, monotonic counters, retained <= observed, combined-retained equality, and write-once output finalization; post-seal events are append-only late incidents | Terminal CAS only after current branch dispositions, trigger watermark, finalized output snapshot, and generations are revalidated | Replacement supervisor | Rejected tampering, no trigger/output rewrite, no success after a disqualifying breach, and at most one immutable terminal result |
| Crash after terminal CAS, before response | Terminal result immutable and durable | Return recorded result | Supervisor | No second terminal record or side effect |
| Trigger races: cancellation/deadline/output breach | One ordered trigger winner plus retained secondary events | One termination/cleanup operation | Host trigger arbiter | Original trigger timestamp/sequence and one final result |
| Natural exit with inherited pipes | Exit provisional | Bounded drain and complete sandbox cleanup | Cleanup controller | Late output breach cannot be converted to success |
| Host suspend/resume | BOOTTIME includes suspended interval | No renewed execution/cleanup time | Watchdog + supervisor | Expired if deadline passed; quarantine if clock evidence ambiguous |
| VM reboot or snapshot restore | Old monotonic values cannot be compared blindly | No new work before identity/clock reconciliation | Outer watchdog + replacement | Expired/quarantined on uncertainty |
| Outer VM cutoff fires | No claim of sandbox cleanup success | Stop/rebuild VM | Outer VM safety watchdog | Failed/unverified sample; host quarantined/destroyed |

### 9.3 Acceptance rules

- Every row above must have a deterministic test or controlled fault-injection procedure with exact injected boundary, expected journal rows/versions/generations, allowed containerd side effects, recovery owner, and independent evidence.
- Test both process crash and abrupt VM power-off where applicable. Process-kill tests do not substitute for power-loss durability tests.
- Test supervisor pause, not only exit; prove the kernel lock prevents concurrent privileged access while the old process is alive.
- Test that stale generations cannot update attempts, branches, or terminal results.
- Test the termination exception with journal and evidence I/O deliberately unavailable; termination must begin immediately.
- A test returning non-zero is not sufficient. Require host-side inventory and durable evidence of the expected outcome.

## 10. Implementation gates and open decisions

Privileged implementation remains blocked until all of the following are true:

1. ADR-0019's rootful/rootless privilege decision is independently reviewed and accepted.
2. The three watchdog roles, identities, privilege sets, restart path, and outer hard-stop interface are frozen for the exact host.
3. The logical journal schema, generations, unique constraints, CAS transitions, migrations, and recovery algorithm are independently reviewed.
4. A backend, exact SQLite build/driver if applicable, filesystem, storage device, mount options, durability profile, backup/restore, corruption policy, and lock mechanism are selected and approved for the exact disposable host.
5. Journal power-loss, disk-full, BUSY/IOERR/CORRUPT, interrupted migration, backup/restore, and stale-supervisor lock tests pass on that exact host/storage stack.
6. The explicit CLOCK_BOOTTIME capture/re-arm behavior, boot identity, suspend/resume, NTP/clock uncertainty, snapshot/restore, and cross-reboot policy pass review and fault injection.
7. The cleanup deadline and evidence/terminal-finalization reserve are measured under the separately authorized Phase A campaign and recorded together in a reviewed resource-profile revision.
8. Independent security review approves the implementation boundary and host proof plan.

Only then may a separately scoped implementation issue authorize the narrow supervisor/journal/watchdog code. The first implementation milestone must still keep `UnconfiguredExecutor` active and expose no student/public execution endpoint. Phase B's 35-fixture adversarial proof remains separately gated.

## 11. References

- Linux `clock_gettime(2)` documentation: https://man7.org/linux/man-pages/man2/clock_gettime.2.html
- M0 runtime harness: `docs/specifications/m0-runtime-proof-harness-design.md`
- M0 journal evaluation: `docs/specifications/m0-journal-backend-evaluation.md`
- M0 host launch ADR: `docs/adr/ADR-0019-m0-host-launch-boundary.md`
- M0 Phase A/Phase B cleanup deadline profile: `docs/specifications/m0-proof-resource-profile-v1.md`
- M0 independent security review packet: `docs/security/m0-sandbox-security-review-packet.md`
