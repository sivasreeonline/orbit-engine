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
- If ADR-0019 is independently accepted, one dedicated host supervisor is the only application principal permitted to issue rootful containerd operations.
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
9. Terminal success requires durable, current cleanup and evidence dispositions, independent verification of all resource absence, and one durable terminal compare-and-set.
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

**Authority:** only the approved supervisor can perform normal privileged containerd lifecycle operations. The controller may request only the five typed supervisor operations in the runtime harness design; it must not expose generic containerd, shell, file, OCI, or command APIs.

**Failure behavior:** if the journal is unavailable, the controller still issues termination and continues best-effort cleanup. It stops new admissions, marks the host/attempt unsafe for success, and requests supervisor recovery. If the original trigger or disposition cannot be reconstructed after restart, treat the cleanup budget as expired and quarantine. Never restart the cleanup interval.

### 3.2 Supervisor liveness and recovery watchdog

**Owner:** a separately supervised host service or equivalent independently reviewed host mechanism, not a goroutine, timer, request handler, or health check inside the supervisor process it monitors.

**Responsibilities:**
- Monitor a bounded supervisor heartbeat and the age of in-flight host operations using a read-only, bounded status channel.
- Detect process exit, missed heartbeat, deadlock/pause, expired operation progress, or inability to reconcile the host journal.
- Request fail-stop of the exact supervisor service instance and allow the operating system to release its kernel process lock before a replacement may proceed.
- Permit one replacement supervisor to acquire the host lock, allocate a new supervisor generation, and reconcile every non-terminal attempt before accepting new work.
- Escalate to the outer VM safety watchdog if the supervisor cannot be stopped/replaced safely or if the recovery path cannot establish ownership and deadlines.

**Prohibited authority:** it must not become a second unrestricted containerd caller, a generic root command broker, an alternate journal writer, or a bypass around the host lock. Any narrow authority required to stop/restart the named supervisor service must be explicitly enumerated and independently reviewed. It must not mutate attempt terminal results.

**Failure behavior:** if the watchdog itself is unavailable, cannot prove supervisor ownership, or cannot perform bounded recovery, no new work is admitted. The outer VM safety watchdog is the final containment authority. A watchdog restart does not prove cleanup and does not reset any attempt deadline.

### 3.3 Outer VM safety watchdog

**Owner:** a control plane, hypervisor, or other mechanism outside the disposable VM's supervisor/journal/containerd failure domain.

**Responsibilities:** enforce the separately approved outer VM CPU, memory, PID, disk, and wall-time safety envelope; isolate, stop, or rebuild the disposable VM if the in-VM recovery path is no longer trustworthy.

**Prohibited interpretation:** a VM hard-stop is not successful cleanup of an individual sandbox. A fired cutoff produces a failed/unverified calibration sample, host quarantine/destruction, and no terminal-success acknowledgement.

**Open deployment dependency:** the provider/control-plane mechanism cannot be selected until the host/provider decision is approved. No provider, region, VM size, or spend is selected here.

### 3.4 Failure-domain matrix

| Failure | Per-attempt cleanup controller | Supervisor recovery watchdog | Outer VM safety watchdog | Required disposition |
|---|---|---|---|---|
| Runner/client disconnect | Continues independently | No action unless supervisor unhealthy | No action | Same attempt remains owned; no implicit cancel |
| Evidence store unavailable | Continues termination/removal | No action unless supervisor blocked | No action | Cleanup may succeed; evidence incomplete; never passed |
| Journal BUSY/FULL/IOERR | Issues termination; bounded journal retry only off cleanup path | Detects failure/stall; stops new work and recovers supervisor if needed | Escalates only if in-VM recovery fails | Quarantine if durable state/trigger cannot be reconciled |
| Supervisor SIGSTOP/deadlock | Cannot assume in-process progress | Fail-stops exact service, waits for lock release, starts one replacement | Stops/rebuilds VM if safe replacement cannot be established | No fresh deadline; reconcile or quarantine |
| Supervisor SIGKILL/crash | Existing workload may remain until replacement reconciles | Starts replacement only after old process exits and releases lock | Final containment if replacement cannot recover | Inspect actual resources; never blind create/start |
| Containerd unavailable | Attempts safe termination through available host controls; no false absence claim | Restarts/reconciles supervisor after daemon recovery | Contains VM if host state is unsafe | Stop new launches; quarantine ambiguous resources |
| Host suspend/resume | Original elapsed budget must include suspend | Re-arm using approved suspend-aware clock and original trigger | Enforces outer wall limit | Expired/uncertain deadline means quarantine |
| VM reboot/snapshot restore | Old-boot monotonic value is not reused | Requires trusted clock + host incarnation + journal reconciliation | Stops/rebuilds if identity/clock trust is uncertain | Expire budget and quarantine if not reconstructible |

**Acceptance gate:** the concrete OS/service mechanism, identities, privileges, heartbeat format, stop/restart action, lock-release proof, and outer hard-stop interface must be named in the host-specific implementation plan and reviewed before privileged implementation.

## 4. Identity, generation, and fencing model

Do not overload one `generation` field. The following values have different owners and lifetimes.

| Value | Scope | Allocated by | Changes when | Enforced by |
|---|---|---|---|---|
| `host_instance_id` | One disposable VM incarnation | Trusted host/control-plane enrollment; never caller-supplied | New VM incarnation or restore that cannot prove continuity | Host identity verification and evidence manifest |
| `supervisor_generation` | One supervisor process ownership epoch on a host instance | Supervisor after acquiring the exclusive host lock | Every accepted supervisor replacement/restart | Host lock + journal CAS + supervisor self-check |
| `attempt_generation` | Ownership/recovery epoch for one logical attempt | Current supervisor under journal transaction | Attempt ownership is transferred during restart/reconciliation | Attempt row CAS; checked on every operation |
| `operation_sequence` | Ordered operations within one attempt | Journal transaction | Every newly claimed lifecycle operation | Unique `(attempt_id, operation_sequence)` and operation ID |
| `state_version` | Attempt state row | Journal transaction | Every accepted state transition | Compare-and-set expected version |
| `branch_generation` | One cleanup or evidence branch | Journal transaction | Branch ownership is reclaimed/restarted | Branch-specific compare-and-set |
| `trigger_sequence` | Host-observed trigger stream for one attempt | One host-owned event arbiter | Each accepted trigger observation | Atomic event ordering and immutable trigger records |

All values are distinct from the immutable external `attempt_id`, `operation_id`, `trigger_id`, and `correlation_id` identifiers.

### 4.1 Ownership handoff

1. The supervisor must acquire a stable, root-owned kernel process lock before opening the journal for writes or issuing any privileged containerd operation.
2. A replacement must not start privileged work until the previous supervisor process has exited and the kernel has released the lock. A database lease alone is not a fence against a paused process.
3. After lock acquisition, the replacement validates host identity, boot identity, journal identity/schema/durability settings, and the last committed generation.
4. In one durable transaction, allocate a new `supervisor_generation`, then reclaim each non-terminal attempt by incrementing its `attempt_generation` and the affected branch generations using expected-version compare-and-set.
5. Before every external side effect, the supervisor verifies the host lock, current supervisor generation, current attempt generation, operation sequence, expected state/version, and deterministic resource identity.
6. An old process or worker that observes lock/generation mismatch must fail-stop before any further side effect or journal mutation.
7. If a restored/replicated VM cannot prove a unique trusted `host_instance_id`, it is not eligible to accept work. A restored journal does not itself prove host incarnation or fencing.

Do not claim that an arbitrary generation integer fences containerd. Containerd does not consume this application generation; exclusivity must be proven at the host process/lock boundary.

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
- The trigger event and `ACTIVE -> TERMINATING` transition use one serialized arbitration decision. If trigger ordering cannot be proven because the arbiter or clock is unavailable, the attempt is quarantined and its cleanup budget is treated as expired.
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
| `attempts` | Unique `(proof_run_id, fixture_id, attempt_id)`; canonical immutable request digest; authenticated owner; profile IDs/revisions and image digest; original API intake UTC timestamp and absolute end-to-end deadline; intake boot/clock metadata; deterministic sandbox identity; lifecycle state and state version; attempt generation; active operation ID; terminal classification if committed. |
| `idempotency_keys` | Unique scoped idempotency-key digest; canonical request digest; attempt and operation IDs; bounded versioned response descriptor; current durable disposition. Same scope/key + same digest returns the same logical operation; changed digest is a conflict. |
| `operations` | Unique operation ID; unique `(attempt_id, operation_sequence)`; host/attempt generations; operation type; expected prior state/version; target state; deterministic external resource identity; immutable request digest; durable intent time; observed external result; bounded error class; completion disposition. |
| `triggers` | Unique trigger ID; attempt and generations; trigger sequence; trigger type; authenticated source; boot ID; BOOTTIME observation; UTC audit timestamp; primary/secondary/late disposition; termination-request timestamp; durable persistence disposition. |
| `finalization_branches` | Unique `(attempt_id, branch, branch_generation)`; branch kind `cleanup` or `evidence`; owner generation; state; disposition; bounded error class; start/completion timestamps; independent verification reference. |
| `terminal_results` | Unique attempt ID; immutable result classification; final state version; winning trigger ID/cause; cleanup disposition; evidence disposition; terminal commit timestamp; response descriptor digest. |
| `evidence_references` | Opaque attempt-scoped object key/version; SHA-256; byte count; evidence-root ID; redaction disposition; independent verification status. No raw content or private URL. |
| `quarantine_records` | Host/attempt identity; quarantine reason code; observed resources/uncertainty class; originating generation; timestamp; operator/recovery disposition; evidence reference. Never delete unresolved quarantine records during ordinary retention. |

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
- All state changes use expected state version and generation predicates. The implementation checks affected-row counts; zero or unexpected multiple rows are conflicts/corruption, not success.
- Indexes support lookup by logical attempt, idempotency scope/key digest, operation ID, deterministic sandbox identity, non-terminal attempts, pending branch dispositions, and quarantine state.
- SQL identifiers are constants from the implementation. Caller-controlled values are parameters only; caller input never constructs SQL, table names, or query fragments.

### 6.2 Retention and backup invariants

- Active attempts, non-terminal operations, unresolved branches, terminal results needed for idempotency, and unresolved quarantine records cannot be pruned.
- Backup/restore runs outside the cleanup critical path. Use the backend's reviewed consistent snapshot API; do not copy a live database file and assume it is consistent.
- A restored journal does not authorize work. The host remains quarantined until host identity, schema, integrity, generation, and all non-terminal attempts are reconciled against actual resources.
- A corrupt or unknown/newer schema fails closed. Do not automatically delete, recreate, or “repair” a journal and resume execution.
- Exact size limits, free-space low-watermark, backup cadence, retention duration, secure deletion, and restore RTO remain open until a host/storage profile is approved.

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

### 7.3 No exactly-once claim

The journal and containerd do not share one atomic transaction. The protocol guarantee is durable intent, deterministic identity, exclusive privileged ownership, inspect-before-retry reconciliation, idempotent operation handling, and one durable logical terminal result. If an external side-effect outcome is ambiguous, quarantine instead of blindly repeating create/start.

## 8. Deadline and clock contract

### 8.1 Within-boot clock

Use an explicitly selected, suspend-aware monotonic clock for elapsed execution, trigger, cleanup, and watchdog deadlines. The recommended Linux candidate is `CLOCK_BOOTTIME`: Linux documents that it includes time spent suspended, whereas `CLOCK_MONOTONIC` does not. The implementation must use an explicit audited clock API and must not assume that a language runtime's default monotonic clock has the required suspend semantics.

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
| Journal BUSY/FULL/IOERR during termination | Trigger may be missing/uncertain; no false terminal record | Termination proceeds immediately | Cleanup controller + recovery watchdog | Quarantine; original budget never resets |
| Journal corruption/unknown schema | Integrity failure visible | No new work | Supervisor/reviewer | Host quarantined; no auto-recreate |
| Containerd outage after intent | Intent durable, side-effect status uncertain | No retry until daemon and resource identity verified | Replacement supervisor | Reconcile or quarantine |
| Evidence store unavailable during cleanup | Cleanup branch may complete; evidence branch incomplete | Termination/removal continues | Independent branches | No passed result; evidence incomplete |
| Cleanup branch worker stale generation | Current branch generation durable | Stale update rejected | Journal CAS | No stale overwrite |
| Crash after both branches durable, before terminal CAS | Both current dispositions durable | Terminal CAS only | Replacement supervisor | One immutable terminal result |
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
