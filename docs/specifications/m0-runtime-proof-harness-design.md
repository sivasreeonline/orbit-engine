# M0 Runtime Proof Harness Design

- Status: Design proposal only; no executor or host supervisor implementation is authorized by this document.
- Related: ADR-0018, `m0-host-preflight-and-proof-runbook.md`, `m0-adversarial-fixture-contract.md`, `m0-proof-evidence.schema.json`.
- Security posture: fail closed. The Go runner remains on `UnconfiguredExecutor`; readiness remains HTTP 503.

## 1. Objective and non-goals

Define a reproducible, independently observable harness for proving the selected containerd + gVisor runtime baseline on one disposable Linux AMD64 VM.

The harness must establish runtime compatibility, systrap selection, isolation, resource enforcement, cancellation, cleanup, restart recovery, and repeatability using synthetic fixtures only.

This design does not:
- Add an HTTP execution endpoint or queue consumer.
- Accept or execute student source code.
- Enable Java/Python student execution.
- Grant the Go runner access to the containerd socket.
- Select a cloud provider, region, VM size, or paid service.
- Claim that gVisor is secure before the required evidence and independent review exist.

## 2. Trust boundaries and components

| Component | Trust level | Responsibility | Must not do |
|---|---|---|---|
| Proof coordinator | Trusted control plane | Select approved fixture IDs, issue bounded proof runs, collect signed/hashed evidence references | Accept arbitrary commands, images, mounts, or OCI settings from a workload |
| Host launch boundary | Privileged and separately reviewed | Validate typed requests, apply root-owned profiles, manage sandbox lifecycle through containerd | Expose containerd socket, arbitrary OCI spec, host paths, devices, or runtime selection to the runner |
| containerd daemon | Host infrastructure | Create and manage OCI task/container lifecycle | Be reachable from the guest or student process |
| gVisor runsc + matching shim | Sandbox boundary | Run the pinned fixture image using the approved platform | Fall back silently to another platform |
| Fixture image | Untrusted workload | Execute only reviewed synthetic test cases | Contain secrets, network callbacks, destructive host operations, or hidden assessment data |
| Host evidence collector | Trusted observer | Observe cgroups, process tree, network policy counters, mounts, scratch, runtime metadata and cleanup | Trust guest-reported security claims as sole evidence |
| Evidence store | Trusted, access-controlled | Store sanitized manifests and immutable evidence files | Store raw secrets, raw daemon environments, student source, hidden tests, or private artifact URLs |

The launch boundary is an unresolved ADR gate. The preferred design candidate is a narrowly scoped host supervisor with a typed allowlisted API, but rootless containerd remains an alternative until compatibility and privilege analysis are complete. Do not implement either path before the independent threat review and ADR decision.

## 3. Host supervisor contract boundary

The Go runner must never receive broad containerd socket access. A future supervisor interface must expose only fixed operations:

- `CreateProofSandbox`
- `StartProofSandbox`
- `GetProofSandboxStatus`
- `CancelProofSandbox`
- `DeleteProofSandbox`

Every operation is authenticated, authorized, bounded, correlated, and idempotent where applicable. Transport is a private Unix socket with peer-identity checks or another separately reviewed private authenticated transport. No public listener is permitted.

### 3.0 Operation-level contract

| Operation | Preconditions and authorization | Idempotency / response contract |
|---|---|---|
| `CreateProofSandbox` | Approved fixture, runtime profile, resource profile, unexpired deadline, authorized proof run and unused attempt | Same idempotency key returns the existing attempt; conflicting request digest for that key is rejected |
| `StartProofSandbox` | Exact attempt is durably created and its image/profile digests are re-verified | Repeated start returns current state; it never starts a second task |
| `GetProofSandboxStatus` | Caller is authorized for the exact proof run and attempt | Read-only; returns bounded state and evidence references, never raw guest output or hidden test data |
| `CancelProofSandbox` | Exact attempt is owned by the caller's authorized proof run | Repeated cancel converges on the same cancellation/terminal state; client disconnect does not stop cleanup |
| `DeleteProofSandbox` | Attempt is terminal or in an explicitly authorized cleanup/reconciliation path | Repeated delete verifies absence; it does not erase journal or evidence needed for audit |

All responses are versioned, bounded, and typed. They contain the operation ID, attempt ID, correlation ID, current lifecycle state, a fixed infrastructure/result classification, and opaque evidence references where appropriate. They must not contain OCI specs, host paths, raw command lines, environment values, credentials, hidden tests, expected outputs, or unbounded stdout/stderr.

The supervisor must compare a canonical digest of the immutable request fields with the persisted request digest. Reusing an idempotency key with different fixture/profile/deadline content is a conflict, not a retry. Do not permit caller-selected sandbox names or resource labels; derive those from the durable attempt identity using a collision-resistant deterministic encoding.

### 3.1 Allowed request fields

A request may contain only:
- Protocol version.
- Proof run ID and fixture ID from the approved catalog.
- Attempt ID and correlation ID.
- Approved runtime profile ID.
- Approved resource profile ID.
- Absolute deadline / remaining wall-clock budget.
- An idempotency key.

The supervisor resolves image digests, entrypoints, environment allowlists, user/group IDs, mount layout, network policy, capabilities, seccomp profile, cgroup limits, output ceilings, and scratch layout from root-owned immutable profiles. The proposed M0 proof-only values are documented in `m0-proof-resource-profile-v1.md` and must be recorded in every evidence manifest. The authoritative end-to-end deadline is derived only from the control plane's durably persisted API intake timestamp plus the approved 10-minute budget; neither the runner nor the caller may supply or extend that timestamp/deadline. Persist the derived absolute deadline and original intake timestamp with the attempt before queueing. Queue wait, retries, reconnects, supervisor restarts, and containerd recovery consume the same budget; they never reset or extend it. The 60-second sandbox wall clock begins at the host-observed workload start and is an additional, stricter bound, not a replacement for the end-to-end deadline. On host reboot, reconstruct the remaining budget from the persisted absolute deadline using a trusted wall clock and a fresh monotonic timer. If clock rollback, timestamp integrity, or remaining budget cannot be established, fail closed and quarantine the attempt/host rather than granting a fresh interval.

### 3.2 Forbidden request fields

Never accept caller-supplied:
- OCI JSON/spec fragments or arbitrary annotations.
- Image names, mutable tags, arbitrary registries, or runtime binary paths.
- Entrypoints, shell commands, command strings, or arbitrary argument arrays.
- Host paths, bind mounts, devices, namespaces, capabilities, privileged flags, or host networking.
- Environment variables except named non-secret fixture parameters from a strict allowlist.
- Network destinations, firewall rules, DNS servers, or proxy settings.
- Resource limits above the platform hard ceilings.
- Credentials, source code, hidden tests, expected outputs, or raw host command lines.

Reject unknown fields and duplicate JSON keys. Fail closed if a profile is missing, stale, untrusted, or fails signature/digest verification.

### 3.3 Unix-socket authorization and service isolation

The initial transport candidate is a local Unix stream socket only. Before implementation, record and independently review the exact socket path, service UID/GID, socket owner/group/mode, parent-directory permissions, systemd unit, and containerd socket access mechanism.

Minimum design requirements:

1. The socket lives under a root-owned directory that is not writable by the runner, guest, or other unprivileged accounts. Reject symlinked socket paths and verify the parent directory and socket inode/owner/mode at service startup.
2. Use Linux peer credentials (for example, `SO_PEERCRED`) on every accepted connection and compare the authenticated UID/GID against one explicitly configured runner identity. Do not trust a caller-supplied UID, PID, username, or role field.
3. Authenticate and authorize each operation and each referenced proof run/attempt. A valid local socket connection is not blanket authorization to operate on arbitrary attempts.
4. Apply a small fixed maximum request size, strict UTF-8/JSON parsing, duplicate-key rejection, unknown-field rejection, bounded strings, and operation-specific required fields. Reject trailing JSON and malformed framing.
5. Set bounded connection, request, response, and concurrent-operation limits. A disconnected client must not cancel cleanup or leave a partially created task.
6. Do not pass client file descriptors, environment, working directory, or inherited capabilities into the sandbox. Do not accept SCM_RIGHTS descriptors unless a future reviewed contract explicitly requires them.
7. The runner service identity must not belong to the containerd socket's access group. Only the dedicated supervisor identity may access the root-owned containerd socket; no broad interactive-user group membership is allowed.
8. Keep the supervisor's journal, profiles, evidence staging area, and runtime socket in separate directories with explicit owner/mode policy. The guest receives none of these paths or descriptors.
9. The systemd hardening profile must be tested against the exact containerd operations. Record effective unit settings and capabilities; fail deployment if an unexpected capability, writable host path, or network listener is present.
10. The supervisor must not expose a generic command runner, shell, arbitrary file API, arbitrary OCI-spec API, or generic containerd proxy.

Peer credentials and socket permissions authenticate the local process identity; they do not make a compromised runner trustworthy. The supervisor must still authorize every operation against its durable attempt record and immutable profile.

### 3.4 Privilege and compromise analysis

A process that can issue unrestricted requests to the rootful containerd socket has host-level authority. The supervisor must therefore be treated as a high-value privileged component, not as a harmless adapter.

The design review must explicitly compare:
- A narrowly scoped supervisor that directly accesses containerd.
- A split design with an unprivileged request coordinator and a minimal privileged broker.
- Rootless containerd with caller-configured user namespaces.

Do not assume that splitting processes automatically removes risk: the privileged broker still needs independent validation, and the broker's API must be narrower than the containerd API. Any helper that can accept arbitrary OCI settings or forward arbitrary containerd requests is rejected.

Before selecting the rootful path, document the effective capability set, systemd sandboxing, writable paths, syscalls, socket access, update/rollback procedure, and recovery access. If the required containerd operations force broad ambient privileges that cannot be acceptably constrained, stop and revisit the rootless alternative rather than weakening the threat model.

## 4. Sandbox lifecycle state machine

The lifecycle is controlled by the host supervisor and recorded in a durable host-side journal. Process termination/cleanup and evidence collection are independent finalization branches; neither branch may wait for the other to begin or make progress.

```text
REQUESTED
   |
   v
VALIDATING ---- invalid profile/request ----> REJECTED
   |
   v
QUEUED
   |
   v
CREATING
   |
   v
STARTING
   |
   v
RUNNING ------ deadline/cancel/policy breach -> TERMINATING
   |                                             |
   +---- natural exit ---------------------------+
                                                 |
                                                 v
                                           FINALIZING
                                            /       \
                                           v         v
                                      CLEANING    COLLECTING
                                           |         |
                                           v         v
                                     CLEANUP      EVIDENCE
                                     DISPOSITION  DISPOSITION
                                            \       /
                                             v     v
                                      DURABLE FINALIZATION
                                         /          \
                                        v            v
                                   TERMINAL       INCOMPLETE /
                                   (eligible      INFRA_FAILED
                                    for success)
```

Entering `FINALIZING` must schedule cleanup immediately, without waiting for evidence collection, redaction, hashing, object-store availability, or manifest generation. The cleanup controller owns termination and resource removal independently of the collector and client connection. Evidence collection may observe already captured bounded host-side buffers and immutable metadata, but it must not retain a live workload or sandbox merely to finish writing evidence.

The two branches report explicit, durable dispositions. Cleanup is successful only after all required host-side absence checks pass. Evidence is complete only after every referenced object and the final manifest are durably published and independently verified. A failure or timeout in either branch produces an incomplete or infrastructure-failed result; it cannot be converted to a passed fixture. The terminal compare-and-set may run only after both branch dispositions are durably recorded. A success acknowledgement additionally requires both dispositions to be successful and the terminal journal transition to be durable.

A supervisor restart must reconcile every non-terminal journal entry and both finalization branches against actual containerd tasks, shim processes, namespaces, cgroups, mounts, scratch directories, evidence staging objects, immutable evidence objects, and manifest state. It must re-arm the watchdog from the original persisted absolute deadline and must not grant a new 10-minute or 60-second interval. The watchdog must be independently supervised from the request connection and ordinary runner process; its restart/recovery path must be included in the proof. The exact watchdog implementation and boot/clock trust assumptions remain review gates. Unknown or unowned resources are quarantined and cleaned under the host recovery procedure; they must never be silently adopted as successful work.

A terminal acknowledgement is allowed only after independent host-side inspection confirms:
1. The complete workload process tree is absent.
2. The containerd task and container are absent.
3. The matching shim process is absent.
4. All sandbox namespaces and the sandbox cgroup are absent.
5. All temporary mounts and the per-attempt scratch directory are absent.
6. The sandbox network namespace and per-attempt network-policy state are removed.
7. Host-side evidence collection is complete or explicitly marked incomplete.
8. The terminal state and cleanup result are durably journaled.

`CLEANUP_FAILED` is an infrastructure-failed, non-success state: it must never be mapped to a passed fixture, terminal-success acknowledgement, or host-ready state. The exact cleanup deadline remains an explicit pre-stress-test gate; it must be finite, configured in the approved proof profile, measured from the termination trigger, and validated under worst-case failure and restart conditions. Do not infer or silently choose a value.

## 5. Lifecycle and idempotency rules

- The idempotency key is unique to proof run, fixture, and attempt.
- Repeated create/start calls for the same active attempt return the existing state; they must not create a second workload.
- Repeated cancellation is safe and returns the same terminal/cancelling state.
- Delete is idempotent and must verify absence rather than infer success from an API response.
- One attempt has at most one terminal result. Conflicting terminal results are an infrastructure failure.
- A retry after uncertain cleanup must first reconcile and prove the prior sandbox is gone.
- Duplicate delivery is tested at the coordinator/supervisor boundary, not by relying on containerd's incidental behavior.

### 5.1 Durable journal and crash consistency

The journal is the source of truth for logical proof attempts. Its storage location must be host-only, root-owned, permission-restricted, and excluded from all guest mounts. Select and document a storage engine and durability settings before implementation; a database commit that has not reached durable storage is not a safe acknowledgement.

For every lifecycle operation:

1. Validate caller identity, authorization, request schema, profile revision, and deadline.
2. Persist the operation intent and unique idempotency key before performing an external side effect.
3. Perform exactly one bounded containerd/lifecycle operation using a deterministic sandbox identity derived from the persisted attempt record.
4. Inspect actual host/runtime state and persist the observed result.
5. Acknowledge the caller only after the journal transition is durable.

Enforce unique constraints for the idempotency key and for the logical attempt identity (proof run + fixture + attempt). Persist terminal state with a compare-and-set transition so racing exit, timeout, cancellation, and output-overflow handlers cannot create conflicting terminal results. The transition from an active state to `TERMINATING` or natural-exit `FINALIZING` is the single arbitration point and must be one durable journal transaction. The transaction checks for already-recorded termination triggers before accepting natural exit. A winning termination trigger fixes the primary terminal cause; later triggers are appended as secondary causes and never overwrite it. A natural exit may win only if no termination trigger has already been durably accepted. A late cancellation after the attempt has entered terminal finalization or reached a terminal state is idempotent and cannot rewrite the result. Record each trigger's type, authenticated source, UTC observation time, monotonic elapsed time, attempt ID, and operation generation. Client disconnect is not a cancellation trigger. Cleanup requests are idempotent and fenced by the durable attempt/generation; repeated watchdog, cancel, or policy signals converge on the same termination and cleanup work.

A journal record must include the request digest, authenticated caller identity, profile IDs/revisions, deterministic sandbox identity, current lifecycle state, operation generation, timestamps, last observed runtime state, cleanup state, and evidence references. Do not persist source code, hidden tests, credentials, raw command lines, or arbitrary caller-supplied payloads.

The exact durability mode, filesystem, atomicity assumptions, backup/recovery procedure, and corruption behavior remain design gates. If the journal is corrupt, unavailable, or cannot prove a unique attempt state, stop accepting new work and quarantine the host for reconciliation.

### 5.2 Restart and failure reconciliation matrix

| Failure point | Required restart/retry behavior | Required host-side proof |
|---|---|---|
| Before intent is durable | No operation may have been acknowledged; caller may retry with same idempotency key | No task/container exists for the deterministic sandbox identity |
| Intent durable, before create | Reconcile by attempt identity; create only if absence is proven | Durable intent plus absence inspection |
| During container create/start | Inspect containerd, shim, process, cgroup, namespace and mount state; never blindly issue create again | One matching owned resource set or a verified absence; ambiguous state is quarantined |
| Runner restart during an active attempt | Runner reconnects using the same authorized attempt identity; supervisor lifecycle remains independent and does not launch a duplicate | Durable attempt identity, idempotency key, one task and one terminal result are verified |
| Workload running during supervisor restart | Reattach only to the exact journal-owned sandbox; otherwise terminate and reconcile | Process/task identity, cgroup membership, runtime handler and journal generation match |
| Containerd daemon restart or unavailable socket | Stop new launches; reconcile all non-terminal attempts after daemon recovery | Daemon identity/version rechecked; no unowned task or orphan shim |
| Cancellation races with natural exit | One compare-and-set terminal winner; all paths converge on cleanup | Single terminal record and no surviving process/task |
| Deadline races with cancellation | Terminate once; record both triggers if observed, but emit one terminal result | Watchdog and journal timestamps plus one terminal transition |
| Shim exits unexpectedly | Treat as infrastructure failure; inspect and clean all associated resources | No process, task, namespace, mount or scratch remains |
| OOM/PID/output enforcement | Host watchdog terminates remaining descendants and performs cleanup | cgroup events, output counters and post-cleanup inventory |
| Evidence collector/store unavailable | Do not mark proof passed; retain bounded local evidence staging or mark evidence incomplete | Hashes and byte counts for retained evidence; explicit incomplete state |
| Journal corruption or disk full | Fail closed; no new work; quarantine host | Recovery report, journal integrity check and full host inventory |

The reconciler must enumerate resources by deterministic supervisor-owned labels and journal ownership, not by guest-controlled names. It must never adopt an unknown resource as successful work. If ownership or cleanup cannot be proven, quarantine the host and require operator intervention.

### 5.3 Cleanup completion and acknowledgement

A cleanup result is successful only after independent inspection confirms all of the following are absent: workload process tree, containerd task/container, shim process, sandbox namespaces, sandbox cgroup, scratch directory, temporary mounts, and network policy state. The exact cleanup deadline must be specified before stress testing and measured under worst-case failure conditions.

A client disconnect, timeout, or supervisor restart does not stop cleanup. Cleanup runs under a host-side lifecycle controller independent of the request connection. If any absence check is inconclusive, retain `CLEANUP_FAILED` / infrastructure-failed state, quarantine the host, and do not acknowledge terminal success or return the host to a ready pool.

## 6. Resource and isolation enforcement layers

Use independent layers so a single misconfiguration does not exhaust the disposable host:

1. Disposable VM outer cgroup and host watchdog cap total CPU, memory, PIDs, disk, and wall time for the complete proof process.
2. Per-sandbox cgroup v2 controls CPU, memory, PIDs, and accounting.
3. gVisor provides the userspace-kernel boundary with explicitly verified systrap platform.
4. Root filesystem is immutable/read-only; scratch is per-attempt, size- and inode-bounded, and never a host bind mount.
5. Network policy defaults to deny IPv4/IPv6 egress, DNS, direct-IP traffic, loopback-to-host, and metadata routes. Controlled probes use reserved test destinations and host-side counters only.
6. stdout and stderr are drained concurrently by independent non-blocking/pollable readers (or an equivalently proven multiplexed implementation). A full or continuously writing stdout pipe must never prevent stderr from being drained, and vice versa. Each reader uses a fixed-size buffer; no unbounded queue, channel, in-memory accumulator, or blocking evidence-store write may sit between pipe reads and the bounded accounting path.
7. Count every byte read immediately in monotonic observed-byte counters, before retention, decoding, formatting, logging, or evidence publication. Then reserve retention budget under one shared atomic accounting operation across both readers, enforcing each per-stream ceiling and the shared combined ceiling. A fixed-size read buffer may cross a ceiling: retain only the prefix that fits the remaining reserved budget and discard the rest. Never let two readers independently check then write against a stale combined count. The proposed profile's stdout and stderr individual ceilings are each 1 MiB, while the shared combined ceiling is 1 MiB; therefore the aggregate ceiling is the stricter storage bound. Retain raw contiguous byte prefixes in separate stdout/stderr evidence objects, without UTF-8 decoding or newline normalization. Record observed byte counts, retained byte counts, truncation flags, and the first policy-breach reason as host-side metadata. The order in which concurrent readers reserve the shared budget is scheduler-dependent; do not promise deterministic inter-stream ordering.
8. On the first observed per-stream or combined ceiling breach, atomically record the breach and request termination of the entire sandbox workload through the host lifecycle controller. Do not wait for readers, evidence writes, or client acknowledgement before requesting termination. Continue draining and discarding excess bytes with fixed-size buffers until EOF or the bounded cleanup deadline; never retain bytes beyond the configured ceilings. If EOF does not arrive, the host watchdog must finish termination and cleanup without waiting indefinitely for pipe closure.
9. Pipe readers must not block on evidence-store I/O. Write retained bytes only to a bounded, attempt-scoped local staging sink with a defined failure mode; if that sink is unavailable or full, continue draining/discarding, mark evidence incomplete, and preserve cleanup progress. Do not retry storage synchronously from a pipe reader.
10. Reap the complete process tree and verify pipe EOF/descriptor closure independently. A descendant that inherits stdout/stderr must not keep the attempt alive indefinitely: termination targets the complete sandbox/cgroup, not only the direct child or its process group. Handle natural exit, cancellation, deadline, and output overflow as racing triggers with one durable terminal winner; any observed output breach remains an infrastructure/resource failure, never a passed fixture.
11. The host watchdog remains outside the sandbox and terminates the complete process tree on deadline, cancellation, or resource-policy breach.

The outer VM controls are mandatory before running CPU, memory, PID, filesystem, or output stress fixtures.

## 7. Host-side evidence and observability

For each attempt capture:
- Resource profile ID/revision and every applied CPU, memory, PID, wall-time, output, scratch-byte, and scratch-inode limit.
- Proof run, fixture, attempt, correlation IDs, fixture source revision and immutable image digest.
- Runtime profile revision, OCI image digest, containerd/runsc/shim versions, actual gVisor platform, kernel and cgroup mode.
- UTC wall timestamps and monotonic durations for queue, create, start, run, terminate, collect, cleanup, and acknowledgement.
- Host-observed UID/GID, capabilities, cgroup counters/events, process tree, network policy counters, mount/device inventory, scratch bytes/inodes, and output byte counts.
- Exit status, classification, timeout/cancellation reason, resource events, cleanup checks, and journal state.
- Sanitized evidence paths, SHA-256 hashes, byte sizes, and reviewer disposition.

Guest stdout/stderr is untrusted and bounded. Guest-reported UID, platform, network state, or cleanup is never accepted as sole proof. Raw daemon command lines and environment output must never be archived; follow the redaction rules in the host preflight runbook.


### 7.1 Evidence publication, integrity, and crash ordering

The manifest's `relative_path`, `sha256`, `bytes`, and `redacted` fields are declarations, not proof that an evidence object exists or matches its declaration. JSON Schema validation alone MUST NOT authorize a passed proof. A separate host-side evidence verifier is required before a passed result can be committed.

The evidence publisher and verifier must enforce this sequence for every evidence object:

1. Create an attempt-scoped staging location using exclusive creation beneath a trusted, root-owned directory. Reject symlink traversal and any path that escapes the attempt's staging root.
2. Collect only allowlisted, sanitized evidence. Apply redaction before publication; do not publish raw evidence and then rely on manifest metadata to claim it was redacted.
3. Close the staged file, flush file contents to durable storage using the selected platform's documented durability primitive, and compute SHA-256 and byte count from the exact final bytes.
4. Publish to an immutable, content-addressed object identity derived from the digest (or an equivalently reviewed immutable object version). Publication must be no-overwrite; an existing object is accepted only after its bytes are independently re-read and verified against the digest and byte count.
5. Make the containing directory or object-store commit durable using the selected backend's documented semantics. Re-open/read back the published object and independently verify exact byte count and SHA-256 before recording its reference.
6. Persist the verified evidence reference, digest, byte count, redaction disposition, and evidence-collection status in the durable attempt journal. Do not persist a reference before the object is verified and durable.
7. Generate and validate the final manifest from the durable journal and verified objects. Persist the manifest and its integrity metadata durably before making the attempt terminal.
8. Persist the terminal result with compare-and-set only after both evidence disposition and independently verified cleanup disposition are known. Acknowledge terminal success only after that terminal journal transition is durable.

The exact filesystem or object-store technology, durability primitives, immutable versioning/retention settings, access-control policy, and recovery procedure are implementation gates. Do not assume that rename, close, database commit, or an object-store success response alone implies durable publication; document and test the selected backend's actual guarantees.

Crash recovery must reconcile staging files, published objects, journal references, and manifests by attempt identity and digest:
- Staged object with no journal reference: quarantine or safely garbage-collect only after proving no in-flight publisher owns it; never include it in a passed manifest.
- Published object with no journal reference: treat as an orphan; verify ownership and retention before cleanup, never infer a successful attempt.
- Journal reference with missing object or mismatched digest/size: mark evidence incomplete, prevent passed status, preserve the incident record, and quarantine the proof host if integrity cannot be restored.
- Manifest persisted but terminal journal transition absent: verify every referenced object and cleanup state, then resume the same idempotent terminal transition or mark incomplete; never issue a second terminal result.
- Terminal journal state with missing/unverified manifest or evidence: treat as an invariant violation, revoke any success acknowledgement where possible, mark the proof run invalid, and quarantine for investigation.

Evidence collection and evidence-store access must not be on the critical path for process termination. The host lifecycle controller must continue termination and cleanup even if the collector blocks, crashes, or loses storage access. Evidence failure may make the proof incomplete or infrastructure-failed, but it must never prevent cleanup or be converted into a passed result.

The verifier must reject path traversal, symlink substitution, duplicate logical references with conflicting metadata, digest/byte-count mismatch, absent objects, unapproved evidence roots, and evidence objects whose redaction disposition is not independently established. It must also verify that every passed fixture has at least one verified evidence object and that all references in the final manifest resolve to the exact immutable object version that was checked.

No evidence retention duration or cleanup policy is selected here. Define retention, access logging, deletion authorization, and post-proof export before implementation; evidence needed for audit must not be deleted while a journal or manifest still references it.

## 8. Result model

Keep execution verdict separate from infrastructure state.

- Fixture outcome: passed, failed, blocked, not_run.
- Runtime result: exited, compilation_error, runtime_error, timed_out, cancelled, resource_limited.
- Infrastructure state: healthy, unavailable, startup_failed, cleanup_failed, host_failed, evidence_incomplete.

Any host boundary exposure, successful forbidden network flow, unbounded resource use, orphan process, cleanup failure, unexpected host mutation, or evidence leak is a proof failure and stops the suite. It is not a student verdict.

## 9. Recovery and fault-injection matrix

Before declaring the lifecycle design complete, prove recovery for:
- Supervisor restart before sandbox creation.
- Supervisor restart during creation or startup.
- Supervisor restart while the fixture is running.
- Runner/coordinator disconnect while the fixture is running.
- Cancellation racing with natural process exit.
- Deadline racing with cancellation.
- Containerd daemon restart or unavailable socket.
- Shim crash or unexpected task disappearance.
- OOM, PID exhaustion, output overflow, and forced host-side termination.
- Evidence collector failure and evidence-store unavailability.
- Duplicate create, start, cancel, and delete requests.

For each case, expected terminal state, cleanup deadline, journal reconciliation, and evidence completeness must be explicit. If cleanup cannot be verified, the attempt remains infrastructure-failed and the host is not returned to the ready pool.

## 10. Implementation gates

No implementation begins until all of the following are approved:
1. ADR selects the host launch boundary and privilege model.
2. Disposable VM outer resource controls and recovery access are specified.
3. Runtime and fixture images are source-reviewed, signed/provenance-verified, and pinned by immutable digest.
4. The adversarial fixture contract is reviewed and its stress-fixture safety bounds are proven.
5. The supervisor request/response schema and threat model receive independent security review.
6. Host-side evidence and cleanup verification are testable without trusting guest output.

After approval, implement the supervisor and proof harness behind a separate M0-only interface. Keep the student-facing runner executor unconfigured until every M0 gate passes and a separate security approval explicitly authorizes integration testing.
