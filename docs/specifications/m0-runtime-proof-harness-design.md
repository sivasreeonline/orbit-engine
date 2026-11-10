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

The supervisor resolves image digests, entrypoints, environment allowlists, user/group IDs, mount layout, network policy, capabilities, seccomp profile, cgroup limits, output ceilings, and scratch layout from root-owned immutable profiles. The proposed M0 proof-only values are documented in `m0-proof-resource-profile-v1.md` and must be recorded in every evidence manifest.

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

The lifecycle is controlled by the host supervisor and recorded in a durable host-side journal.

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
RUNNING ------ deadline exceeded ----------> TERMINATING
   |  \
   |   +---- cancellation ----------------> TERMINATING
   |   +---- output/resource violation ---> TERMINATING
   |   +---- runtime exit ----------------> COLLECTING
   |
   v
COLLECTING
   |
   v
CLEANING
   |
   +---- cleanup verified ----------------> TERMINAL
   |
   +---- cleanup uncertain ---------------> CLEANUP_FAILED (not terminal-success)
```

A supervisor restart must reconcile every non-terminal journal entry against actual containerd tasks, shim processes, namespaces, cgroups, mounts, and scratch directories. Unknown or unowned resources are quarantined and cleaned under the host recovery procedure; they must never be silently adopted as successful work.

A terminal acknowledgement is allowed only after:
1. The workload process tree is gone.
2. The containerd task and container are removed.
3. Sandbox network state is removed.
4. Scratch is removed and its absence is verified.
5. Host-side evidence collection is complete or explicitly marked incomplete.
6. The terminal state and cleanup result are durably journaled.

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

Enforce unique constraints for the idempotency key and for the logical attempt identity (proof run + fixture + attempt). Persist terminal state with a compare-and-set transition so racing exit, timeout, cancellation, and output-overflow handlers cannot create conflicting terminal results.

A journal record must include the request digest, authenticated caller identity, profile IDs/revisions, deterministic sandbox identity, current lifecycle state, operation generation, timestamps, last observed runtime state, cleanup state, and evidence references. Do not persist source code, hidden tests, credentials, raw command lines, or arbitrary caller-supplied payloads.

The exact durability mode, filesystem, atomicity assumptions, backup/recovery procedure, and corruption behavior remain design gates. If the journal is corrupt, unavailable, or cannot prove a unique attempt state, stop accepting new work and quarantine the host for reconciliation.

### 5.2 Restart and failure reconciliation matrix

| Failure point | Required restart/retry behavior | Required host-side proof |
|---|---|---|
| Before intent is durable | No operation may have been acknowledged; caller may retry with same idempotency key | No task/container exists for the deterministic sandbox identity |
| Intent durable, before create | Reconcile by attempt identity; create only if absence is proven | Durable intent plus absence inspection |
| During container create/start | Inspect containerd, shim, process, cgroup, namespace and mount state; never blindly issue create again | One matching owned resource set or a verified absence; ambiguous state is quarantined |
| Workload running during supervisor restart | Reattach only to the exact journal-owned sandbox; otherwise terminate and reconcile | Process/task identity, cgroup membership, runtime handler and journal generation match |
| Cancellation races with natural exit | One compare-and-set terminal winner; all paths converge on cleanup | Single terminal record and no surviving process/task |
| Deadline races with cancellation | Terminate once; record both triggers if observed, but emit one terminal result | Watchdog and journal timestamps plus one terminal transition |
| Containerd unavailable or restarted | Stop new launches; reconcile all non-terminal attempts after daemon recovery | Daemon identity/version rechecked; no unowned task or orphan shim |
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
6. stdout and stderr have independent byte counters; a shared 1 MiB combined hard storage ceiling is enforced. On the first per-stream or combined ceiling breach, terminate the complete process tree, retain no more than the first 1 MiB combined, and drain/discard remaining pipe data with fixed-size buffers while reaping.
7. The host watchdog remains outside the sandbox and terminates the complete process tree on deadline, cancellation, or resource-policy breach.

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
