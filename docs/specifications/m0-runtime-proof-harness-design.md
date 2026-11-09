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

### 3.1 Allowed request fields

A request may contain only:
- Protocol version.
- Proof run ID and fixture ID from the approved catalog.
- Attempt ID and correlation ID.
- Approved runtime profile ID.
- Approved resource profile ID.
- Absolute deadline / remaining wall-clock budget.
- An idempotency key.

The supervisor resolves image digests, entrypoints, environment allowlists, user/group IDs, mount layout, network policy, capabilities, seccomp profile, cgroup limits, output ceilings, and scratch layout from root-owned immutable profiles.

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

## 6. Resource and isolation enforcement layers

Use independent layers so a single misconfiguration does not exhaust the disposable host:

1. Disposable VM outer cgroup and host watchdog cap total CPU, memory, PIDs, disk, and wall time for the complete proof process.
2. Per-sandbox cgroup v2 controls CPU, memory, PIDs, and accounting.
3. gVisor provides the userspace-kernel boundary with explicitly verified systrap platform.
4. Root filesystem is immutable/read-only; scratch is per-attempt, size- and inode-bounded, and never a host bind mount.
5. Network policy defaults to deny IPv4/IPv6 egress, DNS, direct-IP traffic, loopback-to-host, and metadata routes. Controlled probes use reserved test destinations and host-side counters only.
6. stdout and stderr have independent byte counters and hard storage ceilings; truncation/termination behavior is explicit and measured.
7. The host watchdog remains outside the sandbox and terminates the complete process tree on deadline, cancellation, or resource-policy breach.

The outer VM controls are mandatory before running CPU, memory, PID, filesystem, or output stress fixtures.

## 7. Host-side evidence and observability

For each attempt capture:
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
