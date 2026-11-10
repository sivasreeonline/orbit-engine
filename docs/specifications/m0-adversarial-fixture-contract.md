# M0 Adversarial Fixture Contract

- Status: Proposed for disposable-host proof; no workload fixtures are authorized for execution yet.
- Baseline: ADR-0018 and `docs/specifications/m0-host-preflight-and-proof-runbook.md`.
- Resource profile: `docs/specifications/m0-proof-resource-profile-v1.md` (proposed M0 proof-only values; pending empirical and independent review).
- Evidence manifest: `docs/schemas/m0-proof-evidence.schema.json`.
- Scope: M0 runtime, isolation, resource enforcement, lifecycle, and control-plane proof.

## 1. Contract principles

1. Every fixture has a stable ID, immutable source revision, language/runtime image digest, expected outcome, host-side assertion, timeout, and cleanup assertion.
2. A fixture is successful only when both the in-sandbox stimulus and the independent host-side assertion agree. A non-zero exit code alone is never proof of isolation or enforcement.
3. The test controller, not the workload, owns the wall-clock watchdog, output byte counters, process-tree observation, sandbox lifecycle, and cleanup verification.
4. Student source, production data, real credentials, and hidden assessment tests are prohibited. Use synthetic inputs and inert sentinel values only.
5. Network probes use controlled destinations and packet observation. They must not call public services or send callbacks to the Internet. The metadata-address probe is a narrowly defined exception to the reserved-range rule: it attempts the metadata link-local IP only from inside the sandbox, while an independently verified outer-VM deny/blackhole rule drops that destination before any host uplink or metadata service can receive it. Never run this probe until the outer rule and its counters have been verified; never query metadata from the host.
6. Every resource-exhaustion fixture runs inside a disposable VM with an outer host-level cgroup and watchdog that remain effective even if the inner sandbox limit fails.
7. Record expected and observed outcomes, timestamps, fixture revision, runtime/image digests, resource measurements, and sanitized evidence references in the M0 evidence manifest.
8. A fixture marked `blocked` or `not_run` is not a pass. Any unexplained result blocks M0.

## 2. Runtime correctness fixtures

| Fixture ID | Runtime | Stimulus | Required outcome | Host-side assertion |
|---|---|---|---|---|
| `M0-RUN-JAVA-001` | Java 25 | Deterministic stdin-to-stdout program | Exact expected stdout bytes and exit code 0 | Captured stdout hash and byte count match the fixture expectation |
| `M0-RUN-PY-001` | Python 3.14 | Deterministic stdin-to-stdout program | Exact expected stdout bytes and exit code 0 | Captured stdout hash and byte count match the fixture expectation |
| `M0-RUN-JAVA-002` | Java 25 | Deliberate source compilation error | Compilation Error classification; no workload process remains | Compiler phase, bounded diagnostics, and cleanup are recorded |
| `M0-RUN-003` | Java 25 and Python 3.14 | Controlled non-zero exit / runtime exception | Runtime Error classification; no infrastructure error | Exit status and sanitized stderr are captured without exposing host data |
| `M0-RUN-004` | Java 25 and Python 3.14 | UTF-8 and newline boundary output | Byte-for-byte output matches the defined fixture | No trimming, newline conversion, Unicode normalization, or hidden output rewrite |

## 3. Identity and host-boundary fixtures

| Fixture ID | Stimulus | Required outcome | Independent assertion |
|---|---|---|---|
| `M0-ID-001` | Inspect effective UID/GID inside workload | Non-root UID and GID | Host runtime configuration and process credentials agree |
| `M0-ID-002` | Inspect effective Linux capabilities | No ambient, permitted, effective, or inheritable capabilities beyond the explicitly approved empty set | Host-side OCI spec and observed process state agree |
| `M0-HOST-001` | Inspect mount namespace and known host-only sentinel paths | No host filesystem paths or writable host mounts visible | Host mount table and sentinel checks confirm isolation |
| `M0-HOST-002` | Inspect device namespace and device nodes | No host devices or privileged device access | Host-side OCI device configuration is allowlisted and minimal |
| `M0-HOST-003` | Inspect environment, process arguments, and approved filesystem locations | No application credentials, cloud credentials, runner tokens, or host environment values visible | Secret canary scan returns no matches; no real secret is used |
| `M0-HOST-004` | Inspect containerd socket and host control endpoints | No containerd socket or supervisor control socket visible | Host-side mount and namespace inspection confirms absence |
| `M0-HOST-005` | Attempt bounded path traversal and symlink traversal against synthetic host-only sentinels | Access denied; sentinel contents unchanged | Host-side hashes and file metadata remain unchanged |

## 4. Network-denial fixtures

All ordinary probes target reserved test/documentation ranges, a controlled proof resolver, or a host-local sentinel listener bound only to the disposable proof network. No public endpoint is contacted. `M0-NET-006` is the sole special case: the sandbox attempts the metadata link-local destination (for example, IPv4 `169.254.169.254`) only after an independently verified outer-VM deny/blackhole rule is active. The rule must drop the destination before it can reach a host uplink or real metadata service, and host-side counters/packet observation must prove the drop. The probe must never retrieve metadata, and the host itself must never issue a metadata request. If the outer deny cannot be independently verified, mark the fixture `blocked` and do not run it.

| Fixture ID | Probe | Required outcome | Independent assertion |
|---|---|---|---|
| `M0-NET-001` | IPv4 egress to a controlled TEST-NET destination | Blocked | Host-side packet observation records no successful egress |
| `M0-NET-002` | IPv6 egress to a controlled documentation-prefix destination | Blocked | Host-side packet observation records no successful egress |
| `M0-NET-003` | DNS query to the controlled proof resolver | Blocked | Resolver receives no query from the workload network namespace |
| `M0-NET-004` | Direct-IP connection bypassing DNS | Blocked | Host-side network policy counters show the attempted flow denied |
| `M0-NET-005` | Connection to a host-local sentinel listener | Blocked | Sentinel listener accepts no connection from the sandbox |
| `M0-NET-006` | From inside the sandbox only, attempt a bounded connection to the metadata link-local address after the outer-VM deny/blackhole rule is independently verified | Blocked before host uplink or metadata service | Host-side deny counters and packet observation prove the drop; no metadata service receives the packet and no metadata response is received |

## 5. Resource-enforcement fixtures

Resource values are injected from the versioned proof profile, not chosen by the workload. The initial candidate is `m0-proof-small-v1`; its CPU, memory, PID, wall-time, scratch, and output values are defined in `docs/specifications/m0-proof-resource-profile-v1.md`. These are proposed M0 proof values only and require empirical validation and independent approval. The outer disposable-VM cgroup and watchdog must cap damage if an inner control is broken.

| Fixture ID | Stimulus | Required outcome | Independent assertion |
|---|---|---|---|
| `M0-RES-CPU-001` | Sustained CPU-bound workload | CPU quota enforced within the configured tolerance | Host-side cgroup counters show throttling and no host-wide saturation |
| `M0-RES-MEM-001` | Bounded incremental allocation beyond the sandbox memory ceiling | Sandbox memory limit enforced and classified as resource/infrastructure outcome, never Accepted | Host-side memory events identify the sandbox cgroup; outer VM remains healthy |
| `M0-RES-PID-001` | Bounded child-process creation beyond the sandbox PID ceiling | Additional process creation denied at the configured limit | Host-side pids.current / pids.events confirm enforcement; outer VM remains responsive |
| `M0-RES-TIME-001` | Infinite loop with a controlled child process | Wall-clock deadline terminates the full process tree | Host supervisor observes no surviving descendant after terminal acknowledgement |
| `M0-RES-FS-001` | Attempt to write to the base filesystem | Write denied | Base image remains unchanged and mounted read-only |
| `M0-RES-FS-002` | Write synthetic data beyond scratch byte ceiling | Further writes denied or sandbox terminated at the hard ceiling | Host-side scratch usage never exceeds the configured hard bound |
| `M0-RES-FS-003` | Create files beyond scratch inode ceiling | Further inode creation denied or sandbox terminated at the hard ceiling | Host-side inode usage never exceeds the configured hard bound |
| `M0-RES-OUT-001` | Run stdout-only overflow and duplex subcases: stdout crosses its 1 MiB per-stream ceiling while stderr is continuously written; include a child that inherits both output descriptors | Host detects the applicable per-stream or combined breach, requests complete sandbox termination immediately, drains/discards both streams concurrently, and stores no more than the shared 1 MiB combined ceiling | Host-side stdout/stderr counters and retained-byte totals prove each cap; stderr continues draining while stdout is full; child and descendants are gone; no pipe keeps the attempt alive past the cleanup deadline |
| `M0-RES-OUT-002` | Run stderr-only overflow and duplex subcases: stderr crosses its 1 MiB per-stream ceiling while stdout is continuously written; include a child that inherits both output descriptors | Host detects the applicable per-stream or combined breach, requests complete sandbox termination immediately, drains/discards both streams concurrently, and stores no more than the shared 1 MiB combined ceiling | Host-side stdout/stderr counters and retained-byte totals prove each cap; stdout continues draining while stderr is full; child and descendants are gone; no pipe keeps the attempt alive past the cleanup deadline |

Output-capture fixture requirements: execute each output fixture in isolated subcases so the stdout-only and stderr-only 1 MiB per-stream limits are independently reached without the combined ceiling masking them. In duplex subcases, continuously write both streams so the combined ceiling is reached; verify concurrent draining and prove that a saturated stream cannot block the other. Include a child that writes beyond the applicable ceiling and exits immediately while bytes remain buffered in the OS pipe; verify that the collector drains to EOF, discovers the overflow after process exit if necessary, and prevents provisional natural exit from becoming a passed result. Include a descendant that inherits the output descriptors, then verify complete sandbox termination, EOF/descriptor closure or watchdog-forced closure, bounded cleanup, and no orphan process. Also inject bounded-staging failure and confirm readers continue draining/discarding while evidence is marked incomplete. These are synthetic M0 workloads only; do not use student code or hidden tests.

## 6. Lifecycle and control-plane fixtures

| Fixture ID | Stimulus | Required outcome | Independent assertion |
|---|---|---|---|
| `M0-LIFE-CLEAN-001` | Normal successful execution | All sandbox resources are removed before completion is acknowledged | Independent host inventory confirms absence of workload process tree, containerd task/container, shim, namespaces, cgroup, scratch, temporary mounts, and network policy state |
| `M0-LIFE-CLEAN-002` | Compile error, runtime error, timeout, cancellation, OOM, output overflow, and forced termination | Cleanup completes for every terminal path | Each path has a separate cleanup record; independent inventory confirms no process, task/container, shim, namespace, cgroup, mount, scratch, or network-policy residue |
| `M0-LIFE-CANCEL-001` | Cancel while workload and child process are active; race cancellation with natural exit, output overflow, the immutable 10-minute intake deadline, and 60-second sandbox watchdog in isolated subcases; repeat cancel/watchdog signals and issue a late cancel after finalization | One durable arbitration winner and one terminal result; complete process tree terminated; late/repeated signals do not rewrite terminal state or duplicate cleanup | Journal transaction proves the winning primary cause and retained secondary triggers; timestamps prove the original intake/start deadlines were not reset; complete host inventory proves no process/task/container/shim/namespace/cgroup/mount/scratch/network-policy residue |
| `M0-LIFE-DUP-001` | Deliver the same logical job more than once | One logical execution and one terminal result | Persistent idempotency/claim record and result count prove deduplication |
| `M0-LIFE-RESTART-RUNNER-001` | Restart the unprivileged Go runner during an active attempt | Supervisor-owned lifecycle continues independently; retry/reconnect does not create a duplicate workload | Durable journal and post-restart inventory prove one logical attempt and no unowned task/container, shim, process, namespace, cgroup, mount, scratch, or network-policy residue |
| `M0-LIFE-RESTART-SUPERVISOR-001` | Restart the host supervisor and its independently supervised watchdog during each active lifecycle phase (create, start, run, terminate, cleanup), including immediately before/after deadline and cancellation arbitration | Supervisor reconciles from durable intent and observed state; watchdog recovery re-arms the original persisted deadlines without resetting either budget; ambiguous ownership is quarantined | Fault-injection records prove no duplicate launch, no fresh deadline grant, no false terminal success, one terminal arbitration winner, and no unowned task/container, shim, process, namespace, cgroup, mount, scratch, or network-policy residue |
| `M0-LIFE-RESTART-CONTAINERD-001` | Restart or make the containerd daemon unavailable during an active attempt | New launches stop; existing attempts are reconciled after daemon recovery without blind create retries | Daemon identity/version and journal generation are checked; post-recovery inventory proves one logical attempt and no orphan task/container, shim, process, namespace, cgroup, mount, scratch, or network-policy residue |
| `M0-LIFE-REPEAT-001` | Repeat each fixture on a clean sandbox | Same expected classification and bounded variance | Each repetition has an independent correlation ID and evidence record |

## 7. Result classification

The runner and proof harness must keep student verdicts separate from infrastructure state.

- **Student verdicts:** Accepted, Wrong Answer, Compilation Error, Runtime Error, Time Limit Exceeded, Memory Limit Exceeded, Output Limit Exceeded.
- **Infrastructure outcomes:** Sandbox startup failure, runtime unavailable, host resource failure, cancellation infrastructure failure, cleanup failure, evidence incomplete, internal error.
- Infrastructure outcomes must never be converted to Wrong Answer or Accepted.
- A security assertion failure is a failed M0 fixture even if the student-facing process exits non-zero.
- Missing host-side evidence means the fixture is incomplete, not passed.

## 8. Execution order and stop conditions

1. Review fixture source and immutable image digests; approve the fixture revision.
2. Verify the disposable VM outer cgroup, watchdog, network containment, and recovery access before any stress fixture.
3. Run runtime compatibility and identity/host-boundary fixtures first.
4. Run network-denial fixtures before resource-exhaustion fixtures.
5. Run CPU, memory, PID, filesystem, output, timeout, and cancellation fixtures individually with cleanup verification after each.
6. Run duplicate-delivery, restart-recovery, and repeatability tests last.
7. Stop immediately on any host-boundary exposure, successful network egress, unbounded resource use, orphan process, cleanup failure, unexpected host mutation, or evidence leak.

Do not execute this suite on a shared developer machine, production host, or host containing student data. Do not run stress fixtures until the outer VM-level safety controls have been independently checked.

## 9. M0 exit criteria

M0 proof is complete only when every required fixture is either passed with complete host-side evidence or formally dispositioned as a blocked non-goal with an approved security rationale. No required isolation, resource, cleanup, or network test may be waived silently.

A passing fixture suite permits a separate security review and integration-test decision. It does not enable the production executor or authorize student execution.
