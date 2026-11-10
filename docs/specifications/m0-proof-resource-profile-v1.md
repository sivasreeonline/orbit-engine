# M0 Proof Resource Profile v1

- Profile ID: `m0-proof-small-v1`
- Revision: `1`
- Status: Proposed disposable-host proof profile; pending independent security review and empirical runtime validation.
- Scope: Synthetic M0 proof fixtures only. This is not a production student-execution profile.
- Protocol alignment: `ResourceLimitsV2`; the protocol's `outputBytes` is the combined stdout + stderr ceiling.

## 1. Per-sandbox limits

| Resource | Initial value | Enforcement contract |
|---|---:|---|
| CPU quota | 1,000 millicores (1 vCPU) | cgroup v2 CPU quota; host-side throttling counters must prove enforcement |
| Memory | 1 GiB (1,073,741,824 bytes) | cgroup v2 hard memory ceiling; OOM is an infrastructure/resource outcome |
| Process count | 128 | cgroup v2 PID ceiling; host-side `pids.current` / `pids.events` prove enforcement |
| Sandbox wall time | 60,000 ms | Host watchdog terminates the complete process tree and verifies cleanup |
| End-to-end request budget | 10 minutes maximum | Includes queue wait; deadline originates from persisted API intake time |
| Combined output | 1 MiB (1,048,576 bytes) | One shared hard ceiling across stdout and stderr, matching protocol `outputBytes` |
| Per-stream observation | stdout 1 MiB; stderr 1 MiB | Independent byte counters; each stream is separately testable, but both share the combined 1 MiB storage ceiling |
| Scratch bytes | 256 MiB (268,435,456 bytes) | Hard per-attempt scratch quota; never a host bind mount |
| Scratch inodes | 4,096 | Hard per-attempt inode quota |

The protocol hard ceilings remain 512 MiB scratch and 8,192 scratch inodes. The proof profile uses the lower defaults. No caller or workload may raise these values.

The 10-minute end-to-end deadline is measured from the control plane's durably persisted API intake timestamp and includes queue wait, retries, reconnects, and recovery. The 60-second sandbox wall time begins at host-observed workload start. Persist both origins/deadlines; neither may be reset by runner/supervisor/containerd restart or retry. The host watchdog must re-arm from the original deadline after restart, using trusted wall-clock/monotonic-clock handling. Caller- or runner-supplied timestamps are never authoritative.

A finite cleanup deadline is still deliberately unset. It must be added to a reviewed revision of this profile, measured from the first durable termination trigger, and validated under cancellation, deadline, output-overflow, inherited-pipe, supervisor restart, containerd outage, and evidence-store failure conditions. Pipe drain/EOF waiting is bounded by this cleanup deadline and may not extend it. No stress fixture or host proof may start until the cleanup deadline and its clock/restart semantics are explicitly approved; do not invent a default.

## 2.1 Cleanup deadline qualification — required before profile approval

The numeric cleanup deadline is intentionally **unset** in revision 1. It must not be guessed from a developer workstation, a clean cancellation, or an average runtime. This section defines how a future revision may qualify and approve it.

### Scope and start point

- The cleanup deadline bounds the **host cleanup branch**, not evidence publication. Evidence finalization runs independently; evidence-store failure must never delay termination or resource cleanup.
- The deadline starts at the earliest host-observed termination trigger: cancellation accepted by the host, sandbox wall watchdog, end-to-end deadline admission/watchdog, output overflow, OOM/resource enforcement, natural-exit cleanup, or infrastructure/supervisor recovery that requires termination.
- Capture the trigger's host monotonic timestamp and boot identity before or at the termination request. Issue termination immediately; do not wait for a database fsync, client response, pipe EOF, evidence write, or remote service. Persist the trigger record durably as soon as possible. The cleanup budget is measured from the captured trigger instant, **not** from the later journal commit or acknowledgement, so journal latency cannot extend it.
- Repeated or secondary triggers never reset the original cleanup deadline. Arbitration may select one immutable primary cause, but the earliest trigger remains the cleanup clock anchor.
- The deadline ends only when the host has independently verified absence of the complete process tree, containerd task/container, shim, namespaces, cgroup, scratch, temporary mounts, and attempt-scoped network-policy state, and has durably recorded the cleanup disposition. If any resource cannot be inspected, cleanup is unverified and the host/attempt is quarantined; timeout is not success.

### Clock and restart semantics

- Use a monotonic clock for elapsed-time measurement within one boot and persist its clock identity plus boot ID. Wall-clock timestamps are audit metadata, not the elapsed-time authority.
- On supervisor restart within the same boot, re-arm from the original monotonic trigger timestamp; never start a fresh interval.
- Across host reboot, the prior boot's monotonic clock cannot be compared with the new boot's clock. Persist the original trigger wall timestamp and boot ID, require a trusted synchronized host clock with recorded synchronization/uncertainty evidence, and conservatively calculate remaining budget. If clock trust, time ordering, or remaining budget cannot be established, treat the cleanup deadline as expired, quarantine, and continue best-effort independent cleanup. Never grant a new full cleanup interval after reboot.
- Suspend/resume, clock steps, NTP loss, VM snapshot/restore, and clock rollback must be included in qualification. A host restored from snapshot must not reuse a stale supervisor generation or extend a deadline.
- The external watchdog must enforce termination/cleanup even if the supervisor is paused, deadlocked, or unable to write the journal. The watchdog's clock and control path must be independent enough to avoid sharing the failure being tested.

### Measurement protocol

1. Freeze the candidate host envelope before measurement: exact VM image, kernel, filesystem/mount options, storage class, containerd/runsc versions, supervisor/watchdog build, cgroup hierarchy, and profile revision. No student data or student source is used.
2. Instrument monotonic timestamps for trigger detection, termination request, process-tree/cgroup empty, task/container removal, shim exit, namespace/mount/scratch/network-policy cleanup, final independent absence verification, and durable cleanup disposition. Record phase durations and the overall trigger-to-verified-cleanup duration.
3. Run every cleanup-trigger class separately: explicit cancellation; 60-second sandbox watchdog; end-to-end deadline admission/watchdog; stdout overflow; stderr overflow; combined output overflow; memory/OOM; PID exhaustion; natural exit with descendants holding inherited pipes; compile/runtime failure; supervisor crash/restart; containerd restart/outage; journal SQLITE_BUSY/FULL/IOERR; evidence-store outage (proving cleanup is independent); and partial/ambiguous runtime state.
4. Include adversarial process trees: nested descendants, rapid fork/exit races, ignored termination signals, stuck/uninterruptible tasks where safely reproducible, inherited stdout/stderr descriptors, full pipes, and repeated/late cancellation. Do not create a workload that can escape the disposable VM or access real metadata services.
5. Repeat each case across cold/warm runtime state, load levels within the approved outer-VM envelope, supervisor restart, and containerd restart. Include abrupt VM reboot only after the outer recovery/watchdog path is independently verified.
6. Preserve raw monotonic measurements and sanitized host evidence; distinguish verified completion from cleanup timeout, host failure, and unknown state. Report sample count, min, median, p95, p99, maximum, phase breakdown, and all outliers. Percentiles describe observed performance; they do **not** establish a hard upper bound.
7. Determine a candidate deadline from the largest verified cleanup duration plus a separately justified engineering margin for measured clock/scheduler/IO uncertainty and host variance. The margin and its rationale must be reviewed; do not pick an arbitrary multiplier or percentile. If the candidate exceeds the remaining end-to-end budget, redesign the budget/architecture or reject the profile rather than silently shortening cleanup.
8. Repeat the full suite with the candidate deadline configured. Demonstrate that the watchdog fires at the intended boundary, all cleanup paths finish and verify within it, late/secondary triggers do not extend it, and cleanup failure results in quarantine rather than false terminal success.
9. Have an independent reviewer inspect raw evidence, clock semantics, watchdog independence, failure cases, margin rationale, and the exact numeric value before it is added to a new profile revision.

### End-to-end budget interaction

The 10-minute API-intake budget is an absolute upper bound through terminal finalization, not a separate execution allowance followed by unbounded cleanup.

- Before starting a sandbox, admission must prove that the remaining intake budget can accommodate the maximum 60-second sandbox wall time plus the approved cleanup budget and the separately measured/bounded evidence-and-terminal-finalization reserve. If not, do not launch; return a bounded infrastructure timeout/expiry result without creating a sandbox.
- A workload that exits early may use less than the reserved sandbox wall time, but admission must not depend on that optimistic outcome.
- Queue wait, retries, reconnects, supervisor recovery, cleanup, evidence verification/publication, and terminal commit all consume the same original intake-based budget. No stage resets it.
- The cleanup watchdog uses the earlier of the cleanup deadline and the remaining absolute intake deadline as its effective stop boundary. At the absolute deadline, unresolved cleanup is marked unverified/quarantined and independent cleanup continues; the API must not claim success.
- The evidence branch must also have a bounded finalization policy that fits the same absolute intake budget. Its timeout/incompleteness cannot block the cleanup branch; terminal outcome remains incomplete/infrastructure-failed if evidence is not durably verified by the terminal deadline.

**Approval gate:** the numeric cleanup deadline, clock/reboot semantics, watchdog mechanism, evidence-finalization reserve, and admission rule must be added together to a new reviewed resource-profile revision. Until then, no stress fixture, host proof, or execution enablement is authorized.

## 2. Output-limit behavior

1. Count stdout and stderr independently at the host-side collector, before writing to evidence storage.
2. Enforce a shared combined ceiling of 1,048,576 bytes. The per-stream counters each have the same 1,048,576-byte ceiling for independent accounting and fixture coverage.
3. On the first per-stream or combined ceiling breach, mark output overflow and request termination of the complete sandbox process tree.
4. Retain no more than the first 1 MiB combined across both streams. Do not buffer unbounded output in memory, temporary files, logs, or telemetry.
5. Drain stdout and stderr concurrently using independent non-blocking/pollable readers or an equivalently proven multiplexed implementation. A full pipe must not prevent draining the other. Each reader uses a fixed-size buffer; no unbounded queue or blocking evidence-store write may sit on the read path.
6. Count every byte read immediately in monotonic observed-byte counters, before retention or transformation. Then reserve retention budget under one shared atomic accounting operation across both readers, enforcing each stream's 1 MiB retained ceiling and the 1 MiB combined retained ceiling. A read buffer may cross a ceiling: retain only the prefix that fits the remaining reserved budget and discard the rest of that buffer. Never let two readers independently check then write against a stale combined count. Retain raw contiguous byte prefixes in separate stream artifacts, without decoding or newline normalization. The order in which concurrent readers reserve the shared budget is scheduler-dependent; do not claim deterministic inter-stream ordering. Record observed and retained counts separately.
7. On the first observed per-stream or combined breach, atomically record the breach and request complete sandbox/cgroup termination immediately; do not wait for pipe readers, storage, or client acknowledgement. Continue draining/discarding excess bytes with fixed-size buffers until EOF or the bounded cleanup deadline. A descendant inheriting a pipe must not keep the attempt alive: terminate the complete sandbox, and let the external watchdog complete cleanup if EOF does not arrive.
8. Pipe readers may write retained bytes only to a bounded local staging sink. If staging is unavailable/full, keep draining and discarding, mark evidence incomplete, and continue cleanup; never synchronously retry storage from a reader.
9. Classify the result as Output Limit Exceeded only after the host collector confirms the breach. A collector failure or uncertain process cleanup is an infrastructure failure, never a student verdict.
10. Record per-stream observed and retained byte counts, combined stored byte count, truncation flags, overflow flag, termination reason, and hashes of retained sanitized evidence. Never store hidden tests or expected outputs in guest-visible output artifacts.

## 3. Safety and validation constraints

- This profile is only a candidate for a disposable, single-tenant M0 proof VM.
- The disposable VM must have independently verified outer CPU, memory, PID, disk, and watchdog controls before any stress fixture.
- Do not infer outer VM capacity from the per-sandbox limits. Provider, region, VM size, and spend remain undecided.
- Verify Java 25 compilation/runtime and Python 3.14 behavior under this profile. If legitimate runtime startup or compilation requires more resources, stop and propose a versioned profile change; do not silently raise limits.
- Validate actual cgroup enforcement, runtime platform, network denial, output capture, process cleanup, and repeated failure behavior with host-side evidence.
- A profile document, schema-valid manifest, or passing synthetic validator is not runtime proof.
- Independent security review must approve the final profile and the host's outer safety envelope before M0 workloads are launched.

## 4. Change control

Any change to CPU, memory, PID, wall-time, output, scratch, or inode limits requires:
- A new profile revision and documented rationale.
- Updated protocol/schema/fixture/runbook references where applicable.
- Regression tests for both the new ceiling and the previous boundary.
- Independent review of any change that increases resource exposure.

