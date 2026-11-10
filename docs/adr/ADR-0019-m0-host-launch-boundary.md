# ADR-0019: M0 Host Launch Boundary

- Status: Proposed; Candidate A and Candidate B remain under evaluation. No launch-boundary candidate is selected; independent security review and candidate-specific host evidence are pending.
- Related: ADR-0018, `m0-runtime-proof-harness-design.md`, `m0-sandbox-security-review-packet.md`.

Implementation contract for the proposed supervisor/journal/watchdog boundary: `docs/specifications/m0-supervisor-journal-implementation-contract.md`. It does not change ADR-0019's proposed status or authorize implementation.

- No production or student execution is authorized by this proposal.

## Context

ADR-0018 selects containerd 2.3 LTS and gVisor runsc with systrap as the M0 proof candidate, but deliberately leaves the runner-to-containerd privilege boundary open.

The Go runner must not receive broad access to the root-owned containerd socket. A compromised runner or untrusted request must not be able to select arbitrary OCI settings, mounts, devices, runtime binaries, network policy, or host paths.

A rootless alternative is attractive because it can reduce the host privilege exposed to the container runtime. However, "rootless gVisor" is not one uniform mode:

- The gVisor `runsc --rootless` mode documents that `create` is unsupported, Netstack is unavailable, and cgroup configuration errors are ignored. Those constraints conflict with this M0 design's containerd lifecycle, network isolation, and hard resource-enforcement requirements.
- gVisor also documents caller-configured user namespaces through higher-level engines, with multi-UID mappings and network namespace setup. This is a different path and must not be conflated with the `runsc --rootless` CLI mode.
- containerd's rootless mode uses user namespaces/RootlessKit; its documentation requires cgroup v2 and systemd for cgroup management.

Therefore, rootless containerd with caller-configured user namespaces remains a candidate for an explicit compatibility experiment, but it is not assumed to satisfy M0 requirements.

## Candidates under evaluation

- **Candidate A:** a dedicated, narrowly scoped host supervisor is the only application principal permitted to call rootful containerd; the Go runner remains unprivileged and has no direct containerd socket access.
- **Candidate B:** rootless containerd with caller-configured user namespaces, subject to the exact compatibility and isolation proof requirements below.

Neither candidate is selected. The same control set and evidence standard apply to both. The decision may select exactly one candidate, reject both, or defer; this proposal is not permission to implement or provision either candidate before all review and qualification gates are met.

### Candidate A — rootful host supervisor requirements

1. Run as a dedicated host service on the disposable proof VM. It is the only application principal permitted to access the root-owned containerd socket.
2. Expose only a private Unix-domain socket. Authenticate the caller using socket filesystem permissions and peer credentials; allow only the designated runner identity.
3. Accept a strict typed request containing approved proof-run ID, fixture ID, attempt ID, correlation ID, runtime profile ID, resource profile ID, and idempotency key. Resolve the authoritative intake timestamp and derived deadlines from the durable control-plane attempt record; never trust a caller/runner-supplied timestamp or deadline.
4. Resolve all OCI settings from root-owned immutable profiles. Do not accept arbitrary OCI JSON, image names/tags, entrypoints, commands, arguments, environment, mounts, devices, namespaces, capabilities, host networking, or runtime binary paths.
5. Verify image and fixture digests and provenance against a local allowlist before launch.
6. Enforce per-sandbox cgroup v2 limits and network-deny policy through the trusted host runtime configuration.
7. Keep a durable lifecycle journal. On finalization, start process termination/resource cleanup and evidence collection as independent branches; evidence collection, redaction, hashing, publication, or manifest generation must never delay cleanup. Persist each branch disposition separately. A terminal compare-and-set is permitted only after both dispositions are durable; terminal success additionally requires verified absence of the workload process tree, containerd task/container, shim process, sandbox namespaces, cgroup, scratch directory, temporary mounts, and network-policy state, plus complete independently verified evidence. Any uncertain or failed branch is incomplete/infrastructure-failed, never success.
8. Use systemd hardening and a minimal capability/syscall surface appropriate to the exact operations. The hardening profile must be tested; do not copy a generic unit file and assume it is safe.
9. Never expose the supervisor socket, containerd socket, journal, or host evidence directory to the guest.
10. Fail closed on unknown fields, stale profiles, missing digests, authorization failure, uncertain cleanup, or unsupported runtime settings.

11. Place the supervisor socket beneath a root-owned, non-runner-writable directory; validate socket inode, owner, group, mode, and parent path; reject symlink substitution.
12. Authenticate every connection using kernel-provided Unix peer credentials and compare against one configured runner UID/GID. Authorize each operation against a durable proof-run/fixture/attempt record; never trust identity claims in request fields.
13. Bound request size, framing, concurrency, and operation duration; reject malformed UTF-8/JSON, duplicate keys, unknown fields, trailing data, and unexpected file descriptors.
14. Keep the runner outside the containerd socket access group. Only the dedicated supervisor identity may access containerd; no generic containerd proxy or command API is permitted.
15. Treat rootful containerd access as host-level authority. Record the exact supervisor capability set, systemd hardening, writable paths, syscall surface, and residual privilege risk; if privilege cannot be sufficiently constrained, revisit the rootless alternative.
16. Persist operation intent before ordinary side effects and observed state afterward. Enforce durable unique idempotency/attempt keys and compare-and-set terminal transitions. A single host-owned trigger arbiter serializes competing observations. On the first termination trigger, capture its boot ID, BOOTTIME timestamp, sequence and authenticated source, then request workload termination immediately; persist the trigger and `TERMINATING` transition concurrently without delaying termination. Persistence failure means continue cleanup, stop admission and quarantine. Natural exit remains provisional and is ordered by the same arbiter; terminal compare-and-set waits for both durable finalization branches and reconciliation of all triggers. The first accepted trigger fixes the primary cause, later triggers are retained as secondary causes, and late cancellation cannot rewrite finalization/terminal state. Repeated cancel/watchdog signals converge on one idempotent termination/cleanup operation.
17. Derive the immutable 10-minute end-to-end deadline from the control plane's persisted API intake timestamp, including queue wait/retries/restarts; derive the 60-second sandbox wall deadline from host-observed start. Re-arm original deadlines after restart; never reset or extend them. Caller/runner timestamps are not authoritative.
18. On restart, reconcile by deterministic supervisor-owned sandbox identity against containerd tasks, shim processes, cgroups, namespaces, mounts, network state, and scratch. Never blindly repeat create or adopt unknown resources.
19. Cleanup runs independently of client connections. Terminal success requires verified absence of every workload resource; uncertainty means infrastructure failure and host quarantine.
20. Define and independently approve a finite cleanup deadline in the versioned proof profile before the Phase B full M0 adversarial stress campaign. Phase A calibration may run only under its separate written authorization, fixed synthetic scenario allowlist, verified outer-VM resource/network boundary, and independent VM hard-stop control. The outer safety cutoff is not a cleanup deadline and cannot be recorded as successful cleanup.
21. Persist attempt, idempotency, operation, trigger, and independent finalization-branch records with unique keys, immutable request digests and state versions. Keep `supervisor_generation`, `attempt_generation`, `operation_sequence`, `trigger_sequence`, and `branch_generation` distinct. Claim the idempotency key, logical attempt, initial attempt generation, operation sequence, operation ID, and first operation intent in one durable transaction while recording the current supervisor generation. Same key/digest returns the recorded operation; changed digest or reused logical attempt is a conflict.
22. Treat containerd and the journal as separate failure domains: persist intent before side effects, inspect actual resources after uncertain outcomes, and reconcile before retry. Do not claim cross-system exactly-once execution. Never blindly repeat create/start after a crash.
23. Hold one exclusive host-wide kernel process lock for the full lifetime of the selected supervisor's candidate-approved containerd access. For Candidate A this covers rootful access; for Candidate B it covers the dedicated non-root supervisor's rootless daemon access. A replacement supervisor may act only after the old process has exited and released the kernel lock; it then allocates a new durable `supervisor_generation` and reclaims non-terminal attempts by compare-and-set increment of their `attempt_generation` before accepting work. A database lease or generation integer alone cannot fence a paused process from containerd. Before each candidate-approved side effect, verify lock ownership and both current generations; a stale supervisor fail-stops. Prove the lock and generation fencing under pause, crash, and restart fault injection.
24. Acknowledge an operation only after its journal state and bounded response descriptor are durable. A lost response followed by the same idempotency key/digest returns the recorded result without repeating the side effect. Terminal results are immutable; cleanup/evidence branch updates are compare-and-set operations fenced by the current `supervisor_generation`, `attempt_generation`, `branch_generation`, and expected branch state version.

### Explicitly prohibited

- Adding the runner to the `docker` group or any group that grants broad containerd control.
- Exposing containerd's gRPC socket over TCP.
- Passing arbitrary OCI specs or shell commands through the supervisor.
- Mounting the supervisor or containerd socket inside a sandbox.
- Allowing guest-controlled image pulls, registries, network destinations, host paths, devices, or resource ceilings.
- Treating gVisor as a substitute for host isolation, patching, or a separate security review.

## Candidate B — rootless containerd experiment

Candidate B is eligible only through a disposable-host experiment using rootless containerd plus the gVisor caller-configured user-namespace path. It is evaluated against the same security controls and host qualification evidence as Candidate A.

It is eligible only if the exact pinned versions demonstrate all of the following:
- containerd and runsc lifecycle works through the actual containerd shim, including create/start/stop/delete.
- systrap is independently verified.
- Non-root host identity and intended container UID/GID mappings are proven.
- cgroup v2 CPU, memory, and PID limits are actually enforced, not ignored.
- Network namespace isolation and default-deny IPv4/IPv6/DNS/direct-IP/loopback/metadata behavior are independently proven.
- Host abstract Unix sockets, containerd state, user namespace mappings, and host paths are not exposed.
- Scratch, output, cancellation, restart recovery, and cleanup gates pass.
- The resulting privilege model is demonstrably narrower than the proposed rootful supervisor.

If any criterion is unsupported or cannot be proven, record the rootless path as rejected for this M0 baseline. Do not fall back to `runsc --rootless` or weaken any required control.

## Decision matrix

| Criterion | Rootful containerd + typed host supervisor | Rootless containerd + caller-configured userns |
|---|---|---|
| Runner has direct containerd authority | No, if supervisor boundary is enforced | No, if user daemon is isolated to dedicated identity |
| Host privilege blast radius | Higher; supervisor is privileged and requires strict minimization | Lower in principle; user namespace and delegated host resources still need review |
| cgroup v2 enforcement | Must be proven with rootful daemon | Requires cgroup v2, systemd and correct controller delegation |
| Network isolation | Host firewall/network namespace policy must be proven | Rootless network namespace/RootlessKit behavior adds another layer to prove |
| gVisor lifecycle compatibility | Expected containerd integration path; exact versions still need proof | Must prove caller-configured userns + containerd shim path; do not infer from CLI rootless mode |
| Operational complexity | Dedicated privileged service and API hardening | User namespaces, subordinate IDs, RootlessKit, cgroup delegation and networking |
| M0 disposition | Candidate A; not selected or qualified | Candidate B; not selected or qualified |

## Cleanup calibration authorization boundary

Cleanup deadline qualification is a two-phase gate; it is not a reason to choose an arbitrary timeout and is not a reason to disable measurement.

**Phase A — controlled calibration:** permit only a separately authorized, synthetic-only campaign on a dedicated disposable VM. Before launch, independently verify the outer VM CPU/memory/PID/disk/wall-time boundary, the VM hard-stop/rebuild control, default-deny network containment, metadata-address denial before host uplink, exact runtime identity, the journal backend proof gate, and the fixed digest-pinned calibration bundle. The host owner and independent security reviewer must approve an immutable authorization manifest that lists the exact host/runtime/supervisor/journal/watchdog digests, allowed CAL-CLEAN scenario IDs, run count, finite outer safety cutoff, evidence location, expiry, and stop authority.

Phase A must exercise the same supervisor cleanup controller and journal path proposed for M0. It must not expose a public API, student execution route, general-purpose command interface, or ordinary job queue. It must not accept student source, arbitrary commands, caller-selected OCI settings, or caller-selected limits. No full 35-fixture adversarial suite runs in Phase A.

The outer VM safety cutoff exists only to contain a failed experiment. If it fires, the host is quarantined or destroyed and the sample is failed/unverified; it is not a successful cleanup measurement. The cleanup timer remains anchored to the earliest host-observed trigger and is not reset by repeated triggers, supervisor restart, journal latency/failure, containerd recovery, or evidence-store failure. Cleanup and evidence work remain independent.

**Phase B — full M0 proof:** remains blocked until Phase A raw measurements, the uncertainty-margin rationale, reboot/clock semantics, independent watchdog, and numeric cleanup deadline are approved. The numeric cleanup deadline and bounded evidence/terminal reserve must be recorded together in a new resource-profile revision, along with the 10-minute admission reserve calculation. The full 35-fixture matrix may run only after this approval.

Neither Phase A nor Phase B authorizes student or production execution. The runner remains unprivileged and UnconfiguredExecutor remains fail-closed.

## Independent review package

Complete `docs/security/m0-independent-security-review-checklist.md` and the machine-readable record schema/template before accepting this ADR.

The reviewer must compare the rootful supervisor against rootless containerd with caller-configured user namespaces using the same stable controls and evidence standards. The `runsc --rootless` CLI mode is separate and must not be represented as equivalent.

An architecture decision does not authorize privileged implementation. Implementation, Phase A, Phase B, student execution and production execution remain separate gates; the review-record schema keeps all actual authorization flags false.

## Required gates before accepting this ADR

1. Independent reviewer evaluates both privilege models and the exact gVisor rootless-mode distinctions.
2. A disposable host proves the pinned runtime and supervisor/userns path without running student code.
3. Negative authorization tests prove the runner cannot access containerd or request forbidden settings.
4. Host-side evidence proves network, cgroup, filesystem, process, cancellation, and cleanup requirements.
5. The chosen option is recorded with exact package versions, profiles, unit hardening, and residual risks.

## Consequences

- The runner remains unprivileged and `UnconfiguredExecutor` remains the only executor implementation.
- Neither Candidate A nor Candidate B is selected. Candidate A's privileged attack surface and Candidate B's user-namespace, helper, cgroup-delegation and network boundaries remain explicit independent review items.
- Candidate B is not discarded categorically; it must prove the exact required controls to be eligible for selection.
- No cloud provider, region, VM size, or spend is selected or authorized.
- No implementation, workload launch, or student execution is authorized until independent review and evidence gates pass.

## References

- [gVisor rootless modes and documented limitations](https://gvisor.dev/docs/user_guide/rootless/)
- [containerd rootless setup and cgroup v2 requirements](https://github.com/containerd/containerd/blob/main/docs/rootless.md)
- [gVisor containerd quick start](https://gvisor.dev/docs/user_guide/containerd/quick_start/)
- [gVisor platform guide](https://gvisor.dev/docs/user_guide/platforms/)


## Architecture decision closure dossier

The candidate definitions, same-control comparison, evidence rules, permitted outcomes and no-go triggers are controlled in `docs/adr/ADR-0019-decision-dossier.md`. Use `docs/schemas/m0-adr-0019-decision-record.schema.json` and its blank template for the independent decision.

ADR-0019 remains **Proposed** until a real independent reviewer completes the comparison and the selected candidate has its own exact-host qualification record. The rootless candidate means rootless containerd with caller-configured user namespaces; it does not mean the separate `runsc --rootless` CLI mode.

An accepted M0 proof boundary does not authorize privileged implementation. The decision schema keeps implementation, Phase A, Phase B, student and production authorization flags false.


## Upstream compatibility evidence

The current upstream compatibility review is recorded in `docs/adr/ADR-0019-upstream-compatibility-evidence.md`. It is documentary evidence only; ADR-0019 remains Proposed and neither candidate is qualified or selected. Any completed review must pin the exact upstream source revisions/content digests before relying on branch-head documentation.


## Immutable upstream source baseline

The immutable upstream source set is recorded in `docs/adr/ADR-0019-upstream-source-manifest.json`; the exact manifest SHA-256 must be embedded in any completed ADR-0019 decision record. A reviewer must check the seven source pins and recorded signature-verification status. The branch-head URLs are discovery references only; the manifest points to immutable commit URLs and records Git blob SHA-1 plus content SHA-256.
