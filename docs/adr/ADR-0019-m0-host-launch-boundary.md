# ADR-0019: M0 Host Launch Boundary

- Status: Proposed; recommended for disposable M0 proof only, pending independent security review and runtime evidence.
- Related: ADR-0018, `m0-runtime-proof-harness-design.md`, `m0-sandbox-security-review-packet.md`.
- No production or student execution is authorized by this proposal.

## Context

ADR-0018 selects containerd 2.3 LTS and gVisor runsc with systrap as the M0 proof candidate, but deliberately leaves the runner-to-containerd privilege boundary open.

The Go runner must not receive broad access to the root-owned containerd socket. A compromised runner or untrusted request must not be able to select arbitrary OCI settings, mounts, devices, runtime binaries, network policy, or host paths.

A rootless alternative is attractive because it can reduce the host privilege exposed to the container runtime. However, "rootless gVisor" is not one uniform mode:

- The gVisor `runsc --rootless` mode documents that `create` is unsupported, Netstack is unavailable, and cgroup configuration errors are ignored. Those constraints conflict with this M0 design's containerd lifecycle, network isolation, and hard resource-enforcement requirements.
- gVisor also documents caller-configured user namespaces through higher-level engines, with multi-UID mappings and network namespace setup. This is a different path and must not be conflated with the `runsc --rootless` CLI mode.
- containerd's rootless mode uses user namespaces/RootlessKit; its documentation requires cgroup v2 and systemd for cgroup management.

Therefore, rootless containerd with caller-configured user namespaces remains a candidate for an explicit compatibility experiment, but it is not assumed to satisfy M0 requirements.

## Proposed decision

For the initial M0 proof, use a dedicated, narrowly scoped host supervisor as the only caller of rootful containerd. Keep the Go runner unprivileged and deny it direct access to the containerd socket.

This is a proposed proof boundary, not permission to implement or provision it before the gates below are met.

### Host supervisor requirements

1. Run as a dedicated host service on the disposable proof VM. It is the only application principal permitted to access the root-owned containerd socket.
2. Expose only a private Unix-domain socket. Authenticate the caller using socket filesystem permissions and peer credentials; allow only the designated runner identity.
3. Accept a strict typed request containing approved proof-run ID, fixture ID, attempt ID, correlation ID, runtime profile ID, resource profile ID, deadline, and idempotency key.
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
16. Persist operation intent before side effects and observed state after them. Enforce durable unique idempotency/attempt keys and compare-and-set terminal transitions.
17. On restart, reconcile by deterministic supervisor-owned sandbox identity against containerd tasks, shim processes, cgroups, namespaces, mounts, network state, and scratch. Never blindly repeat create or adopt unknown resources.
18. Cleanup runs independently of client connections. Terminal success requires verified absence of every workload resource; uncertainty means infrastructure failure and host quarantine.
19. Define a finite cleanup deadline in the approved proof profile before stress testing; measure it from the termination trigger and validate it under worst-case failure and restart conditions. An unset or unvalidated cleanup deadline blocks stress testing and cannot be replaced by an assumed default.

### Explicitly prohibited

- Adding the runner to the `docker` group or any group that grants broad containerd control.
- Exposing containerd's gRPC socket over TCP.
- Passing arbitrary OCI specs or shell commands through the supervisor.
- Mounting the supervisor or containerd socket inside a sandbox.
- Allowing guest-controlled image pulls, registries, network destinations, host paths, devices, or resource ceilings.
- Treating gVisor as a substitute for host isolation, patching, or a separate security review.

## Alternative: rootless containerd experiment

Before the proposed rootful supervisor is accepted, the M0 design review should consider a disposable-host experiment using rootless containerd plus the gVisor caller-configured user-namespace path.

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
| M0 disposition | Recommended candidate, not yet approved | Alternative proof candidate; not yet tested |

## Required gates before accepting this ADR

1. Independent reviewer evaluates both privilege models and the exact gVisor rootless-mode distinctions.
2. A disposable host proves the pinned runtime and supervisor/userns path without running student code.
3. Negative authorization tests prove the runner cannot access containerd or request forbidden settings.
4. Host-side evidence proves network, cgroup, filesystem, process, cancellation, and cleanup requirements.
5. The chosen option is recorded with exact package versions, profiles, unit hardening, and residual risks.

## Consequences

- The runner remains unprivileged and `UnconfiguredExecutor` remains the only executor implementation.
- The rootful supervisor is only a proposed M0 proof candidate; its privileged attack surface is an explicit review item.
- Rootless containerd is not discarded categorically; it must prove the exact required controls before it can replace the proposed candidate.
- No cloud provider, region, VM size, or spend is selected or authorized.
- No implementation, workload launch, or student execution is authorized until independent review and evidence gates pass.

## References

- [gVisor rootless modes and documented limitations](https://gvisor.dev/docs/user_guide/rootless/)
- [containerd rootless setup and cgroup v2 requirements](https://github.com/containerd/containerd/blob/main/docs/rootless.md)
- [gVisor containerd quick start](https://gvisor.dev/docs/user_guide/containerd/quick_start/)
- [gVisor platform guide](https://gvisor.dev/docs/user_guide/platforms/)
