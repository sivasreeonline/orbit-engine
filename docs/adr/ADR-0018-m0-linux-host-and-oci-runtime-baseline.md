# ADR-0018: M0 Linux Host and OCI Runtime Baseline

- Status: Accepted for the M0 proof environment only; production approval remains blocked.
- Decision owner: Sky High architecture.
- Related: ADR-0008, ADR-0009, issue #10, docs/specifications/m0-execution-proof.md.

## Context

The Go runner must execute hostile Java 25 and Python 3.14 workloads outside the application control plane. The runner remains fail-closed until the host, OCI runtime, gVisor isolation, resource enforcement, network denial, cancellation, and cleanup gates are demonstrated with reproducible evidence.

The architecture already selects Linux AMD64 and gVisor as the conditional sandbox candidate. This ADR narrows the M0 proof baseline without claiming that the selected runtime is already compatible or secure in our environment.

## Decisions

### Host operating system and architecture

- Use Ubuntu Server 24.04 LTS on Linux AMD64 for the initial M0 proof.
- Require a supported Linux kernel meeting gVisor's documented minimum (Linux 5.6+); capture the exact kernel build in every proof report.
- Keep the host dedicated to execution proof workloads. Do not colocate the API, database, queue publisher, student-facing services, or unrelated tenants.
- The cloud provider and region remain deferred until the Neon region, network path, operating cost, and operational access model are confirmed. No infrastructure is provisioned or spend authorized by this ADR.

### OCI lifecycle manager

- Use containerd 2.3 LTS as the M0 OCI lifecycle manager.
- Use the containerd v3 configuration format and the gVisor containerd runtime handler (io.containerd.runsc.v1 / containerd-shim-runsc-v1).
- Do not add Docker Engine or Kubernetes for the single-host M0 proof. Revisit orchestration only when measured capacity and operational needs justify it.
- Pin the exact containerd release and package provenance in the host build manifest. Track supported security updates and test upgrades before rollout.

### gVisor runtime

- Use the official gVisor runsc OCI runtime and its matching shim/sidecar artifacts.
- Pin the exact gVisor release and verify package/release integrity during provisioning. Do not use a floating latest runtime in a reproducible or production build.
- Explicitly select systrap for VM-backed hosts. Do not rely on an implicit default.
- KVM is not the initial VM configuration. Consider it only if a later bare-metal host is selected and the isolation/performance proof justifies the change.
- Do not fall back to the deprecated ptrace platform as a performance or compatibility workaround.

### Privileged host boundary

- The containerd control socket must remain a private, root-owned Unix socket. Never expose it over TCP or mount it into a student sandbox.
- Do not grant the non-root runner broad access to the containerd socket; such access can confer host-level control.
- Before implementing the executor, prove a least-privilege launch boundary: either a narrowly scoped host supervisor with a typed, allowlisted request API, or a separately reviewed rootless containerd design. The proof must show that the runner cannot request privileged OCI settings, arbitrary host mounts, host networking, or arbitrary runtime binaries.
- The student workload always runs as a non-root identity with no capabilities, no host paths, no privileged mode, and no application credentials.

## M0 proof gates

The selected versions are candidates for proof, not compatibility claims. M0 must record exact versions and pass all of the following before the executor can replace UnconfiguredExecutor:

1. Prove containerd 2.3 LTS and the pinned runsc release work together on the selected Ubuntu kernel.
2. Verify the gVisor runtime actually starts and reports the expected systrap platform.
3. Deny outbound IPv4/IPv6, DNS, loopback-to-host escape paths, cloud metadata endpoints, and direct-IP egress from student workloads.
4. Enforce non-root UID/GID, dropped capabilities, read-only base filesystem, bounded scratch bytes and inodes, CPU, memory, PID, wall-clock, stdout, and stderr limits.
5. Verify no host filesystem, containerd socket, device, credential, or privileged host namespace is visible to student code.
6. Exercise success, compile failure, runtime failure, timeout, cancellation, OOM, output flood, process flood, filesystem traversal, symlink attacks, and forced host-side termination.
7. Verify process-tree termination, sandbox removal, scratch cleanup, and idempotent result behavior after every terminal path.
8. Measure cold-start and warm-start latency, memory overhead, and sustainable concurrency using representative Java and Python fixtures. Do not infer capacity from vendor benchmarks.
9. Complete a threat review and record residual risks, patch/upgrade procedure, monitoring, and incident response.

## Consequences

- M0 has a reproducible Linux/OCI baseline and avoids introducing a cluster orchestrator before capacity requires one.
- The provider/region and runner-to-containerd privilege boundary remain explicit blockers; neither is silently inferred.
- gVisor is defense in depth, not a guarantee against all host compromise.
- A passing M0 proof authorizes integration testing only. It does not authorize production execution or student submissions.
- UnconfiguredExecutor and the current health/readiness behavior remain unchanged until all gates and a separate security approval pass.

## References

- [gVisor installation guide](https://gvisor.dev/docs/user_guide/install/)
- [gVisor containerd quick start](https://gvisor.dev/docs/user_guide/containerd/quick_start/)
- [gVisor production guide](https://gvisor.dev/docs/user_guide/production/)
- [gVisor platform guide](https://gvisor.dev/docs/user_guide/platforms/)
- [containerd release support](https://github.com/containerd/containerd/blob/main/RELEASES.md)
- [containerd configuration versions](https://containerd.io/releases/)
