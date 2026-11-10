# M0 Host Preflight and Proof Runbook

## Purpose

The host preflight script checks whether a disposable Linux host matches the selected M0 baseline before any sandbox experiments begin.

It is deliberately read-only. It does not install packages, change host configuration, start or stop services, launch containers, pull images, execute student programs, or claim that gVisor isolation works.

## Selected proof baseline

- Ubuntu Server 24.04 LTS, x86_64.
- Linux kernel 5.6 or newer; record the exact kernel build.
- Unified cgroup v2.
- containerd 2.3 LTS with configuration version 3.
- gVisor runsc and containerd-shim-runsc-v1.
- gVisor runtime handler io.containerd.runsc.v1.
- VM-backed proof hosts explicitly use the gVisor systrap platform.
- Proposed M0 proof resource profile: `docs/specifications/m0-proof-resource-profile-v1.md`; values remain pending empirical validation and independent approval.
- Dedicated disposable host; no student data, production credentials, API services, or unrelated tenants.

The cloud provider and region are intentionally not selected in this runbook.

## Phase 0 — Host preflight

Run as an ordinary account with permission to inspect the containerd socket:

```bash
bash services/execution-runner/scripts/m0-host-preflight.sh
```

The script checks OS release, architecture, kernel minimum, cgroup v2, containerd LTS version, the locally resolved configuration dump, gVisor binaries, and containerd socket ownership/permissions. The configuration check is a preliminary local-file inspection; it does not prove that the running daemon loaded that exact configuration or that the configured handler is operational.

A successful result means only that the host matches these baseline checks. It does not prove that runsc starts, that systrap is active, that network access is blocked, or that resource limits are enforced.

Do not weaken a failed check to make the script pass. Investigate and record the host deviation; update the ADR before changing the baseline.

## Phase 1 — Runtime compatibility proof

On a disposable host only:

1. Record Ubuntu image identifier, kernel build, architecture, containerd package version and provenance, runsc version and provenance, shim version, and containerd config version.
2. Identify the actual running containerd daemon: record its systemd unit state, effective ExecStart arguments, process command line, and the configuration file path selected by those arguments. Resolve and record imported configuration files; do not assume that a standalone `containerd config dump` necessarily represents the daemon's effective configuration.
   - Treat systemd unit definitions, ExecStart arguments, process command lines, and imported configuration as potentially sensitive. Capture only the allowlisted fields needed to establish the daemon binary and configuration paths; redact tokens, credentials, URL user-info, environment values, and unrelated arguments before storing evidence. Never archive raw `/proc/<pid>/cmdline` or environment output.
3. Confirm from the effective daemon configuration that the runtime handler resolves to the expected runsc binary and shim. Record binary paths, ownership, permissions, package provenance, and cryptographic hashes.
4. Launch only a reviewed, digest-pinned, minimal test image through the gVisor handler.
5. Capture the runtime-reported platform and independently verify that systrap is selected.
6. Repeat after a host reboot and after a clean service restart.
7. Record cold-start and warm-start timings; do not extrapolate throughput from a single smoke test.

No student source, hidden tests, application secrets, or production data may be used.

## Phase 2 — Isolation and resource proof

Run the reviewed fixture matrix in `docs/specifications/m0-adversarial-fixture-contract.md` inside a disposable gVisor sandbox. The suite must be digest-pinned, source-reviewed, and contain no network callbacks or destructive host operations. Do not implement or execute fixture payloads until the disposable VM outer cgroup, watchdog, network containment, and recovery controls have been independently verified. In particular, before `M0-NET-006`, install and independently verify an outer-VM deny/blackhole rule for the metadata link-local destination (for example, IPv4 `169.254.169.254`); prove with host-side counters/packet observation that packets are dropped before any host uplink or metadata service can receive them. The probe originates only inside the sandbox. Never issue metadata requests from the host, never accept or store metadata responses, and mark the fixture blocked rather than running it if the outer deny cannot be proven.

| Area | Required evidence |
|---|---|
| Identity | Effective UID/GID is non-root; capabilities are dropped |
| Host boundary | No host paths, devices, namespaces, privileged socket, or credentials visible |
| Network | IPv4, IPv6, DNS, direct-IP, and loopback-to-host attempts fail. The metadata-address probe runs only from inside the sandbox after an independently verified outer-VM deny/blackhole rule drops the link-local destination before host uplink; host-side counters prove the drop and no metadata service is contacted |
| CPU | CPU quota is enforced under sustained load |
| Memory | cgroup memory ceiling is enforced; OOM is classified as infrastructure/resource outcome, not Accepted |
| Processes | PID ceiling stops fork/process floods |
| Time | Wall deadline stops infinite loops and reaps descendants |
| Filesystem | Base is read-only; scratch byte and inode ceilings are hard limits |
| Output | stdout/stderr are drained concurrently with fixed-size buffers; byte counters are updated before retention; a shared 1 MiB combined hard ceiling is enforced atomically; overflow triggers immediate complete-sandbox termination while readers drain/discard without blocking on storage |
| Cleanup | After success, compile failure, runtime failure, timeout, cancellation, OOM, output overflow, and forced termination, independently verify absence of the process tree, containerd task/container, shim, namespaces, cgroup, scratch, temporary mounts, and network-policy state before terminal acknowledgement |

A test passes only with captured host-side evidence and an assertion that checks the expected failure mode. A command returning non-zero by itself is not sufficient proof.

## Phase 3 — Cancellation, recovery, and repeatability

- Cancel while the workload is running; verify the complete process tree is terminated.
- Race cancellation against natural exit, the 10-minute intake-based deadline, the 60-second sandbox watchdog, and output overflow. Verify one durable arbitration winner, immutable primary cause, retained secondary trigger records, and one terminal result.
- Have a workload exceed an output ceiling and exit before the pipe reader drains buffered bytes. Verify natural exit remains provisional until both streams reach EOF and final counters are reconciled; a late-discovered output breach must block success.
- Repeat cancellation and watchdog signals; verify idempotent termination/cleanup with no duplicate task or terminal transition. A late cancellation after finalization must not rewrite the result.
- Restart the watchdog/supervisor during active execution and termination; verify the original persisted deadline is re-armed without granting a fresh budget.
- Confirm cleanup before acknowledging cancellation.
- Deliver the same test job twice; verify one logical execution and one result.
- In separate controlled subcases, restart the runner, host supervisor, and containerd daemon during an active test; verify journal reconciliation, no duplicate execution, and absence of every process/task/container/shim/namespace/cgroup/mount/scratch/network-policy resource before terminal acknowledgement.
- Repeat each failure-path test enough times to expose races.
- Preserve correlation IDs and timestamps without logging student source, hidden inputs, expected outputs, or secrets.

## Evidence bundle

Use `docs/specifications/m0-proof-resource-profile-v1.md` as the proposed versioned resource profile and `docs/schemas/m0-proof-evidence.schema.json` as the versioned manifest contract for the proof report. The evidence manifest must record the exact resource-profile ID, revision, and applied limits. The manifest records structured outcomes and references to sanitized evidence files; it must not embed raw logs, student code, hidden test data, credentials, or private artifact URLs. A schema-valid manifest is a completeness aid, not proof that the underlying tests actually ran or passed.

Before a proof can be classified as passed, a separate host-side evidence verifier must resolve every manifest reference against the immutable evidence store and independently verify the exact published object version, SHA-256, byte count, approved evidence root, and redaction disposition. JSON Schema validation checks manifest structure only; it does not establish object existence, integrity, durability, or provenance.

Evidence publication must follow the crash-safe ordering in Section 7.1 of `m0-runtime-proof-harness-design.md`: sanitize before publication; durably stage and publish immutable content-addressed objects; read back and verify bytes; durably journal verified references; persist the final manifest; then commit the terminal result. A terminal acknowledgement must not precede durable evidence disposition and independently verified cleanup disposition.

Exercise crash injection between each publication/journal/manifest/terminal step. Verify that orphan staging objects are never treated as evidence, missing or mismatched objects force an incomplete/non-passed result, and a persisted manifest without a terminal journal transition is reconciled idempotently. Evidence-store failure must never block the independent termination and cleanup controller.

Finalization must run cleanup and evidence handling as two independently supervised branches. Start process termination and cleanup immediately when the attempt enters finalization; do not wait for evidence capture, redaction, hashing, publication, or manifest generation. Persist cleanup disposition and evidence disposition separately. Only after both are durable may the supervisor perform one terminal compare-and-set. A passed result requires successful verified cleanup and complete verified evidence; either branch failing, timing out, or remaining uncertain forces an incomplete/infrastructure-failed outcome. On restart, reconcile each branch independently before resuming finalization.

Store a proof report outside the host and include:

- Host/provider/region and image identifier (once selected).
- Kernel, containerd, runsc, shim, OCI image digests, and package provenance.
- Exact commands, timestamps, exit statuses, and sanitized logs.
- Test fixture repository revision and immutable image digest.
- Expected versus observed behavior for every test.
- Resource measurements, cold/warm latency, and concurrency results.
- Cleanup verification and any orphan-process scan.
- Known limitations, failed tests, deviations, and remediation.
- Reviewer and approval date.

Never include credentials, production secrets, real student code, hidden test data, or private artifact URLs.

## Stop conditions

Stop the proof and do not enable the executor if:

- The host or runtime version differs from the approved baseline without an ADR update.
- The actual gVisor platform cannot be independently verified.
- Any network path, host mount, privileged socket, capability, or secret is exposed.
- Any configured resource limit is best-effort rather than enforced.
- Cancellation or cleanup cannot be proven.
- A failure is unexplained or the evidence bundle is incomplete.

Passing this runbook permits a separate M0 security review. It does not authorize production deployment or student execution.
