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
- Dedicated disposable host; no student data, production credentials, API services, or unrelated tenants.

The cloud provider and region are intentionally not selected in this runbook.

## Phase 0 — Host preflight

Run as an ordinary account with permission to inspect the containerd socket:

```bash
bash services/execution-runner/scripts/m0-host-preflight.sh
```

The script checks OS release, architecture, kernel minimum, cgroup v2, containerd LTS version/configuration, gVisor binaries, and containerd socket ownership/permissions.

A successful result means only that the host matches these baseline checks. It does not prove that runsc starts, that systrap is active, that network access is blocked, or that resource limits are enforced.

Do not weaken a failed check to make the script pass. Investigate and record the host deviation; update the ADR before changing the baseline.

## Phase 1 — Runtime compatibility proof

On a disposable host only:

1. Record Ubuntu image identifier, kernel build, architecture, containerd package version and provenance, runsc version and provenance, shim version, and containerd config version.
2. Confirm the containerd runtime handler resolves to runsc.
3. Launch only a reviewed, digest-pinned, minimal test image through the gVisor handler.
4. Capture the runtime-reported platform and independently verify that systrap is selected.
5. Repeat after a host reboot and after a clean service restart.
6. Record cold-start and warm-start timings; do not extrapolate throughput from a single smoke test.

No student source, hidden tests, application secrets, or production data may be used.

## Phase 2 — Isolation and resource proof

Run a reviewed adversarial fixture suite inside a disposable gVisor sandbox. The suite must be digest-pinned, source-reviewed, and contain no network callbacks or destructive host operations.

| Area | Required evidence |
|---|---|
| Identity | Effective UID/GID is non-root; capabilities are dropped |
| Host boundary | No host paths, devices, namespaces, privileged socket, or credentials visible |
| Network | IPv4, IPv6, DNS, direct-IP, loopback-to-host, and metadata-service attempts fail |
| CPU | CPU quota is enforced under sustained load |
| Memory | cgroup memory ceiling is enforced; OOM is classified as infrastructure/resource outcome, not Accepted |
| Processes | PID ceiling stops fork/process floods |
| Time | Wall deadline stops infinite loops and reaps descendants |
| Filesystem | Base is read-only; scratch byte and inode ceilings are hard limits |
| Output | stdout and stderr are independently bounded |
| Cleanup | Sandbox and scratch are removed after success, compile failure, runtime failure, timeout, cancellation, OOM, output overflow, and forced termination |

A test passes only with captured host-side evidence and an assertion that checks the expected failure mode. A command returning non-zero by itself is not sufficient proof.

## Phase 3 — Cancellation, recovery, and repeatability

- Cancel while the workload is running; verify the complete process tree is terminated.
- Confirm cleanup before acknowledging cancellation.
- Deliver the same test job twice; verify one logical execution and one result.
- Restart the runner during a test; verify no orphan process or scratch directory remains.
- Repeat each failure-path test enough times to expose races.
- Preserve correlation IDs and timestamps without logging student source, hidden inputs, expected outputs, or secrets.

## Evidence bundle

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
