# ADR-0018: M0 Linux Runner Host Evaluation

- **Status:** Proposed — not approved for provisioning
- **Date:** 2026-11-13
- **Scope:** Temporary M0 security and compatibility proof only; not a production capacity decision

## Context

M0 requires a real Linux host to validate the Go runner, OCI lifecycle, gVisor isolation, resource enforcement, cancellation and cleanup. The current development machine is Windows on ARM64. It is suitable for Go protocol/unit tests and frontend work, but a successful local Docker run on Windows is not evidence that the Linux gVisor isolation boundary is correct.

The existing gVisor ADR is conditional. gVisor officially supports Linux on AMD64 and ARM64 and requires Linux 5.6 or newer. Its production guidance recommends the systrap platform when gVisor runs inside a VM; KVM is the preferred performance path on bare metal. M0 must measure the actual selected host and platform rather than assume capacity or compatibility.

## Proposed evaluation target

Evaluate one temporary AWS EC2 Graviton4 general-purpose VM:

- **Region:** Asia Pacific (Hyderabad), `ap-south-2`
- **Instance candidate:** `m8g.xlarge`
- **Architecture:** ARM64 / Graviton4
- **Capacity:** 4 vCPU, 16 GiB RAM
- **Operating system candidate:** Ubuntu 24.04 LTS ARM64, with a supported Linux kernel at or above 5.6
- **OCI runtime:** Docker Engine initially, with gVisor `runsc` registered as the OCI runtime
- **gVisor platform:** `systrap` while running inside the EC2 VM
- **Workload:** isolated M0 test runner only; no production/student traffic

AWS documentation lists M8g instances in Hyderabad. gVisor documentation lists ARM64 support and describes the VM-versus-bare-metal platform trade-off. The proposed host is therefore a technically plausible low-friction evaluation target, not a claim that the full stack has already been validated.

## Indicative cost

A third-party AWS price tracker reported approximately **USD 94.59/month** for an `m8g.xlarge` in `ap-south-2` at the time of research, using 730 hours and a small EBS gp3 boot disk. This is an estimate, not an AWS quote. It excludes applicable taxes, additional disk, snapshots, network transfer, monitoring, support, and any optional public IPv4 address. Spot pricing is lower but is intentionally excluded from the M0 baseline because interruptions would interfere with reliability and cleanup testing.

No cloud account, VM, paid service, or deployment is created by this proposal.

## Required controls for the evaluation

- Use a dedicated test account/project and a separate VPC/subnet for the runner host.
- Do not expose an unauthenticated runner listener to the public internet.
- Keep administrative access private; prefer a managed session channel over an open SSH ingress rule.
- Use a minimal instance role and short-lived control-plane credentials; do not place secrets in student sandboxes.
- Enforce sandbox network denial independently of host firewall policy.
- Run student processes as non-root with ephemeral filesystems and explicit CPU, memory, PID, wall-clock and output limits.
- Pin runtime images by immutable digest and verify source/test artifact hashes before use.
- Keep the runner host free of database credentials and unrelated production workloads.
- Capture structured, redacted operational evidence and never log hidden tests, expected outputs, source code or credentials.
- Destroy the evaluation host and associated resources after the proof unless a separate decision approves continued use.

The exact API-to-runner private transport, authentication mechanism, artifact retrieval path, host egress policy and operational ownership require separate design and approval before opening any runner endpoint.

## M0 acceptance tests on the selected host

1. Verify kernel, architecture, cgroup version and Docker/OCI runtime compatibility.
2. Install and pin `runsc`; verify the exact `runsc` and sidecar binary versions.
3. Run Java 25 and Python 3.14 known-good fixtures from immutable, architecture-compatible images.
4. Verify compilation errors, runtime exceptions, timeouts, cancellation, OOM, PID exhaustion and output caps.
5. Verify sandbox DNS and outbound network denial, host path isolation, non-root identity and no secret visibility.
6. Verify complete process-tree termination and ephemeral filesystem cleanup after every exit path.
7. Verify duplicate delivery and runner restart behavior without producing duplicate logical results.
8. Measure cold-start latency, compile/run latency, memory overhead, concurrency and host saturation.
9. Repeat the security and reliability suite after any runtime, kernel, image or gVisor version change.

Passing this evaluation permits further integration testing only. It does not automatically approve production.

## Alternatives considered

### Local Windows ARM64 / Docker Desktop / WSL2

Useful for Go unit tests, protocol validation and preliminary compatibility experiments. Not accepted as the M0 security proof unless the actual Linux kernel, OCI runtime and gVisor isolation behavior are independently demonstrated and the environment is reproducible. Docker Desktop's convenience must not be confused with a reviewed production boundary.

### AWS x86_64 EC2

Provides broad compatibility and a common deployment target. Keep as a fallback if ARM64 runtime images, toolchains or gVisor behavior fail the required compatibility tests. Do not choose x86 solely from habit; compare measured performance, availability and full cost.

### Dedicated bare-metal Linux host

Potentially enables gVisor's KVM platform and may improve performance. It adds procurement, setup and operational complexity and is not justified until the VM/systrap proof demonstrates a specific performance or compatibility blocker.

### Spot VM

Lower cost, but interruption risk can distort reliability, restart and cleanup acceptance tests. It may be considered later for disposable non-critical test batches, never as the baseline for M0 acceptance.

## Decision required

Before provisioning, the owner must approve or reject:

1. AWS as the temporary M0 host provider.
2. Hyderabad `ap-south-2` as the evaluation region.
3. ARM64 `m8g.xlarge` as the first candidate, subject to availability and compatibility checks.
4. The temporary monthly cost ceiling and explicit teardown date.

If any approval is withheld, continue with local protocol/unit tests only and do not create paid infrastructure.
