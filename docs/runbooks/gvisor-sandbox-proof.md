# gVisor Sandbox Proof Runbook

## Purpose and safety boundary

This runbook provides a repeatable, manual smoke test for the proposed gVisor (runsc) OCI runtime. It is a proof harness, not production approval and not a student-code execution endpoint.

The workflow uses a disposable GitHub-hosted **Ubuntu 24.04 x86_64** runner as a test host. This establishes a reproducible CI test target only; it does not select a production cloud provider or prove that another host has the same kernel, cgroup, Docker, or runtime behavior.

gVisor documents support for x86_64/AMD64 and ARM64 and requires Linux 5.6 or newer. The workflow uses the official gVisor release apt repository and records the installed runtime version in its job log. See the [gVisor installation guide](https://gvisor.dev/docs/user_guide/install/) and [Docker quick start](https://gvisor.dev/docs/user_guide/quick_start/docker/).

## Run the proof

1. Prepare a reviewed, minimal test image that contains /bin/sh, id, and wget.
2. Push that image to a registry and obtain its immutable IMAGE@sha256:<64 lowercase hex characters> reference. Do not use a mutable tag.
3. Open **Actions → gVisor sandbox proof (manual) → Run workflow**.
4. Supply the immutable image reference as image_ref.
5. Retain the workflow URL, runner image reference, runsc version, and complete job log as evidence.

The workflow installs runsc, registers it with Docker, and runs scripts/gvisor-smoke.sh. It has no access to production credentials or student data.

## Controls checked by the smoke harness

The harness creates a disposable container and inspects its effective Docker configuration before starting it. It requires:

- OCI runtime runsc.
- UID/GID 65532:65532.
- Docker network mode none.
- Read-only root filesystem.
- Writable /tmp tmpfs limited to 16 MiB with noexec,nosuid.
- Memory limit 128 MiB, CPU quota 0.5 CPU, and PID limit 64.
- `/tmp` tmpfs mount options exactly `rw,noexec,nosuid,size=16m`, verified from Docker's effective container configuration.
- All Linux capabilities dropped and no-new-privileges enabled.
- A failed write to the root filesystem, a successful scratch write, and failed outbound requests to both a direct IP and a DNS hostname.

The container is created with --rm semantics implemented by an explicit cleanup trap; cleanup is attempted on normal exit and interruption.

## What this proof does not establish

A passing run is only a smoke-test result. It does not establish:

- Resistance to host kernel/runtime vulnerabilities or container escape.
- That all network paths are blocked on a production host or under a different network stack.
- Enforcement under memory exhaustion, CPU starvation, PID exhaustion, fork bombs, or output floods.
- Safe cancellation, timeout, OOM, forced-termination cleanup, or concurrent workload behavior.
- Filesystem traversal/symlink escape resistance or absence of host mounts on a production deployment.
- Production performance, availability, or suitability of the GitHub-hosted runner as a production host.

The values above are smoke-test policy values, not final per-language production resource policies. Production limits must come from trusted server-side policy, not student input.

## Required follow-up before enabling execution

- Repeat the proof on the selected dedicated Linux production host and record OS/kernel, architecture, Docker/containerd, runsc and cgroup versions.
- Add adversarial tests for process/PID exhaustion, memory exhaustion, CPU and wall-clock limits, oversized stdout/stderr, filesystem traversal and symlink escapes.
- Prove cleanup for success, timeout, cancellation, OOM and forced termination.
- Verify host filesystem and privileged socket isolation, and outbound network denial including DNS and direct-IP paths.
- Review the threat model, runtime configuration and evidence with a security reviewer.
- Keep UnconfiguredExecutor as the only active executor until every M0 gate is evidenced and approved.

A successful workflow must never be interpreted as authorization to enable Run or Submit.
