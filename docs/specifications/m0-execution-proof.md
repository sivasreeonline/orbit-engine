# M0 — Isolated Execution Proof

## Goal
Prove that the Go runner can execute Java 25 and Python 3.14 programs on separate Linux infrastructure with strict resource limits and reliable cleanup. M0 is a security and operability proof, not a student-facing product release.

## Deliverables
1. Linux host decision and reproducible provisioning.
2. OCI runtime and gVisor/runsc compatibility proof.
3. Go runner process with authenticated job intake.
4. Java and Python runtime images pinned by digest.
5. Per-execution ephemeral sandbox lifecycle.
6. Resource controls and bounded output capture.
7. Structured execution result and correlation ID.
8. Automated security, correctness, reliability and performance tests.
9. Runbook for deploy, upgrade, stop, drain and incident response.

## Minimum test programs
- Normal output and exit code.
- Compile error (Java).
- Runtime exception.
- Infinite loop.
- Memory allocation beyond configured limit.
- Excessive process creation.
- Large stdout and stderr.
- Attempted outbound network connection and DNS.
- Attempted filesystem traversal and host access.
- Timeout and cancellation.
- Duplicate job delivery.
- Runner restart during execution.
- Cleanup after success and every failure path.

## M0 acceptance gates
- Both languages execute known-good fixtures with reproducible results.
- No outbound network from the sandbox.
- CPU, memory, PID, wall-clock, filesystem and output caps are enforced.
- No host secret or mounted host path is visible to student code.
- Timeout/cancel kills the full process tree and removes temporary resources.
- Duplicate delivery produces one logical result.
- Infrastructure failure is distinct from student verdict.
- Logs are structured and correlated; no hidden test content or secrets are logged.
- Performance and concurrency limits are measured on chosen host; no capacity is assumed in advance.

## M0 exclusions
No public API, trainer analytics, AI feedback, multi-region scaling or production certification. A passing proof permits integration testing, not automatic production approval.


## Draft runsc adapter implementation status

The repository now contains a draft Go adapter from authenticated execution artifacts into a per-testcase Docker/runsc sandbox. The adapter verifies execution/attempt/problem-version identity, rechecks the source SHA-256, rejects hidden cases for RUN, keeps hidden-case details out of result payloads, and maps only aggregate result fields into the signed completion contract.

The Docker command contract requests:
- digest-pinned runtime image references and the `runsc` runtime;
- disabled network and IPC, read-only container root, dropped capabilities, no-new-privileges, and UID/GID 65532:65532;
- bounded memory/swap, CPU quota, PID count, wall-clock time and combined stdout/stderr;
- private non-executable tmpfs mounts for `/workspace` and `/tmp`;
- forced container removal on success, timeout, cancellation, output overflow and errors.

Student source is not written to the runner host filesystem. The runner streams the exact source bytes first over the attached container stdin. A fixed wrapper consumes exactly the trusted byte length into `/workspace`, verifies the byte count, makes the file read-only and locks the workspace directory. The remaining stdin bytes are then passed to the student program as its testcase input. Source contents are never interpolated into shell arguments and no host bind mount is used.

The current comparator is exact-byte comparison. The artifact contract does not yet include a versioned comparison-mode field; do not infer whitespace normalization.

### Evidence status and mandatory gates

- Go format, vet and unit tests exercise the fake Docker CLI and execution-contract behavior only.
- CI does not run Docker, gVisor, student programs or a real Linux sandbox.
- Runtime images have not been built, signed or verified on a target Linux host.
- Peak-memory sampling is not implemented; OOM classification is not measured peak memory.
- The sandbox adapter requires an explicit enable flag and is not wired into `cmd/runner`. The default command remains loopback-only and health-only.
- No production execution or student-facing Run/Submit release is authorized by these tests.

Before enabling the adapter for any real workload, run the full adversarial test matrix on a disposable, supported Linux host with a pinned Docker/OCI engine and a verified `runsc` installation. Independently review network denial, host filesystem isolation, UID mapping, resource enforcement, timeout/process-tree termination, output limits, container cleanup and peak-memory telemetry. Record host/runtime/image digests and measured concurrency. Keep the worker disabled until those results pass review.
