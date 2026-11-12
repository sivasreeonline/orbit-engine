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


## Draft Docker/runsc adapter implementation

The current Go draft adds an `ArtifactResolver`, a per-test `Sandbox` contract, a structured result model, a `SandboxExecutor` and a Docker CLI adapter. The executor verifies the exact source SHA-256 before sandbox invocation. The resolver must authorize source and test-bundle IDs against the execution and problem-version scope.

Each test case is run in a fresh container using a digest-pinned image and the `runsc` runtime. The container policy is:

- network mode `none` and IPC namespace `none`;
- read-only container root filesystem;
- source workspace mounted read-only at `/workspace`;
- writable `/tmp` tmpfs with `noexec,nosuid,nodev` and a bounded size;
- UID/GID 65532:65532, all capabilities dropped and no-new-privileges;
- Docker memory limit with swap set equal to memory, CPU quota and PID limit;
- bounded wall-clock duration and a combined stdout/stderr capture cap;
- a separate bounded cleanup context that force-removes the container and deletes the host-side source workspace.

Java uses a fixed `javac`/JVM command; Python uses isolated mode and disables bytecode writes. Student source bytes are written to a host-side temporary file and mounted read-only; they are never interpolated into a shell command. The only interpolated runtime version has a strict token allowlist and comes from trusted runner configuration.

The structured result distinguishes infrastructure failure, compilation status, deterministic student verdict and cleanup status. Run bundles containing hidden tests are rejected. Submit bundles may contain hidden tests, but their IDs, inputs, expected outputs and per-test results are kept inside the runner. Only aggregate test counts/verdict leave the runner for hidden cases.

### What this implementation does not prove

- The Docker adapter's CI tests use a fake Docker CLI. They verify policy arguments and lifecycle logic, not Docker or gVisor enforcement.
- No authenticated artifact resolver, private runner dispatch endpoint or real execution API is wired yet.
- No runtime images have been built, signed or published.
- Peak-memory sampling is not implemented yet. Memory limits and OOM classification are separate from measured peak memory.
- No live gVisor execution or adversarial security matrix has been run.
- Runner readiness remains disabled and the health-only HTTP process remains the default.

These items remain mandatory M0 gates. The implementation does not authorize production use or student-facing Run/Submit execution.
