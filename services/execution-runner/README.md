# Sky High Execution Runner

The Go runner is being developed as a separately hosted execution service. It must never run student source inside the browser, Cloudflare Worker or API process.

## Implemented in this draft

- Loopback-only process health endpoint: `GET /healthz`.
- Readiness remains HTTP 503 until authenticated private dispatch and a reviewed sandbox configuration are wired.
- Versioned request validation using opaque source and test-bundle artifact IDs.
- `SandboxExecutor`: verifies the resolved source SHA-256, validates the versioned test bundle and resource policy, and classifies compilation/runtime/test outcomes separately from infrastructure failures.
- `DockerSandbox`: creates one short-lived container per test case using the `runsc` OCI runtime.
- Pinned image references must use `image@sha256:<64 lowercase hex characters>`; the fixed Java/Python entry scripts verify the configured runtime version before compiling/running.
- Source files are mounted read-only. stdin is streamed to the program. stdout/stderr are kept separate and share one combined output byte cap.
- The container policy disables networking, uses a read-only root filesystem, runs as UID/GID 65532, drops all capabilities, enables no-new-privileges, uses a bounded no-exec tmpfs, and applies memory/swap, CPU and PID limits.
- Timeout/output-limit cancellation is followed by `docker rm --force` using a separate bounded cleanup context.
- Hidden test IDs and per-test outputs never appear in the runner result. Submit results expose only aggregate totals for hidden cases.
- Unit tests use fake artifact and Docker adapters. They do not execute student code on the host.

## Explicit not-yet-enabled boundaries

This branch does **not** yet:

- expose an execution HTTP endpoint;
- authenticate queue or runner-to-control-plane dispatch;
- implement the production `ArtifactResolver` against private source/test artifact storage;
- wire `SandboxExecutor` into the runner process or mark the runner ready;
- build, publish or approve the immutable Java/Python runtime images;
- prove gVisor isolation on a disposable Linux host;
- provide measured peak-memory telemetry (OOM enforcement/classification is supported; peak-memory sampling remains outstanding);
- connect the student React editor to the execution API.

The existing `UnconfiguredExecutor` remains the default. Health does not imply readiness. The current adapter code is a candidate implementation and is not production-approved.

## Local Go checks

Run from `services/execution-runner`:

```powershell
go test ./...
go vet ./...
gofmt -w .
```

The CI workflow runs formatting, vet and race-enabled coverage tests.

## Linux gVisor integration gate

The real Docker adapter requires a Linux host with Docker Engine configured with the `runsc` runtime and reviewed, immutable runtime images that contain the expected JDK/Python tools. Run actual code only inside that gVisor sandbox on a disposable, isolated Linux host.

The fake-Docker tests verify argument construction, output caps, timeout handling, classification and cleanup, but they do not prove that a real Docker daemon or gVisor installation enforces those settings. The manual smoke harness and adversarial M0 matrix remain separate required evidence.

Do not run student programs directly on the Windows host. For the planned Windows ARM64 development environment, Docker/WSL2 and gVisor compatibility must be checked before attempting a local real-container run.

## M0 release gates still required

1. Build and review the exact immutable Java and Python images.
2. Validate Docker/runsc support on a disposable Linux host and record host/runtime details.
3. Exercise the real adapter with harmless known-good Java/Python fixtures.
4. Complete network denial, non-root, read-only filesystem, CPU/memory/PID/wall-time/output, cancellation and cleanup adversarial tests.
5. Add trusted artifact resolution, authenticated private dispatch, durable result handoff and measured peak-memory telemetry.
6. Complete independent security review before enabling readiness or connecting student-facing execution.

A passing unit test or GitHub-hosted smoke test is not production qualification.
