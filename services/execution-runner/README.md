# Sky High Execution Runner — M0 Contract Skeleton

This is the initial Go runner foundation. It is intentionally **not an execution service**.

The canonical Go module path is `github.com/sivasreeonline/orbit-engine/services/execution-runner`.

## Current capabilities
- Loopback-only HTTP health endpoint: `GET /healthz`.
- Readiness endpoint returns HTTP 503 until a sandbox executor is configured.
- Versioned internal execution request types and strict structural validation.
- An executor interface with a safe unconfigured implementation.
- Unit tests for health/readiness, request validation and disabled execution.
- Go vulnerability analysis is performed by govulncheck v1.9.0 in GitHub Actions.

## Protocol contract parity status

The Go request model is an initial validated skeleton, not yet a complete implementation of every requirement in `docs/specifications/runner-protocol.md`. In particular, the current request types do not yet carry the tenant-safe correlation ID, immutable runtime image digest, comparison policy, filesystem limits, explicit deadline, or cancellation reference described by the specification.

Track completion in [issue #13](https://github.com/sivasreeonline/orbit-engine/issues/13). Before adding an executor or API adapter, trace all consumers, define field semantics and trust boundaries, choose a compatibility/versioning approach, and add validation plus serialization tests. Do not infer that a field is enforced merely because it appears in the specification.

## Explicit safety boundary
- No endpoint accepts source code or starts a process.
- No Docker, containerd, gVisor or host command is invoked.
- The unconfigured executor always returns `ErrSandboxNotConfigured`.
- The HTTP server refuses non-loopback bind addresses until an authenticated private transport is implemented.
- Student source code is referenced by an opaque artifact ID and SHA-256 digest; it is not included in the runner request body.
- This skeleton must not be deployed as a production runner.

## Local development

```powershell
go test ./...
go vet ./...
gofmt -w .
```

Run the health-only process:

```powershell
go run ./cmd/runner
```

The default listener is `127.0.0.1:8080`.

- `GET http://127.0.0.1:8080/healthz` returns process health.
- `GET http://127.0.0.1:8080/readyz` returns HTTP 503 with `sandbox_executor_not_configured`.

Health does not imply readiness.

## M0 next gates
1. Select a supported Linux host and architecture.
2. Select OCI engine and validate gVisor compatibility.
3. Implement ephemeral sandbox lifecycle behind the Executor interface.
4. Enforce network denial, non-root identity, CPU, memory, PID, wall-clock, filesystem and output limits.
5. Add cancellation, process-tree cleanup, idempotent result persistence and adversarial tests.
6. Complete security review before enabling execution.
