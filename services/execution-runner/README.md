# Sky High Execution Runner — M0 Contract Skeleton

This is the initial Go runner foundation. It is intentionally **not an execution service**.

The canonical Go module path is `github.com/sivasreeonline/orbit-engine/services/execution-runner`.

## Current capabilities
- Loopback-only HTTP health endpoint: `GET /healthz`.
- Readiness endpoint returns HTTP 503 until a sandbox executor is configured.
- Separate strict protocol v1 (legacy/non-executable) and v2 request models; v2 validates immutable runtime digests, exact-byte comparison, absolute deadlines, cancellation references, and hard scratch quota ceilings. Both decoders reject unknown fields, duplicate object keys and trailing values.
- An executor interface with a safe unconfigured implementation.
- Unit tests for health/readiness, request validation, strict JSON decoding and disabled execution.
- Go vulnerability analysis is performed by govulncheck v1.9.0 in GitHub Actions.

## Protocol lifecycle

- Protocol v1 is retained for strict legacy parsing and is permanently non-executable.
- Protocol v2 has a separate strict request model and decoder. The control-plane producer, authenticated dispatch transport, artifact authorization, and sandbox enforcement are not yet integrated.
- A valid v2 request is not evidence that execution is enabled or safe; the executor remains unconfigured and readiness remains unavailable.

## Explicit safety boundary
- No endpoint accepts source code or starts a process.
- No Docker, containerd, gVisor or host command is invoked.
- The unconfigured executor always returns `ErrSandboxNotConfigured`.
- The HTTP server refuses non-loopback bind addresses until an authenticated private transport is implemented.
- Student source code is referenced by an opaque artifact ID and SHA-256 digest; it is not included in the runner request body.
- The decoder caps request bodies at 64 KiB and rejects unrecognized fields, including sourceCode, hiddenTests, expectedOutput and credentials.
- The strict decoders are tested protocol utilities only; no HTTP execution endpoint is registered and no request version can execute student code.
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
