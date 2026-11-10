# Sky High Execution Runner — M0 Contract Skeleton

This is the initial Go runner foundation. It is intentionally **not an execution service**.

The canonical Go module path is `github.com/sivasreeonline/orbit-engine/services/execution-runner`.

## Current capabilities
- Loopback-only HTTP health endpoint: `GET /healthz`.
- Readiness endpoint returns HTTP 503 until a sandbox executor is configured.
- Versioned internal execution request types, strict structural validation and a bounded JSON decoder that rejects unknown fields, duplicate object keys and trailing values.
- An executor interface with a safe unconfigured implementation.
- Unit tests for health/readiness, request validation, strict JSON decoding and disabled execution.
- Go vulnerability analysis is performed by govulncheck v1.9.0 in GitHub Actions.

## Explicit safety boundary
- No endpoint accepts source code or starts a process.
- No Docker, containerd, gVisor or host command is invoked.
- The unconfigured executor always returns `ErrSandboxNotConfigured`.
- The HTTP server refuses non-loopback bind addresses until an authenticated private transport is implemented.
- Student source code is referenced by an opaque artifact ID and SHA-256 digest; it is not included in the runner request body.
- The decoder caps request bodies at 64 KiB and rejects unrecognized fields, including sourceCode, hiddenTests, expectedOutput and credentials.
- The strict decoder is a tested protocol utility only; no HTTP execution endpoint is registered.
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

## M0 implementation boundary and next gates

The host supervisor, durable lifecycle journal, watchdog, evidence publisher/verifier, and containerd integration are still design-only. They are not implemented by this runner skeleton. Do not implement direct containerd access or sandbox lifecycle inside the unprivileged runner.

The approved direction is a separate, narrowly scoped host supervisor as the only rootful containerd caller. The runner must communicate through a strict authenticated private transport after the supervisor boundary, journal design, watchdog recovery, and security review are approved. The runner remains unprivileged; `UnconfiguredExecutor` remains fail-closed until a separately reviewed integration is authorized.

Before any M0 workload is launched:
1. Select and document the disposable Linux host, architecture, OCI runtime versions, and immutable image provenance.
2. Complete the supervisor privilege-boundary ADR and independently review the runner-to-supervisor authorization contract.
3. Select the journal storage engine, filesystem, durability mode, backup/recovery procedure, and corruption behavior; prove crash/power-loss semantics on the actual disposable host.
4. Implement and test durable attempt/idempotency/operation records, exclusive supervisor ownership, restart reconciliation, immutable deadlines, and one terminal compare-and-set.
5. Define and empirically validate a finite cleanup deadline in a reviewed resource-profile revision. This remains unset; no stress fixture may run until it is approved.
6. Implement the supervisor-owned sandbox lifecycle, output collection, cancellation, process-tree cleanup, and independently verified evidence publication.
7. Prove network denial, non-root identity, CPU, memory, PID, wall-clock, filesystem, output, cleanup, and restart controls with host-side evidence.
8. Complete independent security review before any execution integration is enabled.

Passing documentation checks or the existing Go protocol tests does not constitute host proof or authorize student execution.
