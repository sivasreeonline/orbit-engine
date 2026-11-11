# Sky High Execution Runner — M0 Contract Skeleton

This is the initial Go runner foundation. It is intentionally **not an execution service**.

The canonical Go module path is `github.com/sivasreeonline/orbit-engine/services/execution-runner`.

## Current capabilities
- Loopback-only HTTP health endpoint: `GET /healthz`.
- Readiness endpoint returns HTTP 503 until a sandbox executor is configured.
- Versioned internal execution request types, strict structural validation and a bounded JSON decoder that rejects unknown fields, duplicate object keys and trailing values.
- Protocol validation is structural only: runtime and resource fields are not authority. A future trusted boundary must authenticate and authorize each attempt, resolve immutable server-owned profiles, and reject any caller value that differs from the approved profile.
- An executor interface with a safe unconfigured implementation.
- A pure lifecycle contract package enforcing the closed attempt-state transition table, concurrency-safe in-memory first-trigger arbitration, and backend-independent terminal-finalization preconditions.
- A backend-neutral journal transaction port with validated attempt, trigger, branch-CAS, and terminal-commit commands; no database adapter is selected or enabled.
- Unit tests for health/readiness, request validation, strict JSON decoding, disabled execution, lifecycle transitions, trigger arbitration, and terminal-finalization preconditions.
- Go vulnerability analysis is performed by govulncheck v1.9.0 in GitHub Actions.

## Explicit safety boundary
- No endpoint accepts source code or starts a process.
- No Docker, containerd, gVisor or host command is invoked.
- The unconfigured executor always returns `ErrSandboxNotConfigured`.
- The lifecycle package is not connected to an HTTP endpoint or executor; it does not persist triggers, authorize attempts, request termination, manage host resources, or perform an atomic terminal database transaction. Finalization validation is a precondition check only; the selected journal adapter must re-enforce all predicates in one durable transaction.
- The journal package defines interfaces and command validation only. It has no database driver or storage implementation; no durable acknowledgement may be made until an independently qualified adapter is implemented and host-tested.
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

Implementation readiness contract: `docs/specifications/m0-supervisor-journal-implementation-contract.md`. It defines the three watchdog roles, distinct generation/fencing values, journal record invariants, transaction boundaries, recovery sequence, and Linux clock requirements. It is a design contract only; the runner remains fail-closed.


The architecture boundary under evaluation keeps the runner unprivileged and prevents direct containerd access. ADR-0019 has not selected an implementation: Candidate A uses a narrowly scoped rootful host supervisor; Candidate B uses rootless containerd with caller-configured user namespaces. The runner-to-host execution transport and lifecycle integration must remain unimplemented until the independent review, candidate-specific host qualification, and ADR decision are complete. `UnconfiguredExecutor` remains fail-closed.

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
