# Sky High Execution Runner — M0 Contract Skeleton

This is the initial Go runner foundation. It is intentionally **not an execution service**.

The canonical Go module path is `github.com/sivasreeonline/orbit-engine/services/execution-runner`.

## Current capabilities
- Loopback-only HTTP health endpoint: `GET /healthz`.
- Local append-only acceptance journal with fsync-before-send semantics, restart recovery and pending-receipt replay support.
- Outbound Ed25519-signed claim/accept/start/heartbeat/artifact/completion HTTP client with strict bounded response validation.
- Artifact responses are independently checked for source SHA-256, cross-language test-bundle digest, action scope, fixture visibility, ordering and size limits.
- Readiness endpoint returns HTTP 503 until a sandbox executor is configured.
- Versioned internal execution request types and strict structural validation.
- An executor interface with a safe unconfigured implementation.
- Unit tests for health/readiness, request validation and disabled execution.
- Go vulnerability analysis is performed by govulncheck v1.9.0 in GitHub Actions.

## Explicit safety boundary
- No endpoint accepts source code or starts a process.
- The acceptance journal stores only opaque IDs, lease identity and receipt lifecycle metadata; it never stores source code, hidden tests or execution artifacts.
- A single runner process must own a journal file. Journal files are created with owner-only permissions (0600), and incomplete trailing records are truncated during recovery.
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

## Acceptance journal

The local journal is a write-ahead record for the future runner protocol:

1. Persist a `PREPARED` receipt event and fsync the journal.
2. Only after that succeeds, send the signed acceptance receipt to the control plane.
3. After receiving the durable API acknowledgement, append a `CONFIRMED` event and fsync again.
4. After a restart, retry every prepared-but-unconfirmed receipt using the same acceptanceId and receipt body, but a fresh signed HTTP nonce.

The journal is append-only JSONL with a 64 MiB initial size ceiling. It rejects malformed complete records and only truncates an incomplete final line left by a crash. It is not yet wired to the HTTP client or claim loop.

## Current runner control-plane client

The Go client exposes separate methods for:
1. Claim metadata-only dispatches.
2. Persist and submit durable acceptance receipts.
3. Request the lease-fenced `CLAIMED -> RUNNING` transition.
4. Renew a started lease with a stable heartbeat ID (reuse the same ID after a lost acknowledgement).
5. Fetch source and the action-scoped test bundle using the exact live dispatch lease.
6. Submit an allowlisted aggregate terminal result against the same dispatch and lease.

The client verifies the returned source hash and canonical test-bundle hash. Completion retries preserve the result body and use a fresh signed nonce; the control plane returns the existing completion receipt when the result is identical. It rejects hidden tests in a `RUN` artifact and permits hidden fixtures only for the trusted runner's `SUBMIT` artifact. The methods are individually testable and are not yet wired into a continuously polling process.

## M0 next gates
1. Add reviewed machine key loading/permissions and a single-process journal owner.
2. Integrate claim → accept → start → heartbeat → artifact retrieval → execute → complete in a bounded runner lifecycle with backoff, cancellation and graceful shutdown.
3. Select a supported Linux host and architecture.
4. Select OCI engine and validate gVisor compatibility.
5. Implement and qualify the ephemeral sandbox lifecycle behind the Executor interface.
6. Enforce network denial, non-root identity, CPU, memory, PID, wall-clock, filesystem and output limits.
7. Add cleanup attestation and adversarial tests; keep execution disabled until the full sandbox/security review passes.
