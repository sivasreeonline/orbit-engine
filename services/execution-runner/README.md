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
- A backend-neutral journal transaction port with validated attempt, trigger, operation, branch-CAS, and terminal-commit commands; no database adapter is selected or enabled.
- A deterministic external-operation phase model with inspect-before-retry proof requirements; no containerd client or resource-inspection implementation is enabled.
- A scoped idempotency/replay contract with compound atomic claim-plus-attempt and terminal-result-plus-response-descriptor port operations; no key-reuse expiry or storage adapter is enabled.\n- A backend-neutral qualification evidence verifier that recomputes evidence hashes and verifies detached Ed25519 attestations against caller-supplied reviewer trust policy; no trust root or evidence source is embedded.\n- A hash-linked verification audit-record contract with sequence/predecessor validation, trusted-checkpoint comparison, and compare-and-append ledger interface; no durable ledger or immutable storage adapter is selected.
- Unit tests for health/readiness, request validation, strict JSON decoding, disabled execution, lifecycle transitions, trigger arbitration, and terminal-finalization preconditions.
- Go vulnerability analysis is performed by govulncheck v1.9.0 in GitHub Actions.

## Explicit safety boundary
- No endpoint accepts source code or starts a process.
- No Docker, containerd, gVisor or host command is invoked.
- The unconfigured executor always returns `ErrSandboxNotConfigured`.
- The lifecycle package is not connected to an HTTP endpoint or executor; it does not persist triggers, authorize attempts, request termination, manage host resources, or perform an atomic terminal database transaction. Finalization validation is a precondition check only; the selected journal adapter must re-enforce all predicates in one durable transaction.
- The journal package defines interfaces, command validation, evidence-manifest validation, and a caller-policy-driven evidence verifier only. It has no database driver or storage implementation; no durable acknowledgement may be made until an independently qualified adapter is implemented and host-tested. The verifier does not authenticate trust-policy distribution or authorize deployment.
- The operations package validates deterministic operation identity and phase/reconciliation commands only. It does not invoke containerd, inspect host resources, or authorize retries; those proofs must come from the trusted host supervisor.
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


## Journal adapter qualification

The backend-neutral journal package maintains the required fault and recovery scenario catalog in `internal/journal/qualification.go`. Adapter qualification must map every `JQ-*` scenario to reproducible backend-specific tests and retained evidence. The catalog validator checks completeness only; it does not execute fault injection or certify storage durability. See `docs/specifications/m0-journal-port-contract.md` for the acceptance and evidence requirements.


## Qualification evidence manifest

The journal qualification evidence model and validator are in `internal/journal/evidence_manifest.go`; the JSON Schema is `../../docs/schemas/m0-journal-qualification-evidence.schema.json`. A structurally valid manifest is not automatically qualified: all 25 scenarios must PASS and the independent review must be APPROVED. Hash and signature verification are implemented as an explicit verifier contract in `internal/journal/evidence_verifier.go`; trusted policy distribution, actual provider evidence retrieval, organizational reviewer-independence assurance, and deployment authorization remain external gates. See `docs/specifications/m0-journal-evidence-verification.md`.


## Signed verification audit checkpoints

The journal package defines externally signed Ed25519 checkpoints for audit-ledger heads. The verifier checks signer identity and role against an injected trust policy, signing-time key validity, current revocation, policy version, signature and checkpoint digest, ledger incarnation, predecessor linkage, monotonic sequence/time, and optional signer separation. See [the signed checkpoint specification](../../docs/specifications/m0-signed-verification-audit-checkpoints.md). This is a contract and in-process verifier only: no production keys, trust roots, policy distribution, durable checkpoint store, WORM retention, trusted clock, or recovery authority is provided.


## Independent checkpoint custody

The journal package defines a separately signed custody receipt and a backend-neutral compare-and-store contract for verification audit checkpoints. Custody receipts bind an exact signed checkpoint to a custody domain, retention policy/version, retained timestamp, and asserted immutability horizon. The verifier requires externally supplied custodian trust policy and can require a distinct custodian principal. See [the checkpoint custody specification](../../docs/specifications/m0-checkpoint-custody-and-retention.md). Receipts are assertions, not proof of actual provider-enforced immutability; no durable store, WORM configuration, provider integration, or external custodian qualification is implemented.
