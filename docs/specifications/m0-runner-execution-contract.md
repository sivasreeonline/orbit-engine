# M0 Runner Execution Contract

- **Status:** Proposed contract for implementation
- **Date:** 2026-11-13
- **Scope:** Internal API between the Sky High execution control plane and an isolated Linux runner
- **Related decisions:** ADR-0012 (immutable attempt evidence), ADR-0018 (host evaluation proposal)
- **Non-goal:** This contract does not approve cloud provisioning or production execution.

## 1. Responsibility boundary

The control plane remains authoritative for identity, tenant ownership, problem/version selection, attempt creation, job scheduling, idempotency, result persistence, verdict publication and evidence history.

The runner is a replaceable execution worker. It accepts a bounded execution instruction, runs the supplied source in an isolated sandbox, returns a bounded execution report and emits operational health. It does not:
- authenticate students or decide tenant ownership;
- create or mutate source snapshots, attempts, jobs or evidence records;
- decide whether a student may access a problem;
- fetch arbitrary URLs or access the public internet from a sandbox;
- access Neon, R2, Cloudflare credentials or other application secrets;
- return hidden test inputs, expected outputs, private test metadata or unrestricted diagnostics;
- call AI or determine learning insights;
- make a final student-facing verdict authoritative.

The control plane must verify that the returned execution identity matches the claimed job, attempt, source digest and problem version before accepting the result.

## 2. Protocol shape

Use a versioned, language-neutral JSON protocol over an authenticated private control channel. The exact transport (for example, private HTTPS with mutual TLS) and credential rotation mechanism remain a separate security design decision; do not expose an unauthenticated public listener.

Every message carries:
- `protocolVersion`: currently `1`;
- `requestId`: unique control-plane request identifier;
- `executionId`: stable identity for one logical execution;
- `issuedAt` and `expiresAt`: UTC RFC 3339 timestamps;
- `traceId`: correlation identifier, not an authorization credential.

The receiver rejects unknown protocol versions, expired requests, malformed identifiers, oversized payloads and policy values outside the runner's configured hard bounds. Unknown fields may be ignored only where doing so cannot weaken a security decision; security-critical fields must be validated explicitly.

## 3. Execute request

The control plane sends an instruction conceptually shaped as follows:

```json
{
  "protocolVersion": 1,
  "requestId": "opaque-request-id",
  "executionId": "opaque-execution-id",
  "issuedAt": "UTC timestamp",
  "expiresAt": "UTC timestamp",
  "traceId": "opaque-trace-id",
  "attempt": {
    "attemptId": "immutable-attempt-id",
    "action": "RUN",
    "problemVersionId": "immutable-problem-version-id",
    "language": "java",
    "runtimeImageDigest": "sha256:...",
    "source": {
      "sha256": "hex-digest",
      "byteLength": 1234,
      "artifact": {
        "kind": "short-lived-authorized-reference",
        "reference": "opaque-reference"
      }
    }
  },
  "executionPolicy": {
    "stdinArtifact": "opaque-authorized-reference",
    "caseSetDigest": "sha256:...",
    "limits": {
      "wallClockMs": 1000,
      "cpuMillis": 1000,
      "memoryBytes": 268435456,
      "pids": 32,
      "stdoutBytes": 65536,
      "stderrBytes": 65536,
      "workspaceBytes": 16777216
    }
  }
}
```

This is a schema illustration, not a selected production resource policy. The values above are examples only; M0 must establish safe measured limits and hard host ceilings before implementation enables execution. The actual wire contract must not allow the caller to raise limits beyond host policy.

Important semantics:
- `action` is exactly `RUN` or `SUBMIT`; it preserves the distinction already recorded by the attempt service.
- Source bytes are retrieved only through a narrowly authorized, integrity-checked artifact reference. The runner verifies byte length and SHA-256 before compilation. It must not accept arbitrary filesystem paths or arbitrary URLs.
- Runtime images are selected from an allowlist and pinned by immutable digest. The caller cannot provide an image name, registry URL, shell command or arbitrary entrypoint.
- The control plane supplies only the input artifacts needed for the selected test cases. Expected outputs and hidden test definitions are not mounted into the untrusted program's filesystem or environment.
- A sandbox receives one bounded stdin stream for a case. The trusted runner supervisor captures bounded stdout/stderr and performs deterministic comparison outside the sandbox. The student process never receives expected output.
- The case-set digest binds the execution to the selected immutable test-set version without revealing test contents in the result.
- No secrets, database credentials, cloud credentials, signing keys or long-lived bearer tokens are included in the sandbox environment.

The exact artifact delivery mechanism, authorization token format and test-case packaging format remain implementation decisions and must be reviewed before integration.

## 4. Result envelope

The runner returns one bounded report for the logical execution:

```json
{
  "protocolVersion": 1,
  "requestId": "same-request-id",
  "executionId": "same-execution-id",
  "attemptId": "same-attempt-id",
  "sourceSha256": "same-source-digest",
  "runtimeImageDigest": "same-runtime-digest",
  "startedAt": "UTC timestamp",
  "finishedAt": "UTC timestamp",
  "runner": {
    "runnerId": "registered-runner-id",
    "runnerBuild": "immutable-build-version"
  },
  "executionStatus": "COMPLETED",
  "terminationReason": "NORMAL",
  "resourceUsage": {
    "wallClockMs": 123,
    "cpuMillis": 100,
    "peakMemoryBytes": 12345678
  },
  "aggregate": {
    "totalCases": 5,
    "passedCases": 4,
    "failedCases": 1
  },
  "diagnostics": {
    "stdout": "bounded-and-policy-filtered-text",
    "stderr": "bounded-and-policy-filtered-text",
    "truncated": false
  }
}
```

The response is illustrative. The implementation must define strict enums and numeric bounds rather than accepting arbitrary strings or unbounded numbers.

Allowed execution status categories must distinguish at least:
- completed normally;
- compilation failed;
- runtime failed;
- timed out;
- cancelled;
- resource limit exceeded;
- infrastructure failed.

Termination reason is separate from student-facing verdict. For example, a runner crash or artifact-store outage is an infrastructure failure, not a wrong answer. The control plane maps validated results into its existing append-only result/event model and decides whether the result is eligible for student display.

Do not return per-hidden-case input, expected output, private test names, internal filesystem paths, host details, raw sandbox environment, secrets or unrestricted process diagnostics. Aggregate hidden-test outcomes only. Any student-visible compiler/runtime text must be bounded and passed through the existing output-safety policy.

## 5. Idempotency and duplicate delivery

Queue delivery is at least once. The runner must treat `executionId` as the stable identity of one logical execution:
- A duplicate request with the same execution identity and same immutable request fingerprint must not start a second concurrent sandbox.
- If the original execution is active, return an `IN_PROGRESS` acknowledgement or the documented status response.
- If it has completed, return the same persisted result identity/digest; do not silently re-execute.
- Reuse of an execution identity with a different attempt, source digest, problem version, action, runtime digest or policy fingerprint is a conflict and must be rejected.
- A retry after a definitive infrastructure failure is a new execution identity linked by the control plane to the original attempt/retry lineage. It must not overwrite the earlier execution evidence.

The runner's deduplication state must survive process restart for the duration of its documented retention window, or the control plane must provide an equivalent durable lease/claim mechanism. An in-memory map alone is insufficient.

## 6. Cancellation and lifecycle

Cancellation is an explicit control-plane operation addressed to the exact `executionId`. It must be idempotent.

The runner:
1. marks the execution as cancellation-requested;
2. prevents new work from starting for that execution;
3. terminates the entire sandbox process tree, not only the direct child;
4. waits for bounded cleanup;
5. removes ephemeral workspace, mounts and per-execution resources;
6. records a terminal cancellation or cleanup-failure result.

A cancellation race with natural completion must resolve to one durable terminal outcome. The control plane's lease fencing and append-only result persistence remain authoritative. Late results from an expired lease must be rejected by the control plane even if the runner completed them.

## 7. Isolation and resource enforcement

The runner supervisor is trusted host-side code; submitted source and all student-controlled inputs are untrusted.

Each execution must use a fresh isolated workspace and sandbox. At minimum:
- run as non-root with no privilege escalation;
- drop unnecessary Linux capabilities;
- use read-only runtime root filesystem where feasible and a bounded writable ephemeral workspace;
- deny network access from the sandbox by default, including DNS and cloud metadata endpoints;
- prevent host filesystem, container-runtime socket, process namespace and device access;
- enforce CPU, memory, PID, wall-clock, file-size, workspace and stdout/stderr limits at the kernel/runtime boundary;
- apply a restrictive syscall policy through the approved gVisor configuration;
- never mount Docker/containerd sockets or host credentials;
- kill the complete process tree on timeout, cancellation or limit violation;
- ensure cleanup runs after success, compile failure, runtime failure, timeout, cancellation, OOM and supervisor error.

A timeout in application code is not sufficient resource enforcement. The host/runtime must enforce hard limits independently.

## 8. Failure taxonomy

Keep execution outcome separate from infrastructure health.

| Category | Examples | Control-plane interpretation |
|---|---|---|
| Student compilation failure | Syntax/type/compiler error | Completed attempt with compilation outcome |
| Student runtime failure | Unhandled exception, non-zero exit | Completed attempt with runtime outcome |
| Test mismatch | Output differs from expected | Completed evaluation; deterministic judge result |
| Resource termination | Wall-clock, CPU, memory, PID, output cap | Completed attempt with explicit limit reason |
| User cancellation | Explicit cancel accepted | Cancelled terminal state |
| Infrastructure failure | Runner crash, unavailable artifact, runtime unavailable | Retry/reconcile under control-plane policy; not wrong answer |
| Integrity failure | Source digest mismatch, image digest mismatch, malformed response | Reject result, quarantine execution, alert |

The runner must not convert infrastructure failure into a failed test case or a wrong-answer verdict.

## 9. Observability and privacy

Structured operational events may include execution ID, attempt ID, trace ID, runner build, runtime digest, timestamps, status category, bounded resource measurements and cleanup outcome.

Never log source contents, hidden tests, expected outputs, environment variables, credentials, signed artifact URLs or unrestricted stdout/stderr. Diagnostic output must be bounded before it reaches logs or the control plane. Operational logs are not a substitute for immutable attempt evidence.

## 10. Contract acceptance tests

Before control-plane integration, the runner contract suite must verify:

1. Valid Java and Python request parsing and runtime allowlist enforcement.
2. Rejection of expired requests, unsupported protocol versions and malformed identities.
3. Source artifact byte-length and SHA-256 verification before compilation.
4. Rejection of arbitrary image names, commands, paths, URLs and caller-supplied limit escalation.
5. Duplicate same-fingerprint request behavior and conflicting-fingerprint rejection.
6. Cancellation before start, during compilation, during execution and at the completion race.
7. Hard wall-clock, CPU, memory, PID, filesystem and output enforcement.
8. No network/DNS/metadata access from the sandbox.
9. No host filesystem, runtime socket, secret or cross-execution workspace access.
10. Complete process-tree termination and cleanup for every terminal path.
11. Strict response bounds, identity/digest linkage and rejection of malformed or mismatched reports.
12. Infrastructure failures remain distinguishable from compilation/runtime/test outcomes.
13. Hidden test inputs, expected outputs and private metadata are absent from student-facing responses and operational logs.
14. Restart/recovery does not create duplicate logical results.

Tests must run against the actual selected Linux kernel, OCI runtime and gVisor configuration before M0 is declared passed. Unit tests on Windows or a mocked runner are useful but cannot satisfy the isolation acceptance gate.

## 11. Decisions deliberately left open

The following must not be silently guessed:
- private runner transport and mutual authentication mechanism;
- artifact-reference authorization and expiry design;
- exact runtime image build/pinning and patch-update process;
- test-case packaging and trusted comparison implementation details;
- concrete per-language resource limits and output policy;
- durable runner deduplication storage versus control-plane lease ownership;
- runner registration, health checks, draining and host replacement;
- operational log retention and alert thresholds.

Resolve these through focused implementation proposals and security review. ADR-0018 host approval remains a separate gate. This contract does not authorize provisioning or production traffic.
