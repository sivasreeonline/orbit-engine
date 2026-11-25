# Runner Result Contract — Draft for Review

> **Status: proposal, not an implemented or normative wire contract.**  
> This document is a design review aid. Do not build an API response, persistence schema, or runner implementation from it until the contract is approved and versioned.

## 1. Design goals

A result must let Sky High distinguish:
- whether the runner infrastructure completed the request safely;
- whether compilation succeeded;
- what verdict applies to the student's submission; and
- what sanitized evidence may be shown to the student or trainer.

These are separate dimensions. A single `status` string must not conflate infrastructure failure with a student answer.

## 2. Proposed result envelope

The following shape is illustrative. Field names and enum values require review before adoption.

| Field | Proposed meaning |
| --- | --- |
| `protocolVersion` | Result schema version, independently versioned from the request if needed |
| `executionId` | Idempotency/correlation key matching the accepted request |
| `sourceSha256` | Hash of the exact source artifact the runner resolved |
| `infrastructureStatus` | `SUCCEEDED` or `FAILED`; indicates whether trusted runner orchestration completed its responsibilities |
| `infrastructureErrorCode` | Stable allowlisted code only when infrastructure failed; never raw host/runtime errors |
| `compilationStatus` | `NOT_STARTED`, `SUCCEEDED`, or `FAILED` |
| `verdict` | `NOT_EVALUATED`, `ACCEPTED`, `WRONG_ANSWER`, `COMPILATION_ERROR`, `RUNTIME_ERROR`, `TIME_LIMIT_EXCEEDED`, `MEMORY_LIMIT_EXCEEDED`, or `OUTPUT_LIMIT_EXCEEDED` |
| `tests` | Sanitized test summaries; never hidden input, expected output, or hidden-test stdout/stderr |
| `metrics` | Bounded elapsed time and memory measurements, with explicit units |
| `startedAt`, `completedAt` | UTC timestamps from trusted runner infrastructure |
| `cleanupStatus` | `SUCCEEDED`, `FAILED`, or `UNKNOWN`; cleanup failure must not be hidden by a student verdict |

## 3. Classification invariants

1. **Infrastructure failure is not a student verdict.** If the runner cannot authenticate, resolve an authorized artifact, start or supervise the sandbox, enforce policy, or establish cleanup, set `infrastructureStatus=FAILED` and `verdict=NOT_EVALUATED`.
2. **Student outcomes require successful infrastructure.** Only classify compilation or test outcomes after the runner has established that the intended sandbox and policy were applied.
3. **Do not turn infrastructure timeouts into student TLE.** A candidate exceeding the configured execution budget may be `TIME_LIMIT_EXCEEDED`; a runner/controller deadline, worker crash, or control-plane timeout is infrastructure failure.
4. **Cleanup is an independent safety result.** A student may receive a verdict while cleanup is failed/unknown, but the execution must be escalated as an infrastructure/security event and must not be treated as an ordinary successful run.
5. **Retry safety:** the same `executionId` must not create multiple logical results. A retry must be idempotent and must not overwrite a previously finalized result with a contradictory outcome.

## 4. Hidden-test and output boundary

- Never return hidden test input, expected output, hidden-test stdout/stderr, private bundle contents, filesystem paths, environment variables, or raw sandbox diagnostics.
- Per-test details exposed to an untrusted client must be limited to safe status and bounded measurements; hidden test identifiers should be opaque or omitted.
- Public-test stdout/stderr may be returned only when the request policy explicitly authorizes it, and each stream must be independently byte-capped.
- Compile output and runtime diagnostics must be sanitized and bounded. Remove host paths, credentials, tokens, internal addresses, and implementation details before returning them.
- Enforce limits while collecting output; truncating after buffering an unbounded stream is not sufficient.
- Persist richer internal evidence separately under authenticated access controls. Do not reuse the student-facing response as the audit record.

## 5. Open decisions before implementation

- Whether infrastructure status needs intermediate states such as `RETRYABLE_FAILURE` or whether retryability belongs in a separate field.
- Exact verdict taxonomy for partial scoring, accepted-with-warnings, cancellation, and policy violations.
- Whether test summaries include per-test timing/memory and how hidden tests are represented.
- Which public-test output is returned for `RUN` versus `SUBMIT`.
- Output sanitization policy and maximum byte limits for compile output, stdout, stderr, and per-test summaries.
- Whether cleanup `FAILED` blocks readiness or triggers a quarantine/reconciliation workflow.
- Timestamp source, clock-skew tolerance, and result-finalization semantics.
- Result schema versioning and compatibility with the request protocol.

## 6. Acceptance tests required after approval

- Infrastructure failure always produces `NOT_EVALUATED`, never `WRONG_ANSWER` or `ACCEPTED`.
- Candidate compile/runtime/time/memory/output failures map only to approved student verdicts.
- Controller deadline, runner crash, artifact authorization failure, and sandbox setup failure map to infrastructure failure.
- Hidden inputs, expected outputs, hidden stdout/stderr, host paths, and secrets are absent from every student-facing serialization.
- Output caps are enforced during collection and remain bounded under stdout/stderr floods.
- Cleanup failure is observable and cannot be reported as a clean successful execution.
- Duplicate delivery for one `executionId` is idempotent.
- Serialization tests pin exact wire names, enum values, units, and omission/null behavior.

## 7. Current repository state

The M0 runner currently has no result DTO, no execution HTTP handler, no configured executor, and no API-to-runner adapter. `runner.Result` contains only an internal `ExecutionID` placeholder. `UnconfiguredExecutor` always returns `ErrSandboxNotConfigured`.

This draft intentionally does not change those runtime boundaries. The request contract gaps remain tracked separately in issue #13.
