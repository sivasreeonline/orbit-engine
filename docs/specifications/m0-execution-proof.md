# M0 — Isolated Execution Proof

## Related M0 proof contracts

- Host preflight and evidence collection: `m0-host-preflight-and-proof-runbook.md`.
- Adversarial fixture IDs and expected host-side assertions: `m0-adversarial-fixture-contract.md`.
- Host supervisor boundary, lifecycle state machine, and recovery design: `m0-runtime-proof-harness-design.md`.
- Structured evidence manifest: `../schemas/m0-proof-evidence.schema.json`.

These are design and review artifacts only. They do not authorize sandbox launch, student execution, cloud provisioning, or executor activation.

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
