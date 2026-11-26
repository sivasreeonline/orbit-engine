# Runner Protocol

## Purpose
Stable adapter contract between orchestration and independently deployed Go runner. API and assessment logic must not depend on a specific OCI engine or sandbox vendor.

## Execution request
- executionId, attemptId, tenant-safe correlation ID.
- source artifact reference and SHA-256 hash.
- language, runtime version and immutable image digest.
- problem version and authorized test bundle reference.
- action Run/Submit and comparison policy.
- CPU, memory, wall-clock, PID, filesystem and output limits issued by trusted policy service.
- deadline, cancellation token/reference and protocol version.

## Execution result
- executionId and source hash confirmation.
- infrastructureStatus and runnerVersion.
- compilation status and bounded compile output.
- per-test sanitized status, elapsed time and memory measurements.
- exit code, timeout/OOM/output-limit flags.
- bounded stdout/stderr for public tests only.
- startedAt, completedAt and sandbox cleanup status.

## Protocol requirements
- Authenticate runner service identity; do not trust tenant or resource policy supplied by student.
- Validate all payload fields and artifact hashes.
- Idempotency key is executionId.
- Use explicit deadlines and cancellation.
- Stream or cap output; never buffer unbounded output.
- Distinguish infrastructure failure from student verdict.
- Results must be safe to retry and persist exactly once logically.
- Never return hidden input or expected output.
