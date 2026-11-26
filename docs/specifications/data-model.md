# Logical Data Model

Reuse Sky High identity, college, batch and student entities. Do not duplicate identity tables.

## Core entities
- problems: stable problem identity, slug, title, difficulty, tags, ownership and lifecycle.
- problem_versions: immutable statement, constraints, input/output specification, comparator policy, runtime policy and version.
- test_cases: public/sample test metadata and private object references.
- hidden_test_cases: private test metadata/object references; service-only access.
- language_runtimes: language, runtime version, image digest, compile/run command template and availability.
- submissions: official Submit identity, student, problem version, language, status and timestamps.
- execution_attempts: immutable Run or Submit event, actor, source hash, snapshot ref, runtime, action and result link.
- code_snapshots: immutable source bytes or object ref, hash, size, encoding and creation time.
- execution_jobs: execution ID, attempt ID, state, lease, retry count, idempotency key and timestamps.
- test_case_results: per-test status, time, memory and sanitized detail; hidden case identifiers/results must not leak.
- evaluation_reports: verdict, passed/total counts, aggregate metrics, policy versions and completion time.
- code_analysis_findings: rule ID/version, location, severity, evidence and advisory score.
- ai_feedback: model/provider/version, prompt policy version, evidence references, generated text and safety review status.
- audit_events: security-relevant actor, action, resource, correlation ID and timestamp.

## Integrity rules
- Every row is scoped to authorized tenant/college context.
- Problem versions and snapshots are immutable.
- Each Run and Submit creates a new attempt.
- Hash exact source bytes (SHA-256) and record byte length.
- Persist UTC timestamps.
- Use UUID or collision-resistant opaque IDs.
- Enforce uniqueness on execution ID and idempotency key in the correct scope.
- Result persistence is idempotent and cannot overwrite a terminal result with a conflicting result.
- Use foreign keys and explicit deletion/retention workflows.

## Storage placement
PostgreSQL: transactional metadata, source content when small, attempts, jobs, test outcomes, reports and audit metadata.
R2: larger immutable source/log artifacts where size or access pattern justifies object storage.
Never store publicly accessible hidden test files. Keep object keys private and non-guessable; authorize access through server-side checks.

## Indexes to plan
student_id + created_at on attempts; problem_version_id + status on submissions; state + created_at on jobs; unique execution_id; unique scoped idempotency key; foreign keys for tenant and problem version. Validate indexes with query plans before production.
