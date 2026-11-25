# Runner Request Contract Gap Analysis — Proposal

> **Status: design proposal only. Not normative and not approved for implementation.**
>
> This document translates the six gaps in issue #13 into reviewable field semantics. It does not change protocol v1, Go types, API behavior, or execution safety gates.

## 1. Current boundary

The Go runner request model currently carries execution, attempt and problem-version identifiers; action; language and runtime version; source-artifact ID and SHA-256; test-bundle ID; and CPU, memory, wall-time, process and output limits.

The normative runner protocol also requires tenant-safe correlation, immutable runtime image identity, comparison policy, filesystem limits, deadline and cancellation. The repository currently has no execution HTTP handler, API-to-runner adapter or configured executor. Keep `UnconfiguredExecutor` fail-closed until the contract and M0 evidence are approved.

## 2. Proposed field semantics

| Concept | Candidate field(s) | Candidate type / rule | Trust boundary |
| --- | --- | --- | --- |
| Tenant-safe tracing and authorization | `tenantId`, `correlationId` | Tenant ID is an opaque internal identifier; correlation ID is a server-generated opaque ID with a bounded ASCII grammar and length | API derives tenant ID from authenticated principal and injects both fields. Never accept either as student-controlled policy. Correlation ID is for tracing, not authorization. |
| Immutable runtime image | `runtimeImage` | Canonical OCI image reference pinned with `@sha256:<64 lowercase hex>`; separate from `runtimeVersion` | Trusted runtime catalog selects the exact image from an allowlist. A syntactically valid digest alone is not authorization. |
| Output comparison | `comparisonPolicy` | Required closed enum with explicit version, initially evaluate `EXACT_BYTES_V1` and `NORMALIZED_TEXT_V1` | Problem version / trusted assessment policy selects it. Never infer from source code or silently default. |
| Writable filesystem limits | `filesystemLimits.scratchBytes`, `filesystemLimits.scratchInodes` | Positive bounded integers; define scope as runner-created writable scratch only, with runtime image and mounted test bundle read-only | Trusted policy service sets values; runner validates against hard platform maxima. |
| Execution deadline | `deadlineAt` | Absolute RFC 3339 UTC timestamp at the service boundary; runner converts to a bounded remaining duration and applies the stricter of deadline and wall-time limit | Trusted API/orchestrator creates it. Reject malformed or expired deadlines; never let a caller extend trusted wall-time policy. |
| Cancellation | `cancellationId` | Opaque, non-secret reference bound to one execution ID; not a bearer credential | Trusted orchestrator creates it. Cancellation is delivered over an authenticated control-plane channel; never expose it to browser/student or include secrets in logs. |

These names and exact types are candidates for review, not approved wire fields.

## 3. Decisions that need explicit approval

1. **Tenant context:** confirm whether the runner needs the tenant ID in the execution envelope or whether authenticated transport metadata can provide it. In either design, tenant authorization must be derived from trusted service identity and server-side state. Keep trace correlation distinct from tenant identity.
2. **Image identity:** define accepted registries/repositories, digest algorithm, canonicalization, runtime-catalog ownership, and image revocation behavior. Pinning a digest prevents tag drift but does not make an unreviewed image trusted.
3. **Comparison semantics:** publish byte-for-byte rules for each enum value, including UTF-8 validity, line endings, trailing spaces, final newline, and stderr handling. Prefer exact comparison as a distinct explicit policy; do not introduce normalization without problem-authoring agreement.
4. **Filesystem accounting:** decide whether scratch bytes and inode counts are both mandatory, the exact enforcement mechanism, and whether compiler caches count toward scratch. No writable host mounts are permitted.
5. **Deadline and clock behavior:** specify timestamp precision, tolerated clock skew, behavior when the deadline is already expired, and whether the service deadline includes queue time. Runner must still enforce a local monotonic wall-time ceiling.
6. **Cancellation lifecycle:** define cancellation delivery, authentication, idempotency, acknowledgement, races with completion, and retention. The identifier must not itself grant cancellation authority.
7. **Versioning:** adding required fields to v1 is a breaking change unless a documented compatibility mechanism exists. Decide whether to introduce request protocol v2 or a negotiated capability/version envelope. Do not silently make fields optional or invent defaults.

## 4. Suggested validation and test matrix

- Reject missing tenant context, correlation ID, image digest, comparison policy, filesystem byte/inode limits, deadline, and cancellation reference once the approved schema makes them required.
- Reject malformed IDs, overlong values, unsupported comparison enum values, non-canonical or non-allowlisted image references, non-positive/over-policy filesystem limits, invalid timestamps, and expired deadlines.
- Verify the tenant ID and runtime image are injected/selected by trusted services rather than copied from student input.
- Verify a cancellation reference is bound to exactly one execution and cannot be used as a credential.
- Pin JSON field names, enum strings, timestamp format, units, null/omission rules, and round-trip behavior.
- Verify protocol-version compatibility explicitly; unknown required semantics must fail closed.
- Preserve the existing rule that hidden test inputs and expected outputs never enter the request sent to an untrusted runner response or student-facing payload.

## 5. Implementation order after approval

1. Approve field names, trust boundaries, comparison semantics, and protocol-version strategy.
2. Update protocol types and strict validation together, with table-driven tests.
3. Add JSON serialization/round-trip and compatibility tests.
4. Update the normative protocol specification and API-to-runner adapter contract.
5. Keep the executor unconfigured until M0 sandbox evidence and security gates are independently satisfied.

## 6. Explicit non-goals

- No executor, process launch, container launch, or student-code execution.
- No API submission endpoint or runner HTTP handler.
- No changes to protocol v1 or existing request payloads.
- No claim that gVisor isolation has been proven or that M0 is complete.
