# Runner Request Contract — Decision Proposal

Status: **PROPOSED — NOT APPROVED / NOT NORMATIVE**

This proposal recommends concrete semantics for the six request-contract gaps identified in issue #13. It does not change the normative protocol, Go types, database schema, API, runner, or deployment. Approval is required before implementation.

## Executive recommendation

Do not silently add the missing fields to protocol v1. The current v1 Go decoder has an exact allowlist and rejects unknown fields. Treat the current v1 shape as a legacy/incomplete contract that remains non-executable. Introduce a deliberate **protocol v2** only after this proposal is approved, with a new exact JSON schema and compatibility tests.

All execution policy values must be selected by trusted server-side policy. The student may supply source and language selection through the API, but must not choose tenant identity, runtime image, test bundle, comparison policy, resource limits, deadline or cancellation authority.

## Proposed v2 field set

The names below are proposals, not accepted wire fields.

| Requirement | Proposed field | Proposed type / shape | Recommendation |
|---|---|---|---|
| Tenant-safe correlation | `correlationId` | UUID string | Generate at trusted API intake. It is trace context, not a tenant ID, authorization claim, or idempotency key. Keep tenant ownership in authenticated control-plane context and persistence. |
| Immutable runtime image | `runtimeImageDigest` | OCI digest string, initially `sha256:` + 64 lowercase hex chars | Resolve from a server-maintained allowlist keyed by language/runtime/platform. Never accept arbitrary registry URLs or image names from students. Pin platform/architecture and image digest together. |
| Comparison policy | `comparisonPolicy` | Enum string | Start M1 with `EXACT_BYTES` only. Do not trim whitespace or normalize line endings implicitly. Add further policies only with normative byte-level definitions and test vectors. |
| Filesystem limits | `limits.scratchBytes`, `limits.scratchInodes` | Positive integers | Bound writable scratch separately from immutable runtime image and read-only mounts. Enforce both byte and inode quotas; fail closed if the selected backend cannot enforce either. |
| Execution deadline | `deadlineAt` | RFC 3339 UTC timestamp | Trusted control plane computes an absolute deadline. Runner rejects expired requests and uses a monotonic local timer for elapsed execution; wall-clock timestamp is for cross-service budget propagation. Retain `wallTimeMillis` as the per-process execution cap; effective stop is the earlier of deadline and wall-time limit. |
| Cancellation reference | `cancellationRef` | Opaque random identifier (UUID or at least 128 bits of entropy) | Reference only, not a bearer token. Cancellation state is held by the trusted control plane and checked over authenticated service transport or delivered over an authenticated control channel. Never log a secret or let a caller cancel another tenant's execution. |

## Detailed decisions and validation

### 1. Correlation context

- Generate a UUID at authenticated API intake; propagate unchanged through attempt, job, dispatch and runner logs.
- Correlation is observability metadata only. It must not grant access, identify a tenant, or replace `executionId`.
- `executionId` remains the runner idempotency key.
- Do not place tenant IDs or user IDs in the correlation field.
- Validation: canonical UUID syntax; required for v2; reject empty, malformed or oversized values.
- Logs: include correlation and execution IDs; avoid logging source, hidden tests, credentials or cancellation secrets.

### 2. Runtime image identity

- Proposed field: `runtimeImageDigest`.
- Initial grammar: `sha256:[0-9a-f]{64}`.
- Trusted policy maps the accepted language/runtime/platform tuple to an approved immutable digest. A syntactically valid digest is not proof that an image is trusted.
- Registry hostname, repository, platform, architecture, signature/attestation policy and vulnerability policy remain server-side allowlist metadata. If a future runtime needs a different registry identity, add a separately reviewed field or registry mapping rather than accepting arbitrary URLs.
- The runner must verify the fetched image resolves to the exact approved digest before sandbox creation.
- Validation: required, exact algorithm prefix and lowercase hex length; reject tags and mutable references.

### 3. Comparison policy

- Proposed field: `comparisonPolicy`.
- M1 v2 initial allowed value: `EXACT_BYTES`.
- Compare expected and actual stdout bytes exactly, after the protocol-defined output capture boundary. No implicit trimming, whitespace folding, Unicode normalization or newline conversion.
- Stderr is diagnostic output, not part of the equality comparison unless a future explicit policy says otherwise.
- Test vectors must cover empty output, final newline, CRLF vs LF, trailing spaces, UTF-8 bytes and invalid UTF-8.
- Validation: required enum; unknown values rejected. Trainers may select only policies explicitly enabled by trusted problem policy; students cannot override them.

### 4. Filesystem quotas

- Proposed fields nested under `limits`: `scratchBytes` and `scratchInodes`.
- Both are positive integers with hard policy maximums defined outside the request schema.
- Apply only to writable scratch space. Runtime image and trusted test input mounts are separate, read-only mounts and must not be counted as writable scratch.
- Reject unsupported quota enforcement. Do not substitute best-effort monitoring for a hard limit.
- Acceptance tests: byte quota reached, inode quota reached, read-only runtime mount, no host path visibility, cleanup after success/failure/timeout/cancellation, and concurrent isolation.

### 5. Deadline semantics

- Proposed field: `deadlineAt`, canonical RFC 3339 UTC timestamp (for example, `2026-11-09T17:00:00Z`).
- Control plane computes the deadline before queueing; student cannot set or extend it.
- Runner checks expiry immediately before dispatch and uses a monotonic timer after start to avoid wall-clock adjustments extending runtime.
- `wallTimeMillis` remains a per-execution hard wall-time cap. The effective execution deadline is the earlier of `deadlineAt` and start time plus `wallTimeMillis`.
- Define queue-wait expiry separately: expired queued work should be marked not-started/expired by the control plane and must not launch.
- Validation: required, UTC only, bounded maximum future horizon and no unbounded deadlines. The actual horizon value is a product/security policy decision and must be configured server-side.

### 6. Cancellation reference

- Proposed field: `cancellationRef`; opaque, random, non-secret identifier.
- It is a lookup reference, not an authorization token. Possession alone must not authorize cancellation.
- Only the authenticated control plane can request cancellation after verifying tenant/attempt ownership.
- Runner cancellation delivery should use the separately approved authenticated private control channel. Do not add polling URLs, arbitrary callback URLs, bearer tokens or student-supplied endpoints to the request.
- Cancellation must terminate the process tree, sandbox and descendants, then confirm cleanup; cleanup failure is infrastructure failure and blocks successful completion.
- Validation: required for v2, bounded opaque syntax, uniqueness scoped to execution; unknown references fail closed. A separate cancellation transport and state transition contract is required before execution.

## Trust and ownership matrix

| Value | Authoritative owner | Student-controlled? |
|---|---|---|
| correlationId | API/control plane | No |
| runtimeImageDigest | Runtime policy registry | No |
| comparisonPolicy | Published problem version + trusted policy | No |
| scratchBytes / scratchInodes | Trusted resource policy | No |
| deadlineAt | Control plane scheduler | No |
| cancellationRef | Control plane | No |
| source artifact and language choice | Authenticated API intake, subject to policy | Submitted source/language choice only; reference and hash are server-issued |
| executionId | Control plane | No |

## Compatibility and migration recommendation

1. Keep current protocol v1 decoder and model unchanged; do not loosen its exact-key allowlist.
2. Mark v1 as non-executable until it contains all required policy context. Do not silently accept incomplete v1 requests in a future executor.
3. Approve the v2 field names, semantics, validation and transport envelope before implementation.
4. Add v2 Go types/decoder as a distinct versioned contract or introduce an explicit version-dispatch decoder. Never decode v2 into the v1 struct.
5. Add golden JSON fixtures and cross-language serialization tests for the API producer and Go consumer.
6. Reject unknown versions and unknown fields. Do not silently downgrade v2 to v1.
7. Implement runtime enforcement only after M0 evidence, authenticated runner identity and transport, artifact authorization, cancellation transport, and result contract are approved.

## Delegated architecture decisions — selected M1 baseline

The product owner delegated selection of the strongest practical defaults to the architecture lead on 2026-11-09. The following choices are therefore the selected M1 design baseline for implementation planning. They remain subject to the acceptance evidence below; documenting a choice does not claim that infrastructure or enforcement already exists.

### D1. Comparison semantics: EXACT_BYTES only

- Select `EXACT_BYTES` as the sole M1 comparison policy.
- Compare captured stdout byte-for-byte against the expected output bytes.
- Do not trim, normalize Unicode, fold whitespace, or convert line endings.
- Stderr remains bounded diagnostic output and is never part of the verdict comparison.
- The published problem version fixes this policy; neither students nor individual submissions can override it.
- Add golden vectors for empty output, trailing newline, CRLF/LF, trailing spaces, UTF-8, invalid UTF-8, and output truncation boundaries.
- Any future relaxed comparison mode requires a new explicitly named policy, normative semantics, test vectors, and a versioned rollout.

### D2. Deadline and queue budget

- Set a maximum end-to-end request budget of **10 minutes from trusted API intake** for M1.
- The control plane creates `deadlineAt`; the client cannot set or extend it.
- Queue wait consumes this budget. A request that reaches the runner after its deadline is expired and must not start.
- `wallTimeMillis` remains the independent hard per-execution runtime cap. Once execution starts, the effective stop is the earlier of the remaining absolute deadline and the monotonic wall-time cap.
- The 10-minute value is a platform ceiling, not a promise that every request waits 10 minutes. The server may assign shorter budgets by action or workload tier.
- Expired queued jobs transition to a terminal not-started/expired state; they are not retried as fresh work.
- Retries preserve the original execution identity and deadline. They must never reset or extend the budget.

### D3. Writable scratch quotas

- M1 default writable scratch quota: **256 MiB and 4,096 inodes per execution**.
- Hard platform maximum: **512 MiB and 8,192 inodes per execution**. A trusted policy may assign lower values; no request may exceed these ceilings.
- Apply quotas to a dedicated writable scratch mount only. Runtime images, compiler/runtime binaries, and authorized read-only test mounts remain immutable/read-only and separately accounted.
- Java and Python initially share these defaults. Introduce per-runtime profiles only when measured compiler/runtime requirements justify them; never increase limits based on student-supplied fields.
- The selected sandbox backend must enforce both byte and inode quotas as hard limits. If it cannot, execution is unavailable; best-effort monitoring is not an acceptable substitute.
- Test quota exhaustion, inode exhaustion, concurrent tenant isolation, cleanup, and host-path non-visibility.

### D4. Runtime image trust and platform

- Initial runner platform: **Linux AMD64**. Do not run an ARM image or silently fall back to another architecture.
- Use a trusted OCI registry allowlist controlled by deployment configuration. GitHub Container Registry is the preferred initial candidate because the source and CI live in GitHub; it is not considered configured until the repository, permissions, and pull path are verified.
- The request carries the exact platform-specific OCI manifest digest, not a tag, mutable image name, or multi-platform index whose selected child could vary.
- Require Cosign signature verification tied to the approved CI workflow identity and repository, plus build provenance for the runtime image. Pin the verifier policy and trusted identity in deployment configuration.
- The server resolves language/runtime/platform to an approved image digest. The runner independently verifies the exact digest and signature/provenance policy before sandbox creation.
- Any registry, signature, provenance, platform, or digest verification failure is an infrastructure failure and must fail closed.
- Runtime image updates are explicit reviewed changes with new digests, vulnerability review, smoke tests, and rollback references.

### D5. Cancellation transport and semantics

- Use a private runner ingress exposed through a Cloudflare Tunnel and protected by Cloudflare Access service identity for the initial Cloudflare-hosted control plane integration.
- Runner machine identity must validate the Access JWT issuer, audience, expiry, and service identity, then resolve the identity through the runner registry. Never trust caller-supplied runnerId, poolId, tenantId, or scopes.
- Store Access service-token credentials only as managed secrets on the control-plane side; rotate them. Do not put them in execution requests, images, source snapshots, logs, or student-visible configuration.
- Cancellation is an authenticated control-plane operation after tenant/attempt ownership is checked. The runner cancellation endpoint is not a student-facing endpoint.
- Cancellation requests are idempotent and bound to executionId plus cancellationRef. A cancellation reference is a lookup identifier, not authorization.
- The runner must terminate the full process tree and sandbox, reap descendants, verify cleanup, and return an authenticated acknowledgement. If acknowledgement is lost, the control plane reconciles state; it does not assume cancellation succeeded.
- Before production use, prove the exact Worker-to-Tunnel-to-Access-to-runner path in a non-production environment, including JWT validation, credential rotation, replay rejection, timeout, duplicate cancellation, and unreachable-runner behavior. If Cloudflare Access cannot provide the required machine identity semantics for this topology, block execution and revisit the transport ADR rather than weakening authentication.

### D6. Protocol v1 lifecycle

- Protocol v1 is permanently **non-executable**. Retain its strict decoder only for compatibility tests, diagnostics, and any explicitly approved migration tooling.
- All new dispatches use protocol v2 after the v2 producer/consumer golden fixtures and all required enforcement gates pass.
- Never translate a v1 request into v2 by filling missing security policy with defaults at the runner boundary.
- Reject unknown versions and downgrade attempts. Remove v1 parsing only through a separately reviewed compatibility/deprecation change after confirming no retained evidence or operational tooling depends on it.

## Implementation prerequisites (evidence, not open-ended design choices)

The baseline above is selected. The following are concrete facts that must be established before the relevant implementation can be enabled:

- Confirm the actual Cloudflare Access application/audience, Tunnel hostname, service-token lifecycle, and Worker secret bindings in a non-production environment.
- Create and review the runtime registry repository, CI identity, signing/provenance workflow, and immutable Linux AMD64 image digests.
- Verify that the chosen gVisor/OCI host can hard-enforce scratch byte and inode quotas and all existing CPU, memory, PID, wall-time, and output limits.
- Demonstrate cancellation delivery, process-tree termination, cleanup acknowledgement, and recovery from lost acknowledgements.
- Obtain and retain M0 adversarial isolation evidence and security review before enabling any executor.
- Define numeric per-action/per-problem values below the selected platform ceilings using measured resource profiles; the ceilings above are not automatically granted to every execution.


## Acceptance criteria for implementation

- Protocol v2 has a normative schema and versioning policy.
- TypeScript producer and Go consumer share golden request fixtures.
- Strict decoder rejects duplicate, unknown, non-canonical, oversized, expired and invalid-policy requests.
- Resource policy values are server-selected and bounded by platform maxima.
- Image digest is allowlisted and verified before launch.
- Filesystem byte and inode quotas are hard-enforced and adversarially tested.
- Deadline and cancellation stop process trees and sandbox cleanup is evidenced.
- No hidden test input/expected output or credentials enter untrusted request/response/log surfaces.
- M0 isolation evidence and security review pass before any student source executes.

## Non-goals

This proposal does not implement protocol v2, configure or prove the selected Cloudflare Access/Tunnel topology, create the runtime registry or signing workflow, define the result DTO, enable a queue consumer, retrieve artifacts, launch gVisor, or execute student code. The selected scratch quotas are policy ceilings/defaults; measured per-action values must still be configured below those ceilings.
