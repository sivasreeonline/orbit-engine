# Runner Request Contract Gap Disposition

Status: engineering audit; non-normative; no protocol fields or semantics are changed by this document.

This record traces the current Go request boundary and separates requirements already represented in protocol v1 from requirements that need an explicit contract decision before implementation.

## Current consumer and boundary trace

| Area | Current state | Consequence |
|---|---|---|
| `internal/protocol/types.go` | Defines `ExecutionRequest` and `ResourceLimits`; contains IDs, action, language, runtime version, artifact/test references, source hash, and CPU/memory/wall-time/process/output limits. | This is the only current Go request data model. |
| `internal/protocol/validate.go` | Validates v1, opaque IDs, RUN/SUBMIT, Java/Python, runtime token, SHA-256 syntax, and positive resource limits. | Semantic validation is limited to represented fields; positive-only limits are not policy authorization. |
| `internal/protocol/decode.go` | Bounded strict JSON decoder; exact canonical keys, duplicate/unknown-key rejection, top-level object requirement, trailing-value rejection, and 64 KiB cap. | Structural parsing is enforced before model validation. |
| `internal/protocol/*_test.go` | Unit coverage for request validation, decoding and serialization behavior. | Tests cover the current Go model, not missing protocol concepts. |
| `internal/runner` | Executor interface plus `UnconfiguredExecutor`; no configured implementation. | Request is not executed. Fail-closed behavior remains. |
| Runner HTTP process | Health/readiness only; no execution request route. | No HTTP consumer currently accepts this request. |
| API / queue / dispatch | Intake, outbox, dispatch and receipt foundations exist in separate layers, but no production API-to-runner request adapter or runner execution endpoint is wired. | There is no end-to-end request consumer to update yet. |

## Requirement disposition

| Protocol requirement | Current representation | Disposition |
|---|---|---|
| Protocol version | `protocolVersion`, currently exactly `v1` | Represented and validated. |
| Execution / attempt / problem version identity | Opaque IDs | Represented and validated syntactically. Authorization and tenant ownership remain upstream responsibilities. |
| Source artifact reference and SHA-256 | `sourceArtifactId`, `sourceSha256` | Represented and validated syntactically. Artifact retrieval and hash verification are not implemented. |
| Language and runtime version | `language`, `runtimeVersion` | Represented and validated syntactically. Runtime selection must remain server-controlled. |
| Test bundle reference | `testBundleId` | Represented as opaque ID. Authorization and hidden-test retrieval are not implemented. |
| Run / Submit | `action` enum | Represented as RUN or SUBMIT. |
| CPU, memory, wall time, process and output limits | `limits` | Represented and required positive. Trusted policy issuance and hard enforcement are not implemented. |
| Tenant-safe correlation identifier | Missing | Decision required: define whether this is a distinct opaque request field or transport metadata, its tenant-scoped uniqueness, propagation and logging/redaction rules. Never accept a student-selected tenant identity. |
| Immutable runtime image digest | Missing | Decision required: OCI digest grammar, registry trust/allowlist, platform/architecture binding, and whether digest is selected solely by trusted policy. Do not conflate with language runtime version. |
| Comparison policy | Missing | Decision required: supported policy identifiers and exact stdout/stderr normalization, encoding, newline, exit-code and determinism semantics. |
| Filesystem limits | Missing | Decision required: writable scratch byte and inode limits, mount boundaries, tmpfs semantics, and distinction from immutable runtime image. |
| Explicit deadline | Missing | Decision required: absolute UTC deadline vs bounded duration (or both), clock authority, maximum horizon, queue delay behavior and cancellation on expiry. |
| Cancellation reference | Missing | Decision required: opaque non-secret reference, ownership, lookup authority, revocation and propagation semantics. Never place bearer credentials in request fields or logs. |
| Result contract | No result DTO or HTTP response path | Separate result-contract decision remains open; do not infer result fields from the request requirements. |

## Safe implementation boundary

The following are safe to do without changing protocol semantics:

1. Keep strict parsing and validation tests aligned with the fields already in v1.
2. Keep request identity and policy values server-issued; do not accept student-supplied tenant, runtime image, test-bundle authorization or resource policy.
3. Keep the executor fail-closed until the M0 isolation gates and the remaining contract decisions are approved.
4. Add an adapter only after the request and result contracts, authentication boundary and transport are approved together.

The following are **not** safe to implement as guessed protocol-v1 fields: correlation identity, OCI image digest, comparison policy, filesystem quotas, deadline representation or cancellation reference. Adding any of them changes the wire contract and requires explicit field/type/validation/versioning decisions.

## Suggested decision sequence

1. Decide correlation context and tenant ownership/propagation.
2. Decide runtime image identity and trusted registry/platform policy.
3. Decide comparison semantics with deterministic test vectors.
4. Decide scratch filesystem byte/inode limits and mount model.
5. Decide deadline and cancellation lifecycle as one coordinated policy.
6. Update the normative protocol and version compatibility plan.
7. Implement request model, validation, serialization and consumer contract tests.
8. Only then implement the authenticated API-to-runner adapter; execution remains blocked by M0.

## Non-goals

This audit does not select an identity provider, transport, OCI runtime, result schema, queue state machine or production resource policy. It does not add an HTTP execution route, retrieve artifacts, launch a sandbox or execute student code.
