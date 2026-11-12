# Evidence Engine E1.2 — Immutable Attempt Comparison Contract

- Status: design contract; implementation follows after the intake schema and storage adapters are verified on the active stacked branch.
- Depends on: E1 source snapshot retrieval (PR #121) and append-only execution evidence (PR #119).
- Proposed API shape: GET /api/v1/attempts/{targetAttemptId}/diff?baseAttemptId={baseAttemptId}
- Purpose: compare two admitted execution snapshots without reading mutable editor state.

## Product and research alignment

The coding journey is the evidence, not only the final verdict. Each meaningful Run and Submit is a separate immutable attempt. A comparison is a derived view over two preserved source artifacts; it must never modify either attempt or replace the original bytes.

This slice supports the code-snapshot/diff direction in F2D-0005 and the immutable Run/Submit evidence requirements in F2D-0276 and F2D-0277. It does not add keystroke-level capture.

## Comparison eligibility

The server must establish all of the following before returning a comparison:

1. Both attempts belong to the authenticated tenant and authenticated student.
2. Both attempts refer to the same problem identity and the same immutable problem version.
3. Both attempts use the same language and compatible runtime version.
4. Both source snapshots are present and pass byte-length, SHA-256 and strict UTF-8 verification.
5. The two attempt identifiers are distinct.

The comparison query must establish eligibility in one owner-scoped database operation (or a transaction with equivalent consistent-read guarantees). Do not fetch arbitrary attempt IDs independently and assume they are comparable. Do not trust client-supplied tenant, student, problem, language or runtime metadata.

If either attempt is outside the caller's scope, return the same non-disclosing not-found response used by source retrieval. If the attempts exist but are not comparable, return a stable non-disclosing conflict response. If either source is R2-backed and the private object reader is unavailable, fail closed with retryable unavailable; never expose object keys or public URLs.

## Diff semantics

- Compare only the exact verified source strings retrieved from immutable snapshots.
- Preserve original line-ending bytes (LF versus CRLF), Unicode, whitespace and trailing-newline differences.
- Never normalize source before hashing or before preserving the original snapshot.
- Return structured line operations (EQUAL, INSERT, DELETE) or bounded hunks; do not return HTML.
- Keep base and target attempt IDs, source hashes and line/byte counts with the derived comparison.
- The diff is derived data. It is reproducible from the two immutable source snapshots and must not be represented as a new raw execution event.
- No compiler diagnostics, hidden tests, expected outputs, private judge details or other students' source may appear in this response.

## Resource and abuse boundaries

Before implementation, choose and test explicit limits for source bytes, line count, diff work and response size. Reject over-limit comparisons with a stable client error; never silently truncate either source and present a partial diff as complete. The diff algorithm must have a documented worst-case resource bound and deterministic output. Avoid adding a runtime dependency unless it materially improves correctness and is justified by repository policy.

## Validation required

- Identical source produces only equal operations.
- Insertions, deletions and replacements produce deterministic operations.
- Empty source and final-newline differences are represented correctly.
- LF, CRLF, tabs, whitespace and Unicode remain distinguishable.
- Invalid UTF-8, hash mismatch and byte-length mismatch fail integrity validation.
- Cross-tenant and cross-student attempts are indistinguishable from missing attempts.
- Different problems, problem versions, languages or incompatible runtimes cannot be compared.
- Duplicate attempt IDs are rejected.
- Oversized inputs fail closed without partial output.
- R2-backed snapshots remain unavailable until private authenticated object retrieval is implemented.

## Explicit exclusions

This contract does not implement a browser-side diff, editor autosave, keystroke capture, trainer access, R2 retrieval, code execution, retention/deletion policy or learning-intelligence conclusions. Those remain separate evidence and authorization milestones.
