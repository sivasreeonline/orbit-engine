# Student Capability Evidence and Continuous Editor Capture

**Status:** Approved product direction; implementation contract for phased delivery  
**Product decision:** Sky High Blueprint ADR 0001 — Evidence-Driven Student Capability Intelligence  
**Date:** 2026-11-13

## 1. Purpose

Sky High must preserve more than final Accepted/Rejected outcomes. It should collect a privacy-conscious, auditable record of how a student develops code, tests it, revises it, explains decisions, and transfers knowledge to new problems.

The system separates:

1. **Observed evidence** — immutable editor/session events, versioned source snapshots, Run/Submit snapshots, execution outputs, reasoning responses, and supervised verification outcomes.
2. **Derived features** — diffs, code-evolution metrics, edit-activity aggregates, debugging trajectories, evidence coverage, and personal baselines.
3. **Interpretations** — capability estimates, confidence, anomaly explanations, and trainer recommendations.

Raw evidence is authoritative for what was captured. Derived features and AI interpretations are versioned and reproducible; they never rewrite raw evidence or change deterministic execution verdicts.

## 2. Collection policy

Collection runs only during an explicitly disclosed, active coding/assessment session. The student must be shown the session notice before evidence collection begins.

### Capture cadence

- **Change-aware interval:** nominally every 2 minutes. Create a full-code snapshot only when the editor document changed since the previous complete snapshot.
- **Checkpoint boundary:** at least every 5 minutes while the session is active. If source content is unchanged, write a checkpoint event referencing the existing snapshot ID and SHA-256 instead of storing duplicate bytes.
- **Run:** create an immutable source snapshot tied to that specific Run attempt before submitting the execution request.
- **Submit:** create a separate immutable source snapshot tied to that specific Submit attempt.
- **Meaningful edit activity:** aggregate edit activity into coarse time buckets (for example, 10–30 seconds) with counts/size deltas. Do not persist raw keystrokes or individual character sequences.
- **Session lifecycle:** record start, pause/resume, visibility changes for the Sky High assessment page, network/synchronization gaps, and end.
- **Language/problem transition:** close or explicitly segment the current editor document so snapshots cannot be misattributed to another language or problem.

The capture schedule must use monotonic elapsed time for local intervals; server receipt time is authoritative for ingestion. Client timestamps remain useful observations and must not be treated as trusted wall-clock proof.

### Capture exclusions

Never collect desktop screenshots, mobile screen contents, operating-system activity, unrelated browser tabs, clipboard contents, passwords, tokens, text from other applications, or keylogging outside the editor. Do not infer that a paste occurred or identify its source unless a supported editor event explicitly provides that limited fact. A bulk insertion is not proof of LLM or third-party assistance.

Focus/visibility signals describe only visibility/focus of the Sky High assessment page. They are context, not proof of misconduct.

## 3. Event model

Every event is immutable and has:

- `schemaVersion`;
- globally unique `eventId` (idempotency key);
- server-issued `sessionId`;
- monotonically increasing per-session `sequence`;
- `eventType`;
- client-observed `occurredAt` and server `receivedAt`;
- authenticated actor/tenant resolved server-side, never trusted from the event body;
- problem/version and language context where applicable;
- optional `snapshotId`, content hash, and bounded metadata;
- ingestion receipt / correlation identity.

Initial event types:

| Event | Purpose |
|---|---|
| `SESSION_STARTED` | Session boundary and policy/notice version |
| `EDITOR_ACTIVITY_AGGREGATE` | Coarse edit/change counts and time bucket |
| `CODE_SNAPSHOT_CREATED` | New immutable editor document version |
| `CHECKPOINT_RECORDED` | Five-minute checkpoint; references unchanged snapshot when appropriate |
| `RUN_REQUESTED` | Immutable Run source version and attempt reference |
| `SUBMIT_REQUESTED` | Immutable Submit source version and attempt reference |
| `PAGE_VISIBILITY_CHANGED` | Assessment page became visible/hidden |
| `SESSION_PAUSED` / `SESSION_RESUMED` | Explicit pause and resume boundaries |
| `SYNC_GAP_RECORDED` | Client detected an upload/network gap; not evidence of misconduct |
| `SESSION_ENDED` | Final checkpoint and session close |

Example event envelope (illustrative; exact API DTO is to be versioned):

```json
{
  "schemaVersion": 1,
  "eventId": "unique-event-uuid",
  "sessionId": "server-issued-session-uuid",
  "sequence": 42,
  "eventType": "CHECKPOINT_RECORDED",
  "occurredAt": "2026-11-13T05:00:00.000Z",
  "problemVersionId": "problem-version-uuid",
  "language": "java",
  "snapshotId": "snapshot-uuid",
  "contentSha256": "64-lowercase-hex-characters",
  "metadata": {
    "unchangedSincePreviousSnapshot": true
  }
}
```

The client may send `eventId`, `sessionId`, sequence, observed timestamp, and allowed evidence fields; tenant, student identity, authorization, and server receipt time are derived or assigned server-side.

## 4. Snapshot model

A source snapshot is a full, immutable editor document at a specific boundary.

Required metadata:
- snapshot ID, session ID, sequence and event ID;
- problem and immutable problem-version IDs;
- language and trusted runtime version reference;
- source byte length and SHA-256;
- snapshot kind: periodic, checkpoint, Run, Submit, or session-final;
- prior snapshot ID (when present);
- server received timestamp and ingestion status.

Store snapshot metadata transactionally in PostgreSQL and bytes through a storage interface. Development uses local storage. Hosted deployment may use private R2 objects, consistent with the existing artifact-storage architecture. Do not expose public object URLs or broad storage credentials to students or runners. Access must be owner/tenant-scoped and audited.

A Run/Submit operation must reference its exact immutable snapshot. Subsequent editor changes must never mutate an already queued or executed attempt.

Do not duplicate identical source bytes: content addressing may reuse blob storage by hash, but every logical snapshot version and association remains separately auditable. Deduplication must not cross tenant access boundaries.

## 5. Ordering, integrity, offline and failure semantics

- Enforce unique `(session_id, sequence)` and unique `event_id` for idempotency.
- Accept retried batches without duplicate logical events.
- Detect sequence gaps and record them; do not silently renumber client events.
- Preserve client-observed time separately from server-received time. Never use client time alone to establish precise ordering across devices or sessions.
- Validate schema, byte limits, ownership, problem version and language on the server.
- Use bounded batches and rate limits. Snapshot size must be capped consistently with execution intake limits.
- The first implementation must make synchronization state visible. Durable offline buffering requires a separate reviewed browser-storage/encryption/key-management design; plaintext localStorage is not acceptable for source evidence.
- If synchronization is unavailable, do not claim evidence was durably received. Preserve a visible pending/gap state and retry idempotently when the session reconnects.
- Browser-generated events are client-observed and can be altered by a compromised client. Hashes and server receipts improve tamper detection and auditability but do not prove a human typed every character.

## 6. Evidence-derived features

Features are computed in versioned, reproducible jobs from immutable evidence. Initial feature groups:

### Code evolution
- snapshot-to-snapshot line/token change ratios;
- new/deleted function and block counts;
- structural replacement versus incremental revision;
- time between meaningful revisions;
- relationship between intermediate versions and final solution.

### Edit activity
- coarse insertion/deletion counts and burst-size distribution;
- idle/active intervals while the assessment page is visible;
- revision, undo/redo, and correction aggregates when provided by editor APIs;
- editor-origin metadata only when the editor explicitly supports it.

### Debugging trajectory
- compilation outcomes, safe compiler diagnostic categories, runtime failure categories;
- tests passed/failed per Run/Submit where policy allows;
- time and code evolution between a failure and subsequent correction;
- repeated error categories across problems.

### Cross-problem consistency and transfer
- consistency of algorithm use, reasoning and implementation across related problems;
- ability to solve a new variation;
- ability to reproduce or modify a solution after a delay;
- performance trend over comparable tasks with difficulty/context accounted for.

Personal baselines require sufficient repeated observations and must be recalibrated as the learner improves. Do not label a student using sparse evidence or a single session.

## 7. Seven capability dimensions

Each capability output must include an estimated level, confidence, evidence coverage, freshness, contributing evidence references, model/rule version, and known limitations.

1. **Problem understanding** — correctly identifies inputs, outputs, constraints, examples, and edge cases.
2. **Algorithmic thinking** — develops, compares, and justifies approaches and complexity.
3. **Independent coding** — translates an approach into code with a development trajectory consistent with demonstrated knowledge.
4. **Debugging ability** — diagnoses errors, tests hypotheses, and makes effective corrections.
5. **Adaptability** — adjusts solutions when constraints or problem requirements change.
6. **Code ownership** — can explain, trace, modify, and defend their own submitted implementation.
7. **Consistency and retention** — demonstrates repeatable ability and retains concepts across problems and time.

Confidence is about the quality and coverage of evidence supporting an estimate, not a probability that a student is honest. Missing data is "not observed", never "unable".

## 8. Knowledge verification

Use assessment instruments as direct evidence of understanding:

- a short pre-coding plan or complexity/edge-case prompt (optional in practice; selected by assessment policy in formal assessments);
- explanation questions about the student's actual code;
- debugging tasks with a known defect;
- unseen or modified problem variations;
- delayed reproduction tasks where appropriate;
- instructor-supervised oral explanation when policy and accessibility needs permit.

Question selection and difficulty must be versioned. Do not reveal hidden tests or expected answers to the runner or student. Keep deterministic correctness verdicts separate from capability estimates and AI feedback.

## 9. Anomaly analysis and human review

Anomaly analysis may combine:
- unusual change volume or large structural insertions;
- deviation from the student's own historical code-evolution patterns;
- timing and submission-gap context;
- code-style/structure changes;
- mismatch between stated reasoning and implementation;
- inability to explain or adapt the submitted code;
- cross-problem and supervised-variation results.

No individual signal proves copying, LLM usage, or misconduct. Fast typing, slow typing, code formatting, one large insertion, long inactivity, sudden improvement, and accessibility tooling all have plausible benign explanations.

AI outputs are advisory. A trainer review item must show observations, evidence references, model/rule version, confidence/coverage, missing data, benign alternative explanations, and a recommended verification step. Consequential decisions require human review and an audit record. AI cannot change the deterministic execution verdict or automatically penalize a student.

## 10. Privacy, access and governance

Before institutional rollout, define:
- exact notice and assessment-policy text;
- lawful basis/consent and student-facing controls as applicable;
- access by student, trainer, TPO and support roles;
- college/tenant isolation for events, snapshots, derived features and exports;
- retention periods by evidence type, deletion and correction workflows;
- audit logs for evidence access and trainer review;
- encryption at rest/in transit, key management, backup and incident response;
- handling of minors and institution-specific requirements where applicable.

Collect only evidence necessary for learning, assessment integrity, and explicitly stated purposes. Retention and access must be least-privilege and auditable.

## 11. Phased implementation

1. Define and test event/snapshot DTOs, schema versions, ownership and sequence semantics.
2. Add backend session creation and bounded idempotent evidence ingestion.
3. Add local development storage behind the same snapshot-storage interface planned for private hosted object storage.
4. Integrate CodeMirror change-aware snapshotting, two-minute dirty capture, five-minute checkpoint, Run/Submit snapshot references and visible sync status.
5. Add durable, reviewed offline synchronization and retention/deletion controls.
6. Build deterministic code-evolution/debugging feature extraction with provenance.
7. Add reasoning/debugging/variation instruments.
8. Calibrate the seven capability dimensions with pilot assessments and trainer review.
9. Add advisory anomaly review workflows; validate false-positive behaviour before enabling any trainer-facing risk indicator.

## 12. Acceptance tests

- Dirty editor content is captured on the configured two-minute cadence; unchanged content does not create duplicate full snapshots.
- A five-minute checkpoint is recorded even when no content changed.
- Run and Submit each reference their own immutable source version.
- Changing the editor after Run/Submit cannot mutate the referenced source version.
- Event retries are idempotent; duplicate event IDs do not duplicate records.
- Out-of-order events and sequence gaps are surfaced without rewriting source history.
- Invalid session ownership, tenant IDs, problem versions, unsupported fields, oversized payloads, and unauthorized snapshot reads are rejected.
- Network loss and browser reload do not silently claim server durability; pending/gap status is recoverable.
- No clipboard, device-wide screenshot, unrelated browsing, OS activity, or outside-editor keystrokes are collected.
- Benign cases (fast typists, slow typists, paste/import, formatters, accessibility tools, network loss, novice improvement) do not independently trigger a misconduct conclusion.
- Every capability estimate and trainer recommendation is traceable to evidence and versioned features.
- AI/anomaly outputs cannot modify deterministic execution results or automatically penalize students.
- 500 online-session load tests are separate from execution concurrency, queue throughput and sandbox load tests.

## 13. Explicit non-goals

This specification does not promise perfect detection of LLM-assisted work, identify the origin of pasted text, authorize desktop/mobile surveillance, establish a final production retention policy, claim 500 simultaneous executions, or enable student code execution. Linux/gVisor qualification remains a separate hard gate.
