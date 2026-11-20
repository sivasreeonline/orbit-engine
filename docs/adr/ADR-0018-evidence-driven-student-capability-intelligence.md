# ADR-0018: Evidence-Driven Student Capability Intelligence

- **Status:** Accepted
- **Date:** 2026-11-13
- **Owner decision:** Approved in product direction; implementation and rollout remain gated by validation.

## Context

Accepted/Rejected and final code snapshots do not fully reveal how a student understands a problem, develops an algorithm, debugs, or transfers knowledge. Sky High's differentiator is to preserve the coding journey and use evidence to help students and trainers understand capability and improvement.

Development must remain zero-cost local-first. A target of 500 online students must not be confused with 500 simultaneous executions. Evidence collection must be transparent, minimized, auditable, and fair.

## Decision

1. **Execution:** Develop and qualify locally without a paid judge/execution vendor. Paid infrastructure may be considered only when deployment needs it and after a separate cost/security/operational review.
2. **Concurrency:** Plan and test for 500 online sessions. Execute code through a durable fair queue with measured, bounded runner concurrency. Do not claim 500 simultaneous executions.
3. **Editor capture:** During a disclosed active coding session, capture changed editor documents on a nominal two-minute cadence and create a checkpoint at least every five minutes. Unchanged checkpoints may reference an existing snapshot. Run and Submit each bind to their own immutable source snapshot.
4. **Evidence storage:** Preserve append-only event history and versioned full-code snapshots. Use stable event/snapshot IDs, per-session ordering, UTC timestamps, hashes, server receipts, idempotent ingestion, and versioned derived features.
5. **Anomaly analysis:** Analyse multiple signals (code evolution, coarse edit aggregates, timing, revisions, structural changes, personal baseline deviations, reasoning alignment and verification outcomes). No individual signal or AI output constitutes a cheating verdict.
6. **Capability dimensions:** Maintain seven evidence-backed dimensions: problem understanding, algorithmic thinking, independent coding, debugging ability, adaptability, code ownership, and consistency/retention. Every estimate must carry evidence references, coverage, freshness, confidence and limitations. Sparse evidence is "not observed", not "unable".
7. **Knowledge verification:** Use reasoning prompts, explanation of submitted code, debugging tasks, and unseen/modified variations as direct evidence of understanding and transfer. Keep deterministic correctness verdicts separate from AI analysis and capability estimates.
8. **Trainer decisions:** Provide evidence-backed recommendations, uncertainty, missing evidence and alternative explanations. Consequential decisions require human review and an auditable review record.

## Privacy and fairness constraints

- Collect only the actual Sky High editor document and narrowly scoped editor/session events during the disclosed session.
- Do not collect desktop/mobile screenshots, clipboard contents, passwords, unrelated tabs/apps, OS activity, or keystrokes outside the editor.
- Page visibility/focus signals are context, not proof of assistance.
- Fast or slow typing, code style, bulk insertion, long pauses, and sudden improvement cannot independently establish misconduct.
- Browser events are client-observed and are not proof that a human typed each character. Hashes and server receipts improve integrity/auditability, not human attribution.
- Network loss, browser failure and missing telemetry are evidence gaps, not misconduct.
- Define notice, retention, deletion/correction, access control, encryption/key management, tenant isolation and audit before institutional rollout.

## Consequences

- Student 360 can explain learning progress, not merely count accepted submissions.
- The system needs continuous evidence ingestion, snapshot versioning, feature provenance, capability calibration and trainer review workflows.
- Event/snapshot capture and storage increase bandwidth and storage costs; cadence, retention and compression must be measured.
- Capability confidence is a measure of evidence coverage/quality, not a probability of honesty.
- 500 online sessions requires load testing independently of execution throughput.

## Implementation order

1. Finish the authenticated runner client/lifecycle and keep execution disabled until M0.
2. Deliver local Java/Python sandbox qualification and connect actual Run/Submit.
3. Implement the editor evidence event/snapshot model and authenticated ingestion.
4. Implement CodeMirror capture (two-minute dirty capture; five-minute checkpoint) and visible sync status.
5. Add deterministic code-evolution/debugging features and provenance.
6. Add reasoning, debugging and unseen-variation assessment instruments.
7. Calibrate seven capability dimensions against pilot assessments and trainer review.
8. Enable advisory anomaly review only after false-positive and fairness validation.

## Validation gates

- Capture schedule, immutability, sequence ordering, retries, offline/gap semantics and snapshot hashes are tested.
- Security/privacy/tenant isolation and retention/deletion are reviewed.
- Benign cases (accessibility tools, formatting, paste/import, fast/slow typing, network failure and genuine improvement) are tested.
- Capability outputs are calibrated and traceable; AI cannot change verdicts or automatically penalize students.
- 500-online-session tests are reported separately from queue throughput and sandbox concurrency.
- Linux/gVisor M0 security qualification is mandatory before untrusted student code executes.

## Non-goals

This ADR does not promise perfect detection of LLM use, identify the origin of pasted code, authorize device-wide surveillance, claim 500 simultaneous executions, authorize paid infrastructure, or enable production execution.
