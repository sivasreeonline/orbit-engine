# M1 — Core Coding Judge

## Goal
Deliver the first usable coding judge. Develop UI, API, database, problem management and assessment flow against a mock execution adapter while M0 validates the real sandbox. Replace the mock only after M0 integration gates pass.

## Student capabilities
- Browse published console-mode problems.
- View statement, constraints, examples and supported language/runtime.
- Select Java or Python.
- Edit source in a browser editor.
- Run against explicitly public/sample tests.
- Submit against the complete server-selected suite.
- View compile output, sanitized stdout/stderr, aggregate verdict, runtime and memory.
- Review immutable Run/Submit timeline and source snapshots.

## Trainer/admin capabilities
- Create and version problems.
- Upload/manage public and hidden tests with role-based access.
- Configure limits and scoring policy within platform-approved bounds.
- Publish/unpublish problem versions.
- View submission status and sanitized evaluation evidence.

## Problem contract
M1 uses console stdin/stdout. Each test case has input bytes and expected output bytes plus comparison policy. Function-style methods, multiple files, interactive I/O and custom frameworks are deferred. Problem version and runtime image digest are pinned for repeatability.

## Run versus Submit
Run: server limits to public/sample tests and is non-authoritative practice evidence.
Submit: server chooses all required tests including hidden cases and creates official evaluation.
Both actions create immutable attempts. Client cannot choose hidden test IDs or change limits beyond policy.

## Verdicts
Accepted, Wrong Answer, Compilation Error, Runtime Error, Time Limit Exceeded, Memory Limit Exceeded, Output Limit Exceeded, Internal Error.
Infrastructure status is separately represented. Infra errors are never scored as Wrong Answer.

## M1 release criteria
- Authenticated student can execute a known Java and Python console problem.
- Public and hidden test selection is server-controlled.
- Every action creates immutable snapshot and attempt record.
- Results are deterministic for pinned runtime/problem/test versions.
- Hidden test inputs/expected outputs do not appear in browser payloads or logs.
- Status is asynchronous; duplicate requests/messages do not duplicate scoring.
- Trainer can trace an attempt and see a sanitized report.
- Core integration tests and security regression tests pass.
