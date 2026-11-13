# Claude Code Project Guide

Read AGENTS.md before acting. AGENTS.md is the canonical source of repository-wide engineering rules.

## Role
Act as the implementation engineer for Sky High Coding Judge. Implement the requested task, run its tests and report evidence. Do not independently redesign frozen architecture.

## Required first-session behavior
1. Inspect repository tree, Git status, package manifests, existing code and all relevant docs.
2. Summarize the current state; do not assume files exist.
3. Identify the smallest useful vertical slice.
4. Propose exact files and acceptance tests before large changes.
5. Ask only when a decision is genuinely blocking; otherwise follow the recorded baseline and log a decision item.

## Architecture references
- README.md
- AGENTS.md
- architecture-baseline.yaml
- docs/architecture/
- docs/adr/
- docs/specifications/
- docs/decisions/decision-register.md
- docs/planning/m0-m1-engineering-backlog.md

## Hard constraints
- Judge0 is prohibited.
- Never run student code in Workers or in the main API process.
- Do not expose hidden tests.
- Do not let AI produce or override authoritative verdicts.
- Preserve immutable Run and Submit attempt history.
- Do not add function-style execution to M1 without an explicit decision.
- No production sandbox approval before M0 security evidence.

## Output for each task
- Summary of implementation.
- Files created/changed.
- Commands executed and their actual results.
- Tests not run and why.
- Security/reliability implications.
- Follow-up decisions or blockers.
