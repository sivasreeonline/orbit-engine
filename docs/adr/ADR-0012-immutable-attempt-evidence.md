# ADR-0012: Immutable Attempt Evidence

- Status: Accepted
- Decision: Every Run and Submit is a separate immutable attempt. Capture exact source bytes, hash, language/runtime, problem version, action, timestamps, execution identity and result.
- Consequences: Never overwrite a previous attempt. Corrections are new attempts; artifact references are immutable and verifiable.
- Privacy: define retention and deletion policy before production pilot.
