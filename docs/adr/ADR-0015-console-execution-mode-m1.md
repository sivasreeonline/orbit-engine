# ADR-0015: Console Execution Mode for M1

- Status: Accepted for initial M1 slice
- Decision: Initial problems use stdin/stdout with versioned input and expected output test cases.
- Context: This enables a robust, transparent first judge without brittle parsing or source rewriting.
- Consequences: Function-signature adapters (such as LeetCode-style class/method harnesses), multi-file tasks and interactive problems are deferred.
- Revisit: inspect the pilot problem bank and trainer requirements before M1 pilot release.
