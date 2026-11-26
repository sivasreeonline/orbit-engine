# ADR-0013: Deterministic Verdicts and Advisory Analysis

- Status: Accepted
- Decision: The assessment engine calculates authoritative verdicts from versioned test specifications and runner evidence. Static analysis and AI feedback are separate advisory dimensions.
- Consequences: AI cannot turn Wrong Answer into Accepted or change resource measurements. Findings cite code snapshots and rule versions. Complexity estimates must include confidence/limitations.
