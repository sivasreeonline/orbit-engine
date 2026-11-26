# ADR-0008: gVisor and OCI Sandbox Candidate

- Status: Conditional
- Decision: Evaluate gVisor runsc as the first isolation candidate behind an OCI-compatible runtime.
- Context: Student programs are hostile, untrusted workloads.
- M0 gates: prove no network access, non-root execution, CPU/memory/PID/wall-clock/output limits, ephemeral filesystem, cleanup, host protection and acceptable performance.
- Consequence: gVisor is defense in depth, not a blanket security guarantee. Production approval requires evidence and a threat review.
