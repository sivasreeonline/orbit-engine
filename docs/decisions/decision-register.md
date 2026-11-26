# Open Engineering Decision Register

Resolve decisions with evidence. These items must not block unrelated mock-backed M1 work.

| ID | Decision | Needed by | Proposed approach |
|---|---|---|---|
| D-001 | Linux host provider and CPU architecture | M0 | Select after gVisor support and cost review |
| D-002 | OCI engine: containerd or Docker Engine | M0 | Benchmark both; prefer minimal production daemon surface |
| D-003 | gVisor kernel/runtime compatibility | M0 | Prove on selected host and runtime images |
| D-004 | Neon connectivity from runner | M0 integration | Private/authenticated service access; avoid exposing DB to sandbox |
| D-005 | Queue pull-consumer authentication | M0 integration | Dedicated service identity and rotated credentials |
| D-006 | Queue retry and dead-letter thresholds | M0 | Set from failure-injection evidence |
| D-007 | Durable Object live status requirement | M1 | Start with polling; add DO only if justified |
| D-008 | Problem function-style support | Pilot | Console mode first; inspect real question bank |
| D-009 | Exact Java 25 patch/image | M0 | Pin maintained patch and digest |
| D-010 | Exact Python 3.14 patch/image | M0 | Pin maintained patch and digest |
| D-011 | Runner host architecture: ARM64 vs x64 | M0 | Choose based on gVisor and language image compatibility |
| D-012 | Source snapshot threshold for R2 | M1 | PostgreSQL for small source; benchmark large artifacts |
| D-013 | Code editor choice | M1 UI | Evaluate Monaco and CodeMirror with license/performance review |
| D-014 | Comparator defaults and normalization | M1 | Exact output first; explicit per-problem policy |
| D-015 | Hidden-test result granularity | M1 | Aggregate only; no case input/expected output |
| D-016 | Concurrency and throughput targets | Pilot | Derive from actual cohort size and load test |
| D-017 | Student source/log retention | Pilot | Define privacy, consent and deletion policy |
| D-018 | Multi-tenancy schema strategy | M1 | Reuse Sky High tenant/college model |
| D-019 | Authentication integration | M1 | Reuse existing Sky High identity provider/contracts |
| D-020 | Live result delivery | M1 | Polling first; evaluate SSE later |
| D-021 | AI provider and data minimization | Later | Advisory only; no source upload without policy |
| D-022 | Code analysis tools and licenses | M1.1 | Evaluate language-specific analyzers |
| D-023 | Runner autoscaling and drain protocol | Pilot | Start bounded single region; measure |
| D-024 | Backup and restore RPO/RTO | Pilot | Define after deployment topology selection |
| D-025 | Abuse controls and assessment quotas | M1 | Server-side per-student/per-assessment limits |
| D-026 | Independent security review | Production | Required before high-stakes use |

Decision updates must record owner, evidence, decision date, consequences and affected ADR/specification.
