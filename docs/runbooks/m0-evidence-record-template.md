# M0 Execution Evidence Record Template

> Use one completed copy per test run. A checklist or planned workflow is not proof. Mark a gate **PASS** only when reproducible evidence, environment details, and reviewer sign-off are attached. Use **NOT RUN**, **PARTIAL**, or **FAIL** otherwise.

## 1. Run identity

- Evidence record ID:
- Date/time started (UTC):
- Date/time completed (UTC):
- Operator:
- Reviewer:
- Git commit / workflow run URL:
- Test case IDs covered:
- Overall disposition: NOT RUN / PARTIAL / PASS / FAIL

## 2. Host and runtime environment

- Provider / host class:
- Region / isolation boundary:
- Operating system image and version:
- Kernel version:
- Architecture:
- cgroup version and configuration:
- Container engine and version:
- OCI runtime and version:
- gVisor/runsc version:
- Runner build SHA:
- Runner configuration SHA:
- Java runtime image digest:
- Python runtime image digest:
- Test image digest:
- Image provenance / vulnerability scan references:

Do not record credentials, private keys, access tokens, or secret environment values. Record only secret names or presence/absence where relevant.

## 3. Effective sandbox policy

Record both requested and observed values. A configuration file alone is not evidence that the runtime enforced the policy.

| Control | Requested value | Observed/effective value | Evidence reference | Result |
| --- | --- | --- | --- | --- |
| Non-root UID/GID | | | | NOT RUN |
| Read-only root filesystem | | | | NOT RUN |
| Writable scratch bytes | | | | NOT RUN |
| Writable scratch inodes | | | | NOT RUN |
| CPU quota | | | | NOT RUN |
| Memory limit | | | | NOT RUN |
| PID limit | | | | NOT RUN |
| Wall-clock deadline | | | | NOT RUN |
| stdout byte cap | | | | NOT RUN |
| stderr byte cap | | | | NOT RUN |
| Network disabled | | | | NOT RUN |
| Capabilities dropped | | | | NOT RUN |
| no-new-privileges | | | | NOT RUN |
| Host mounts / sockets absent | | | | NOT RUN |

## 4. Test execution evidence

For each case, record the exact test program/image, command, expected behavior, observed behavior, exit status, bounded logs, and cleanup result. Reference immutable artifacts rather than pasting unbounded output.

| Test case | Expected assertion | Evidence link / artifact hash | Result | Reviewer |
| --- | --- | --- | --- | --- |
| Known-good Java fixture | Correct output and exit status | | NOT RUN | |
| Known-good Python fixture | Correct output and exit status | | NOT RUN | |
| Java compilation failure | Correct compile classification; bounded sanitized output | | NOT RUN | |
| Runtime exception | Correct runtime classification | | NOT RUN | |
| CPU saturation | Enforced quota and deadline; host remains healthy | | NOT RUN | |
| Memory exhaustion | Contained OOM; host remains healthy | | NOT RUN | |
| PID exhaustion | Process cap enforced; no host impact | | NOT RUN | |
| Wall-clock timeout | Full process tree terminated within tolerance | | NOT RUN | |
| stdout flood | Capture remains within byte cap | | NOT RUN | |
| stderr flood | Capture remains within byte cap | | NOT RUN | |
| Scratch byte exhaustion | Writes stop at configured limit | | NOT RUN | |
| Scratch inode exhaustion | File creation stops at configured limit | | NOT RUN | |
| Filesystem traversal | No host path or mount escape | | NOT RUN | |
| Host socket/device probe | No privileged socket or device access | | NOT RUN | |
| Direct-IP egress | No external connection succeeds | | NOT RUN | |
| DNS/hostname egress | No external resolution/connection succeeds | | NOT RUN | |
| Cancellation | Cancellation reaches all descendants; cleanup completes | | NOT RUN | |
| Duplicate delivery | One logical execution/result | | NOT RUN | |
| Runner restart / forced termination | Orphans detected and safely reconciled | | NOT RUN | |
| Concurrency pressure | Limits hold across concurrent jobs; host remains healthy | | NOT RUN | |

## 5. Cleanup and recovery

- Container/process cleanup evidence:
- Mount and scratch cleanup evidence:
- Orphan detection/reconciliation evidence:
- Cleanup behavior after success:
- Cleanup behavior after compile/runtime failure:
- Cleanup behavior after timeout:
- Cleanup behavior after cancellation:
- Cleanup behavior after OOM:
- Cleanup behavior after runner/controller termination:
- Any residual resources or unresolved incidents:

Any unknown or failed cleanup result blocks a clean M0 pass and requires investigation.

## 6. Security and operational review

- Threat model reviewed (reviewer/date):
- Host isolation boundary reviewed:
- Runtime image provenance reviewed:
- Network-denial evidence reviewed:
- Resource-limit evidence reviewed:
- Secret and hidden-test disclosure review:
- Log redaction review:
- Incident/quarantine procedure tested:
- Rollback and host drain procedure tested:
- Open findings and owners:

## 7. Gate decision

| Gate | Evidence references | Status | Reviewer |
| --- | --- | --- | --- |
| Supported Linux host and architecture | | NOT RUN | |
| Runtime compatibility and pinned images | | NOT RUN | |
| Non-root / no host access | | NOT RUN | |
| Network denial | | NOT RUN | |
| CPU, memory, PID and wall-time enforcement | | NOT RUN | |
| Filesystem and output enforcement | | NOT RUN | |
| Cancellation and complete cleanup | | NOT RUN | |
| Idempotency and restart recovery | | NOT RUN | |
| Structured, sanitized results and logs | | NOT RUN | |
| Security review and operational runbook | | NOT RUN | |

**Final decision:** NOT RUN / PARTIAL / PASS / FAIL

**Approvers:**
- Engineering:
- Security:
- Operations:

A PASS permits only the next explicitly approved integration stage. It is not automatic production approval. Keep `UnconfiguredExecutor` fail-closed until all required M0 gates are reviewed and accepted.
