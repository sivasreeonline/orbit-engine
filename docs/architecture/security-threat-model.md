# Security Threat Model

## Threat assumption
Any submitted source code, compiler output, stdout, stderr, custom input and AI response may be malicious. Student code must never execute within Workers, Durable Objects, the API process or shared application containers.

## Controls required for M0
- Dedicated Linux execution host; non-root runner and non-root sandbox user.
- Ephemeral container/sandbox per job; no shared writable workspace across jobs.
- gVisor/runsc evaluation with pinned runtime versions.
- No network namespace egress by default; verify DNS, loopback and metadata-service denial.
- CPU quota, memory limit, PID limit, wall-clock deadline, file-size and output-byte limits.
- Read-only base filesystem; bounded temporary writable area.
- Drop Linux capabilities; no privileged mode; no host socket or host path mounts.
- Seccomp and mandatory access controls where available.
- Kill process tree on timeout/cancel; guarantee cleanup.
- Runner host and control endpoints private; authenticated runner identity.
- No cloud credentials, database credentials or secrets inside sandbox.
- Hidden tests selected and stored server-side; never returned to browser or included in student logs.

## Threats and expected response
- Infinite loop: wall-clock timeout and process-group termination.
- Memory exhaustion: cgroup/container memory limit; classify MLE.
- Fork bomb: PID limit; kill sandbox; classify resource violation.
- Filesystem inspection: isolated filesystem and no host mounts.
- Network exfiltration: default-deny network and metadata denial.
- Output flooding: capped stdout/stderr; classify OLE.
- Container escape: gVisor defense in depth, patched host, least privilege, monitoring; incident response.
- Queue replay: idempotency and state checks.
- Hidden-test leakage: separate storage, sanitized result schema, access audit.
- Secret leakage: scrub logs and environment; scoped credentials only outside sandbox.

## Production gate
M0 passing tests do not equal independent security certification. Require threat review, host patch process, monitoring, incident procedure and external security review proportionate to deployment risk before real high-stakes assessments.
