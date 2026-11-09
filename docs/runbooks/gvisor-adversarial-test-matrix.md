# gVisor Adversarial Test Matrix

## Status and safety

This matrix is a test plan for M0. Every row is **NOT RUN** until a reproducible result, environment details, and retained logs are attached to the M0 evidence record. The current manual smoke workflow does not satisfy these adversarial checks.

Run only on a disposable, isolated Linux test host with no production credentials, student data, or sensitive host mounts. Use reviewed immutable test-image digests. Never run destructive resource-exhaustion tests on a shared or production host.

## Required environment record

For each run, record:

- Date/time (UTC), operator, workflow/run URL, and test case IDs.
- Host provider/class, OS image, kernel, architecture, cgroup mode/version.
- Docker or containerd version, OCI runtime version, runsc version, and configuration.
- Test image digest, script/test revision, configured policy, and observed limits.
- Exit status, bounded logs, cleanup result, and any deviations.

## Test cases

| ID | Threat / condition | Test method | Required assertion / evidence | Status |
| --- | --- | --- | --- | --- |
| NET-01 | Direct-IP egress | Attempt TCP/UDP connections to controlled external endpoints by IP from inside the sandbox | No connection succeeds; host-side capture confirms no unexpected egress | NOT RUN |
| NET-02 | DNS and hostname egress | Attempt DNS resolution and HTTP(S) access to controlled hostnames | No external resolution or connection succeeds; distinguish local resolver behavior from actual egress | NOT RUN |
| PID-01 | PID exhaustion / fork storm | Launch bounded process-tree pressure under the configured PID cap | Process creation is constrained; host remains responsive; sandbox is terminated and cleaned | NOT RUN |
| CPU-01 | CPU saturation | Run a CPU-bound loop beyond the configured wall-clock budget | Workload is terminated within the documented tolerance; host scheduling remains healthy | NOT RUN |
| MEM-01 | Memory exhaustion | Allocate memory beyond the sandbox memory budget | Sandbox is contained; host and neighboring workloads remain healthy; OOM status is classified correctly | NOT RUN |
| TIME-01 | Wall-clock timeout | Run a process that ignores ordinary termination and exceeds its deadline | Deadline enforcement terminates the complete process tree within the documented tolerance | NOT RUN |
| OUT-01 | stdout flood | Write output continuously beyond the configured byte cap | Captured output never exceeds the cap; execution stops or truncates according to the documented policy | NOT RUN |
| OUT-02 | stderr flood | Write errors continuously beyond the configured byte cap | Captured output never exceeds the cap; no unbounded memory growth occurs | NOT RUN |
| FS-01 | Read-only root filesystem | Attempt file creation and modification outside writable scratch | Writes fail; no host path is writable | PARTIAL: smoke harness checks one root write only |
| FS-02 | Scratch size exhaustion | Fill writable scratch past its configured byte limit | Writes fail at the enforced limit; host storage remains unaffected | NOT RUN |
| FS-03 | Scratch inode exhaustion | Create files until the configured inode limit is reached | Creation is constrained; host remains healthy | NOT RUN |
| FS-04 | Path traversal and symlink escape | Exercise parent traversal, absolute paths, symlink chains, procfs and mount-boundary paths against the sandbox filesystem | No read/write escapes the sandbox or exposes host files/sockets | NOT RUN |
| HOST-01 | Host socket and device access | Probe Docker/container runtime sockets, host devices, proc/sys and unexpected mounts | No privileged socket, device, or sensitive host mount is accessible | NOT RUN |
| CAP-01 | Privilege escalation surface | Inspect effective UID/GID, capabilities, no-new-privileges and permitted syscalls; attempt prohibited privilege transitions | Non-root identity and policy hold; no privilege transition succeeds | PARTIAL: smoke harness inspects UID and configured cap/security flags |
| CLEAN-01 | Normal completion cleanup | Run a short successful workload and inspect runtime/container state | Container, processes, mounts and scratch artifacts are removed | NOT RUN |
| CLEAN-02 | Timeout cleanup | Force wall-clock timeout and inspect host state | All descendants and resources are removed | NOT RUN |
| CLEAN-03 | Cancellation cleanup | Cancel through the intended control path during active work | Cancellation reaches the workload; all descendants and resources are removed | NOT RUN |
| CLEAN-04 | OOM cleanup | Trigger contained memory exhaustion and inspect host state | Sandbox is removed and host remains healthy | NOT RUN |
| CLEAN-05 | Forced termination cleanup | Kill the runner/controller while a sandbox is active, then exercise recovery cleanup | Orphaned containers/processes/mounts are detected and removed safely | NOT RUN |
| CONC-01 | Concurrent workloads | Run multiple sandboxes at policy limits simultaneously | Limits remain per-sandbox; no cross-tenant artifact, process, filesystem or output leakage | NOT RUN |

## Evidence and exit criteria

- Attach a separate result for every test case; a skipped test is not a pass.
- Preserve exact commands, immutable image digests, runtime versions, bounded logs, and host-side observations.
- Repeat critical cases on the selected dedicated production-equivalent Linux host and on every supported architecture.
- Record failures and mitigations; do not delete failed evidence.
- Security review must explicitly accept residual risk before any executor replaces UnconfiguredExecutor.

A passing smoke workflow or a green CI build does not close these M0 gates.