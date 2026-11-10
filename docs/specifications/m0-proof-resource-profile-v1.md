# M0 Proof Resource Profile v1

- Profile ID: `m0-proof-small-v1`
- Revision: `1`
- Status: Proposed disposable-host proof profile; pending independent security review and empirical runtime validation.
- Scope: Synthetic M0 proof fixtures only. This is not a production student-execution profile.
- Protocol alignment: `ResourceLimitsV2`; the protocol's `outputBytes` is the combined stdout + stderr ceiling.

## 1. Per-sandbox limits

| Resource | Initial value | Enforcement contract |
|---|---:|---|
| CPU quota | 1,000 millicores (1 vCPU) | cgroup v2 CPU quota; host-side throttling counters must prove enforcement |
| Memory | 1 GiB (1,073,741,824 bytes) | cgroup v2 hard memory ceiling; OOM is an infrastructure/resource outcome |
| Process count | 128 | cgroup v2 PID ceiling; host-side `pids.current` / `pids.events` prove enforcement |
| Sandbox wall time | 60,000 ms | Host watchdog terminates the complete process tree and verifies cleanup |
| End-to-end request budget | 10 minutes maximum | Includes queue wait; deadline originates from persisted API intake time |
| Combined output | 1 MiB (1,048,576 bytes) | One shared hard ceiling across stdout and stderr, matching protocol `outputBytes` |
| Per-stream observation | stdout 1 MiB; stderr 1 MiB | Independent byte counters; each stream is separately testable, but both share the combined 1 MiB storage ceiling |
| Scratch bytes | 256 MiB (268,435,456 bytes) | Hard per-attempt scratch quota; never a host bind mount |
| Scratch inodes | 4,096 | Hard per-attempt inode quota |

The protocol hard ceilings remain 512 MiB scratch and 8,192 scratch inodes. The proof profile uses the lower defaults. No caller or workload may raise these values.

## 2. Output-limit behavior

1. Count stdout and stderr independently at the host-side collector, before writing to evidence storage.
2. Enforce a shared combined ceiling of 1,048,576 bytes. The per-stream counters each have the same 1,048,576-byte ceiling for independent accounting and fixture coverage.
3. On the first per-stream or combined ceiling breach, mark output overflow and request termination of the complete sandbox process tree.
4. Retain no more than the first 1 MiB combined across both streams. Do not buffer unbounded output in memory, temporary files, logs, or telemetry.
5. Continue draining/discarding pipe data with fixed-size buffers while termination and reaping complete; never block the supervisor because one pipe is full.
6. Classify the result as Output Limit Exceeded only after the host collector confirms the breach. A collector failure or uncertain process cleanup is an infrastructure failure, never a student verdict.
7. Record per-stream observed byte counts, combined stored byte count, overflow flag, termination reason, and hashes of retained sanitized evidence. Never store hidden tests or expected outputs in guest-visible output artifacts.

## 3. Safety and validation constraints

- This profile is only a candidate for a disposable, single-tenant M0 proof VM.
- The disposable VM must have independently verified outer CPU, memory, PID, disk, and watchdog controls before any stress fixture.
- Do not infer outer VM capacity from the per-sandbox limits. Provider, region, VM size, and spend remain undecided.
- Verify Java 25 compilation/runtime and Python 3.14 behavior under this profile. If legitimate runtime startup or compilation requires more resources, stop and propose a versioned profile change; do not silently raise limits.
- Validate actual cgroup enforcement, runtime platform, network denial, output capture, process cleanup, and repeated failure behavior with host-side evidence.
- A profile document, schema-valid manifest, or passing synthetic validator is not runtime proof.
- Independent security review must approve the final profile and the host's outer safety envelope before M0 workloads are launched.

## 4. Change control

Any change to CPU, memory, PID, wall-time, output, scratch, or inode limits requires:
- A new profile revision and documented rationale.
- Updated protocol/schema/fixture/runbook references where applicable.
- Regression tests for both the new ceiling and the previous boundary.
- Independent review of any change that increases resource exposure.

