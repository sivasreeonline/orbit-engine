# Sky High — Docker container cleanup and crash recovery

> Status: **DESIGN / OPERATOR SAFETY NOTE — NOT AUTOMATED RECOVERY**
>
> The runner does not yet have a durable container lifecycle journal or an automated orphan reconciler. A successful normal-path removal test is not proof of crash recovery.

## Current behavior

The draft `DockerSandbox.RunCase` adapter creates a container with the label `com.skyhigh.execution-id=<ExecutionID>`. It attempts forced removal after the attached execution path and surfaces a failed removal through `CleanupSucceeded=false` and an error. A deferred best-effort removal is also attempted if control exits early.

These attempts do not cover every failure:
- The runner process can terminate after Docker creates a container and before normal cleanup completes.
- The Docker daemon can be unavailable during removal.
- A deferred retry is best-effort; its own failure cannot be treated as cleanup success.
- The current label identifies an execution, not a unique runner process or installation.
- The local acceptance journal records dispatch receipt lifecycle, not Docker container IDs or sandbox lifecycle transitions.

Consequently, the system cannot yet prove which container belongs to a particular runner instance or automatically distinguish a crashed runner's container from a live runner's container on a shared daemon.

## Mandatory safety rules

1. **No global container deletion.** Never use an unfiltered `docker rm`, `docker container prune`, or `docker rm $(docker ps -aq)` as runner recovery.
2. **No execution-ID-only janitor.** Do not automatically delete containers solely because they have a Sky High execution label or appear old.
3. **No startup cleanup.** Runner startup must not sweep Docker containers. A second live runner or overlapping restart must never have its active workload removed.
4. **Fail closed.** If cleanup cannot be confirmed, the execution result must not be reported as successful and the host must require operator investigation.
5. **Dedicated host boundary.** Until ownership and reconciliation are implemented, real qualification and any future runner execution must use a dedicated host/daemon with no unrelated workloads.
6. **Evidence preservation.** Record the full container ID, execution ID, timestamps, Docker command outcome, and cleanup outcome in the future durable lifecycle record. Do not put student source or test secrets in Docker labels or operational logs.

## Current manual recovery procedure (dedicated host only)

This procedure is for an operator investigating a disposable, dedicated runner host. It is not a substitute for automated recovery and must not be used on a shared Docker daemon.

1. Stop the runner service and prevent automatic restart.
2. Verify at the operating-system level that no runner process remains. Do not infer this only from a health endpoint or stale journal lock.
3. Confirm the host/daemon is dedicated to this Sky High runner and that no other legitimate Sky High runner is active.
4. List only containers carrying the Sky High execution label:

   ```bash
   docker ps -a --no-trunc --filter 'label=com.skyhigh.execution-id'
   ```

5. Inspect each candidate individually and retain its full ID, labels, state, creation time, and inspect output as incident evidence:

   ```bash
   docker inspect <full-container-id>
   ```

6. Only after confirming the runner is stopped and the daemon is dedicated, remove each confirmed orphan by its exact full container ID:

   ```bash
   docker rm --force <full-container-id>
   ```

7. Repeat the filtered listing and verify it returns no Sky High execution containers. Preserve before/after output and Docker daemon logs.
8. Investigate why cleanup failed before restarting the runner. Do not remove the acceptance-journal lock until its separate ownership recovery procedure has been followed.

If any step cannot be established, stop and escalate; do not guess which container is safe to remove.

## Required engineering design before automated reconciliation

The implementation must be reviewed as a separate safety change and should include:

- A cryptographically random, installation-specific runner instance ID, generated/provisioned outside student-controlled input.
- Docker labels for both the runner instance and execution ID. Labels are identifiers, not authorization by themselves.
- A durable, append-only sandbox lifecycle journal with fsync semantics and bounded record validation. It must record intent before create, then the returned full container ID immediately after create, and terminal cleanup confirmation.
- Explicit handling for the crash window between Docker create and persisting the returned container ID. Recovery must query only the exact runner-instance label and still require proof that the previous process is no longer active.
- An exclusive host-level ownership lock shared by normal execution and reconciliation. Reconciliation must fail closed if lock ownership is ambiguous.
- A manual, dry-run-first reconciliation command that reports candidates and evidence. Deletion must require explicit operator action and exact full container IDs until automated ownership proof has been independently reviewed.
- Tests for daemon unavailable before create, daemon lost after create, process crash at each lifecycle boundary, duplicate runner startup, stale lock, cleanup failure, malformed journal records, and unrelated containers remaining untouched.
- Real Linux/runsc failure-injection evidence and independent security review before any automatic cleanup path is enabled.

## Release gate

Until the lifecycle journal, runner-instance ownership, crash-window handling, and tested reconciliation exist, orphan cleanup remains an explicit sandbox qualification blocker. A green CI run or successful normal-path `docker rm --force` is not sufficient. Student execution remains disabled.
