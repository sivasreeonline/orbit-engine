# Sky High — Docker container cleanup and crash recovery

> Status: **DESIGN / OPERATOR SAFETY NOTE — NOT AUTOMATED RECOVERY**
>
> A durable append-only lifecycle journal is now implemented and wired into the draft Docker sandbox adapter. An automated orphan reconciler is **not** implemented. Journal recovery is not proof that an orphan container can be safely deleted.

## Current behavior

The execution-capable `NewJournaledDockerSandbox` constructor requires a durable `sandboxjournal.Journal` and a stable 32-character lowercase-hex runner instance ID. `RunCase` fails closed when the journal is absent. Before Docker create, it fsyncs a `CREATE_INTENT` event and supplies Docker labels for the execution ID, runner instance ID, and unique lifecycle ID. Immediately after Docker returns a full container ID, it fsyncs a `CREATED` event. After Docker removal succeeds, it fsyncs a `CLEANED` event. The journal stores identifiers and timestamps only; it never stores source code, stdin, outputs, or test fixtures.

The journal is versioned append-only JSONL with a 64 MiB total limit, a 1 MiB record limit, strict transition validation, owner-only file permissions, an exclusive process lock, and fsync on every event. On restart it truncates only an incomplete final line; malformed complete records and invalid transitions fail closed. A stale lock is never removed automatically.

These attempts do not cover every failure:
- The runner process can terminate after Docker creates a container and before normal cleanup completes.
- The Docker daemon can be unavailable during removal.
- A deferred retry is best-effort; its own failure cannot be treated as cleanup success.
- The runner instance ID is now a required, validated `RUNNER_INSTANCE_ID` in foreground runner configuration. It must be generated once with a cryptographically secure random generator and persisted in a protected service environment file across restarts. The foreground process opens a separate sandbox lifecycle journal, holds its exclusive lock, and constructs the journaled Docker adapter with this ID. The adapter is not passed to the worker, which still uses the unconfigured executor; student execution remains disabled.
- A read-only discovery library now performs one Docker inventory query filtered by the exact runner-instance label, then inspects full container IDs in bounded batches of at most 32 per Docker CLI process. Every returned object must match exactly one requested full ID and carry both runner-instance and lifecycle labels; omitted, duplicate, unexpected or malformed inspect records fail closed. It then correlates the complete inventory with pending journal records in memory. It reports mismatches/ambiguity and fails closed if a runner-owned container has no corresponding pending journal lifecycle. A separate `cmd/sandbox-recovery` CLI now performs the same read-only discovery and emits a versioned JSON report. It first acquires the same persistent Linux `flock` host-ownership lock as the foreground runner, then opens the existing journal in strict read-only mode while acquiring that journal's exclusive lock. It refuses to run while another Sky High process holds the configured host lock or while the foreground runner owns that exact journal. It does not create a missing journal, repair/truncate an incomplete tail, mutate journal records, or modify containers. An incomplete final record is a hard stop for operator review. A stale journal `.lock` left by a crashed process must be preserved and investigated; an operator may remove only that exact journal lock after independently verifying no process can own the journal. The CLI never steals stale journal locks. The separate host lock file is persistent and must never be removed or replaced; the kernel releases its flock when a process exits. The kernel host lock is now implemented and shared by foreground startup and the recovery CLI through `RUNNER_HOST_LOCK_PATH`. Every runner installation on the host must be provisioned with the exact same canonical path; different paths do not coordinate. The lock file persists across restarts and must never be deleted or replaced. There is still no container deletion path.
- The local acceptance journal records dispatch receipt lifecycle, not Docker container IDs or sandbox lifecycle transitions. The foreground process now separately opens the sandbox lifecycle journal and binds the stable runner ID to a journaled adapter, but does not make that adapter available to dispatch execution.

The exact runner-instance and lifecycle labels now let the read-only recovery path correlate a discovered container with a pending journal lifecycle. This is stronger than execution-ID-only matching, but labels remain metadata rather than cryptographic authorization: the recovery path independently inspects the full container ID and verifies both labels, while the journal confirms the expected runner and lifecycle. Findings remain operator-review-only. The system still cannot safely infer that a candidate is deletable merely because the labels match, nor can it distinguish every unrelated actor or out-of-band daemon change on a shared host. Keep qualification and any future execution on a dedicated host/daemon until the full host-level failure-injection and independent security review gates pass.

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
4. List only containers carrying Sky High execution labels. When a runner instance ID is known, narrow the listing to that exact instance:

   ```bash
   docker ps -a --no-trunc --filter 'label=com.skyhigh.runner-instance=<RUNNER_INSTANCE_ID>' --filter 'label=com.skyhigh.execution-id'
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
8. Investigate why cleanup failed before restarting the runner. Do not remove the acceptance-journal lock until its separate ownership recovery procedure has been followed. For the sandbox lifecycle journal, remove its exact sibling `.lock` file only after verifying that no process can still own that journal path; never remove it while a runner may be active.

If any step cannot be established, stop and escalate; do not guess which container is safe to remove.

## Required engineering design before automated reconciliation

The implementation must be reviewed as a separate safety change and should include:

- A cryptographically random, installation-specific runner instance ID, generated/provisioned outside student-controlled input.
- Docker labels for both the runner instance and execution ID. Labels are identifiers, not authorization by themselves.
- Complete the handoff of the configured stable runner-instance ID into the future journaled Docker executor, then document and test identity rotation/replacement behavior. The sandbox journal and Docker labels already support this identity.
- Retain the dry-run CLI JSON report as incident evidence. It queries once by the exact runner-instance label, inspects each full ID to verify both labels, and correlates candidates with pending records; findings are never deletion authorization.
- An operator-invoked, dry-run-first reconciler that lists exact owned candidates, requires proof that the previous process is stopped, and refuses ambiguous ownership. No automatic startup janitor.
- Provision and enforce one canonical `RUNNER_HOST_LOCK_PATH` across all runner installations on the host. The Linux kernel lock is shared by foreground and recovery, while the separate journal lock protects the exact journal file. Reconciliation must fail closed if either lock cannot be acquired.
- The dry-run CLI and library report candidates and evidence but do not remove containers. A future reconciliation/deletion command must require explicit operator action and exact full container IDs until automated ownership proof has been independently reviewed.
- Tests for daemon unavailable before create, daemon lost after create, process crash at each lifecycle boundary, duplicate runner startup, stale lock, cleanup failure, malformed journal records, and unrelated containers remaining untouched.
- Real Linux/runsc failure-injection evidence and independent security review before any automatic cleanup path is enabled.

## Release gate

Until operator reconciliation, crash-window failure injection, and independent security review exist, orphan cleanup remains an explicit sandbox qualification blocker. A green CI run or successful normal-path `docker rm --force` is not sufficient. Student execution remains disabled.
