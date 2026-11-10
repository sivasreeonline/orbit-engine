# M0 Host Preflight and Proof Runbook

## Purpose

The host preflight script checks whether a disposable Linux host matches the selected M0 baseline before any sandbox experiments begin.

It is deliberately read-only. It does not install packages, change host configuration, start or stop services, launch containers, pull images, execute student programs, or claim that gVisor isolation works.

## Selected proof baseline

- Ubuntu Server 24.04 LTS, x86_64.
- Linux kernel 5.6 or newer; record the exact kernel build.
- Unified cgroup v2.
- containerd 2.3 LTS with configuration version 3.
- gVisor runsc and containerd-shim-runsc-v1.
- gVisor runtime handler io.containerd.runsc.v1.
- VM-backed proof hosts explicitly use the gVisor systrap platform.
- Proposed M0 proof resource profile: `docs/specifications/m0-proof-resource-profile-v1.md`; values remain pending empirical validation and independent approval.
- Dedicated disposable host; no student data, production credentials, API services, or unrelated tenants.

The cloud provider and region are intentionally not selected in this runbook.

## Phase 0 — Host preflight

Run as an ordinary account with permission to inspect the containerd socket:

```bash
bash services/execution-runner/scripts/m0-host-preflight.sh
```

The script checks OS release, architecture, kernel minimum, cgroup v2, containerd LTS version, the locally resolved configuration dump, gVisor binaries, and containerd socket ownership/permissions. The configuration check is a preliminary local-file inspection; it does not prove that the running daemon loaded that exact configuration or that the configured handler is operational.

A successful result means only that the host matches these baseline checks. It does not prove that runsc starts, that systrap is active, that network access is blocked, or that resource limits are enforced.

Do not weaken a failed check to make the script pass. Investigate and record the host deviation; update the ADR before changing the baseline.

## Phase A — Cleanup deadline calibration (separate authorization)

Phase A is a narrow synthetic-only measurement campaign. It exists to derive a candidate cleanup deadline; it is not the full 35-fixture M0 proof and does not authorize a student execution path.

### Authorization preconditions

Do not start Phase A until every item below is recorded and independently checked:

- The read-only host preflight passes, and the exact host/runtime/configuration inventory is preserved.
- The VM is dedicated and disposable. It contains no student data, production credentials, API secrets, unrelated tenants, or valuable host state.
- An outer VM safety boundary independently enforces CPU, memory, PID, disk, and wall-time ceilings. Its stop/rebuild control is outside the supervisor, journal, and containerd failure domain being measured. The approved finite safety cutoff is recorded before the run.
- Default-deny network containment is enforced outside the sandbox and verified with host-side counters or equivalent independent evidence before the first workload. The metadata link-local destination is denied before host uplink; no metadata request is sent from the host.
- The candidate journal configuration has passed its separately required exact-host durability, crash, power-loss, disk-full, corruption, and restore gates. Phase A does not waive the journal backend proof gate below.
- A fixed calibration image and scenario bundle have been source-reviewed, digest-pinned, and checked to contain no network callbacks, host-destructive operation, credential access, or student/hidden-test material.
- The supervisor, journal, watchdog, evidence collector, and runtime versions/builds are frozen and recorded. The calibration must exercise the same cleanup controller and durable state path intended for M0; mocks do not produce qualifying timing evidence.
- An independent reviewer and host owner authorize an immutable calibration manifest naming exact digests, profile revisions, allowed CAL-CLEAN scenario IDs, finite run count, external safety cutoff, evidence destination, expiry, and emergency stop authority.
- The calibration control path is host-local and restricted to the allowlisted scenario IDs. It is not exposed through the student API, general execution endpoint, public HTTP route, or ordinary job queue. No arbitrary command or source field is accepted.

An external safety cutoff is only an experiment-containment mechanism. If it fires, power off or isolate the disposable VM, mark the sample and campaign failed, and quarantine the host. Never record the outer cutoff as successful sandbox cleanup or adopt its duration as the cleanup deadline.

### Phase A execution order

1. Complete the runtime and containment smoke checks in Phase A.1 below.
2. Confirm the independent outer resource and network controls remain active immediately before each campaign.
3. Run only the fixed synthetic CAL-CLEAN scenarios listed in the cleanup qualification section. Do not run the full 35-fixture contract during Phase A.
4. Capture the original termination trigger timestamp and boot identity before or at the termination request; continue measuring until independent resource-absence verification and durable cleanup disposition.
5. Inject journal and evidence-store failures independently. Verify that the termination/cleanup branch progresses without waiting for either subsystem.
6. Stop and quarantine on any uncertain cleanup, unowned resource, clock ambiguity, failed outer control, forbidden network flow, evidence leak, or unexplained host mutation.
7. Preserve raw measurements and sanitized evidence, then obtain independent review before proposing a numeric deadline.

## Phase A.1 — Runtime compatibility and containment smoke checks

These checks are limited prerequisites for the calibration campaign. They are not the full M0 fixture suite. They may run only after the Phase A authorization preconditions above are approved.

On a disposable host only:

1. Record Ubuntu image identifier, kernel build, architecture, containerd package version and provenance, runsc version and provenance, shim version, and containerd config version.
2. Identify the actual running containerd daemon: record its systemd unit state, effective ExecStart arguments, process command line, and the configuration file path selected by those arguments. Resolve and record imported configuration files; do not assume that a standalone `containerd config dump` necessarily represents the daemon's effective configuration.
   - Treat systemd unit definitions, ExecStart arguments, process command lines, and imported configuration as potentially sensitive. Capture only the allowlisted fields needed to establish the daemon binary and configuration paths; redact tokens, credentials, URL user-info, environment values, and unrelated arguments before storing evidence. Never archive raw `/proc/<pid>/cmdline` or environment output.
3. Confirm from the effective daemon configuration that the runtime handler resolves to the expected runsc binary and shim. Record binary paths, ownership, permissions, package provenance, and cryptographic hashes.
4. Launch only a reviewed, digest-pinned, minimal test image through the gVisor handler.
5. Capture the runtime-reported platform and independently verify that systrap is selected.
6. Repeat after a host reboot and after a clean service restart.
7. Record cold-start and warm-start timings; do not extrapolate throughput from a single smoke test.

No student source, hidden tests, application secrets, or production data may be used.

## Phase B.1 — Full M0 isolation and resource proof (blocked pending Phase A approval)

Only after Phase A measurements, the numeric cleanup deadline, evidence/finalization reserve, clock semantics, watchdog design, and new resource-profile revision have independent approval may the full reviewed 35-fixture matrix in `docs/specifications/m0-adversarial-fixture-contract.md` run inside a disposable gVisor sandbox. The suite must be digest-pinned, source-reviewed, and contain no network callbacks or destructive host operations. Do not implement or execute fixture payloads until the disposable VM outer cgroup, watchdog, network containment, and recovery controls have been independently verified. In particular, before `M0-NET-006`, install and independently verify an outer-VM deny/blackhole rule for the metadata link-local destination (for example, IPv4 `169.254.169.254`); prove with host-side counters/packet observation that packets are dropped before any host uplink or metadata service can receive them. The probe originates only inside the sandbox. Never issue metadata requests from the host, never accept or store metadata responses, and mark the fixture blocked rather than running it if the outer deny cannot be proven.

| Area | Required evidence |
|---|---|
| Identity | Effective UID/GID is non-root; capabilities are dropped |
| Host boundary | No host paths, devices, namespaces, privileged socket, or credentials visible |
| Network | IPv4, IPv6, DNS, direct-IP, and loopback-to-host attempts fail. The metadata-address probe runs only from inside the sandbox after an independently verified outer-VM deny/blackhole rule drops the link-local destination before host uplink; host-side counters prove the drop and no metadata service is contacted |
| CPU | CPU quota is enforced under sustained load |
| Memory | cgroup memory ceiling is enforced; OOM is classified as infrastructure/resource outcome, not Accepted |
| Processes | PID ceiling stops fork/process floods |
| Time | Wall deadline stops infinite loops and reaps descendants |
| Filesystem | Base is read-only; scratch byte and inode ceilings are hard limits |
| Output | stdout/stderr are drained concurrently with fixed-size buffers; byte counters are updated before retention; a shared 1 MiB combined hard ceiling is enforced atomically; overflow triggers immediate complete-sandbox termination while readers drain/discard without blocking on storage |
| Cleanup | After success, compile failure, runtime failure, timeout, cancellation, OOM, output overflow, and forced termination, independently verify absence of the process tree, containerd task/container, shim, namespaces, cgroup, scratch, temporary mounts, and network-policy state before terminal acknowledgement |

A test passes only with captured host-side evidence and an assertion that checks the expected failure mode. A command returning non-zero by itself is not sufficient proof.

## Phase B.2 — Full M0 cancellation, recovery, and repeatability proof

- Cancel while the workload is running; verify the complete process tree is terminated.
- Race cancellation against natural exit, the 10-minute intake-based deadline, the 60-second sandbox watchdog, and output overflow. Verify one durable arbitration winner, immutable primary cause, retained secondary trigger records, and one terminal result.
- Have a workload exceed an output ceiling and exit before the pipe reader drains buffered bytes. Verify natural exit remains provisional until both streams reach EOF and final counters are reconciled; a late-discovered output breach must block success.
- Repeat cancellation and watchdog signals; verify idempotent termination/cleanup with no duplicate task or terminal transition. A late cancellation after finalization must not rewrite the result.
- Restart the watchdog/supervisor during active execution and termination; verify the original persisted deadline is re-armed without granting a fresh budget.
- Confirm cleanup before acknowledging cancellation.
- Deliver the same test job twice; verify one logical execution and one result.
- In separate controlled subcases, restart the runner, host supervisor, privileged supervisor process, and containerd daemon during active operations; inject crashes after durable intent, after create/start side effects but before observed-result commit, after journal commit but before client response, after branch disposition but before terminal CAS, and after terminal commit but before acknowledgement.
- Retry lost responses with the same idempotency key and canonical digest; prove the same operation/response is returned without repeating side effects. Change the digest under the same key and reuse a logical attempt under a different key; both must be rejected without resource creation.
- Pause an old supervisor while attempting replacement startup; prove the exclusive kernel lock prevents concurrent privileged containerd access and stale generations fail closed.
- Verify journal corruption, disk-full, uncertain commit, and partial resource state all stop new work and quarantine the host rather than guessing.
- Verify journal reconciliation, no duplicate execution, and absence of every process/task/container/shim/namespace/cgroup/mount/scratch/network-policy resource before terminal acknowledgement.
- Repeat each failure-path test enough times to expose races.
- Preserve correlation IDs and timestamps without logging student source, hidden inputs, expected outputs, or secrets.

## Phase A measurement evidence and Phase B release gate

The numeric cleanup deadline remains intentionally unset in resource-profile revision 1. Phase A may collect calibration measurements only after its separate authorization preconditions pass. This resolves the measurement/approval sequence without weakening the gate on the full M0 proof.

### Fixed Phase A calibration scenarios

| Scenario ID | Trigger/fault being measured | Required evidence focus |
|---|---|---|
| CAL-CLEAN-001 | Explicit cancellation | Trigger-to-termination and verified complete resource absence |
| CAL-CLEAN-002 | Sandbox wall watchdog | Original wall-deadline trigger retained through termination and cleanup |
| CAL-CLEAN-003 | Output-limit termination | Termination begins before pipe drain or evidence I/O can block it |
| CAL-CLEAN-004 | Descendants holding inherited stdout/stderr pipes | Complete cgroup/process cleanup; bounded drain/EOF handling |
| CAL-CLEAN-005 | Supervisor pause, crash, and same-boot restart | Original monotonic anchor and fencing; no fresh cleanup interval |
| CAL-CLEAN-006 | Containerd interruption/recovery | No blind retry; deterministic reconciliation and independent cleanup outcome |
| CAL-CLEAN-007 | Journal delay or SQLITE_BUSY/FULL/IOERR injection | Termination is issued immediately; journal failure does not extend the cleanup clock |
| CAL-CLEAN-008 | Evidence-store unavailable or delayed | Cleanup proceeds independently; evidence branch records incomplete disposition |
| CAL-CLEAN-009 | Repeated/late triggers and ambiguous partial resources | First trigger remains the anchor; unknown resources force quarantine |

These calibration scenario IDs are separate from the 35 approved M0 fixture IDs. Phase A evidence must use a distinct calibration report and must never be inserted into a full-proof manifest as passed fixture results.

### Measurement and report requirements

- Record the earliest host-observed termination trigger's monotonic timestamp and boot identity, plus the immediate termination-request timestamp. The cleanup clock starts at the trigger, not at a later journal commit or acknowledgement.
- Record phase timings through process-tree/cgroup empty, containerd task/container removal, shim exit, namespace/mount/scratch/network-policy cleanup, independent absence verification, and durable cleanup disposition.
- Keep cleanup and evidence collection independently supervised. A journal or evidence-store failure must not delay termination; unresolved evidence may make the report incomplete but cannot preserve a live sandbox.
- Preserve raw monotonic measurements and sanitized host evidence. Report sample count, min, median, p95, p99, maximum, phase breakdown, outliers, host envelope, exact versions/digests, fault setup, and uncertainty sources. Percentiles are descriptive only and do not establish a hard upper bound.
- Repeat relevant cases across cold/warm runtime state and bounded load. Test same-boot supervisor recovery; test host reboot only after the external recovery/watchdog boundary is independently verified.
- A sample interrupted by the external VM safety cutoff, failed clock reconstruction, missing resource inventory, or ambiguous cleanup is a failed/unverified sample. It cannot contribute as a successful maximum.
- Derive a candidate deadline only from the worst verified trigger-to-verified-cleanup result plus a separately justified engineering uncertainty margin. Do not use an arbitrary multiplier, average, or p99 as the hard deadline.
- Independently review raw evidence, watchdog independence, clock semantics, the uncertainty-margin rationale, and the proposed numeric value.

### Phase B release gate

Before Phase B, add the numeric cleanup deadline and the independently measured/bounded evidence-and-terminal-finalization reserve together to a new reviewed resource-profile revision. Record the exact clock/reboot semantics, watchdog mechanism, host envelope, journal profile, and admission behavior in that revision.

Admission must reserve the maximum 60-second sandbox wall interval, the approved cleanup deadline, and the evidence/terminal-finalization reserve from the same original 10-minute API-intake budget. If the remaining budget is insufficient, reject before sandbox creation. Queueing, retries, recovery, cleanup, evidence publication, and terminal commit never reset the original budget.

**Phase B remains blocked** until the independent reviewer approves the Phase A measurements and profile revision. Only then may the full 35-fixture adversarial suite and its runner/supervisor/containerd restart, network, quota, journal, cleanup, and evidence-integrity cases run. Phase A does not itself authorize student execution.

At the absolute intake deadline or the approved cleanup boundary, unresolved cleanup/evidence is incomplete and quarantined. Continue independent best-effort cleanup; never acknowledge success when either branch is failed or uncertain.

## Journal backend proof gate

The candidate journal configuration and acceptance matrix are defined in `docs/specifications/m0-journal-backend-evaluation.md`. It is a proposal only; no storage engine or host implementation is approved.

Before any supervisor implementation or host proof:

- Review the candidate SQLite DELETE-journal / EXTRA profile against the exact library build, local filesystem, mount options, VM storage device and kernel.
- Verify the effective `journal_mode` and `synchronous` settings at runtime; do not infer them from configuration files or library defaults.
- Prove the host-wide kernel process lock prevents a paused old supervisor and a replacement from concurrently issuing privileged containerd operations. The database generation is not a substitute for this lock.
- Run process-crash and abrupt-VM-power-loss injection around transaction commit, rollback-journal deletion, directory synchronization, disk-full and sync-error paths. Process termination alone does not prove power-loss durability.
- Exercise SQLITE_BUSY, SQLITE_FULL, SQLITE_IOERR, corrupt database/journal, interrupted migration, uncertain commit, backup and restore. Any uncertain or corrupt state quarantines the host and blocks new work.
- Verify that cleanup remains independently operable when journal writes fail; do not let database failure block termination and resource cleanup.
- A backup must be a consistent SQLite Online Backup API snapshot or an equivalently reviewed quiesced copy. Never copy only the live main database file and assume it contains committed WAL/journal state.
- Do not accept work after restart until the new supervisor holds the kernel lock, advances the durable generation, validates the database/schema, and reconciles all non-terminal attempts against actual host resources.

If SQLite is rejected by empirical results, stop and reopen the backend decision. Do not silently switch journal mode, synchronous setting, filesystem, remote database, or custom log implementation.

## Evidence bundle

Use `docs/specifications/m0-proof-resource-profile-v1.md` as the proposed versioned resource profile and `docs/schemas/m0-proof-evidence.schema.json` as the versioned manifest contract for the proof report. The evidence manifest must record the exact resource-profile ID, revision, and applied limits. The manifest records structured outcomes and references to sanitized evidence files; it must not embed raw logs, student code, hidden test data, credentials, or private artifact URLs. A schema-valid manifest is a completeness aid, not proof that the underlying tests actually ran or passed.

Before a proof can be classified as passed, a separate host-side evidence verifier must resolve every manifest reference against the immutable evidence store and independently verify the exact published object version, SHA-256, byte count, approved evidence root, and redaction disposition. JSON Schema validation checks manifest structure only; it does not establish object existence, integrity, durability, or provenance.

Evidence publication must follow the crash-safe ordering in Section 7.1 of `m0-runtime-proof-harness-design.md`: sanitize before publication; durably stage and publish immutable content-addressed objects; read back and verify bytes; durably journal verified references; persist the final manifest; then commit the terminal result. A terminal acknowledgement must not precede durable evidence disposition and independently verified cleanup disposition.

Exercise crash injection between each publication/journal/manifest/terminal step. Verify that orphan staging objects are never treated as evidence, missing or mismatched objects force an incomplete/non-passed result, and a persisted manifest without a terminal journal transition is reconciled idempotently. Evidence-store failure must never block the independent termination and cleanup controller.

Finalization must run cleanup and evidence handling as two independently supervised branches. Start process termination and cleanup immediately when the attempt enters finalization; do not wait for evidence capture, redaction, hashing, publication, or manifest generation. Persist cleanup disposition and evidence disposition separately. Only after both are durable may the supervisor perform one terminal compare-and-set. A passed result requires successful verified cleanup and complete verified evidence; either branch failing, timing out, or remaining uncertain forces an incomplete/infrastructure-failed outcome. On restart, reconcile each branch independently before resuming finalization.

Store a proof report outside the host and include:

- Host/provider/region and image identifier (once selected).
- Kernel, containerd, runsc, shim, OCI image digests, and package provenance.
- Exact commands, timestamps, exit statuses, and sanitized logs.
- Test fixture repository revision and immutable image digest.
- Expected versus observed behavior for every test.
- Resource measurements, cold/warm latency, and concurrency results.
- Cleanup verification and any orphan-process scan.
- Known limitations, failed tests, deviations, and remediation.
- Reviewer and approval date.

Never include credentials, production secrets, real student code, hidden test data, or private artifact URLs.

## Stop conditions

Stop the proof and do not enable the executor if:

- The host or runtime version differs from the approved baseline without an ADR update.
- The actual gVisor platform cannot be independently verified.
- Any network path, host mount, privileged socket, capability, or secret is exposed.
- Any configured resource limit is best-effort rather than enforced.
- Cancellation or cleanup cannot be proven.
- A failure is unexplained or the evidence bundle is incomplete.

Passing this runbook permits a separate M0 security review. It does not authorize production deployment or student execution.
