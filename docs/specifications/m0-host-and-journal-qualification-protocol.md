# M0 Host and Journal Durability Qualification Protocol

- Status: **protocol only; no host selected, provisioned, or qualified**.
- Scope: disposable, single-tenant M0 synthetic proof environment only.
- Related: ADR-0019, M0 runbook, journal evaluation, supervisor/journal contract, independent security review package.
- No provider, region, VM size, storage class, journal implementation or spend is selected or authorized.

## 1. Purpose and qualification outcomes

This protocol makes the host proof prerequisites reproducible and evidence-bound. It separates a read-only host baseline inspection from live runtime, network, resource, watchdog and durability proof. Passing the current read-only preflight is not a host security qualification.

| Outcome | Meaning | Does not establish |
|---|---|---|
| `baseline-inspected` | Host identity, OS/kernel/cgroup, storage and live daemon configuration inventory are captured and independently reviewed | systrap, network containment, cgroup enforcement, cleanup or journal durability |
| `runtime-smoke-qualified` | A separately authorized fixed synthetic smoke test proves the selected runtime handler, systrap and lifecycle behavior | full adversarial proof or production readiness |
| `journal-durability-qualified` | Exact backend/build/filesystem/storage pass the journal durability test catalogue | supervisor integration correctness unless integrated lifecycle tests also pass |
| `outer-boundary-qualified` | Out-of-VM resource cutoff, network deny and stop/rebuild controls are independently evidenced | successful sandbox cleanup when outer cutoff fires |
| `host-candidate-qualified` | Every required test, sub-gate and independent review in this protocol passes for one immutable host/profile identity | Phase A/Phase B authorization, student execution or production approval |

The machine-readable record in `docs/schemas/m0-host-qualification-record.template.json` begins with every test `not-run`, host `selected=false`, overall state `not-qualified`, no reviewer, no evidence and all execution authorization flags false.

## 2. Non-negotiable sequencing

1. **Design review first.** Review ADR-0019 and compare rootful containerd + typed supervisor with rootless containerd + caller-configured user namespaces. Do not conflate either with the `runsc --rootless` CLI mode. No host or spend is selected by this protocol.
2. **Host selection/provisioning is separately authorized.** A selected candidate must be dedicated, disposable, single-tenant and contain no student data, production credentials, API secrets or unrelated workloads. Record the independent provisioning authorization reference and outer resource/network controls before use.
3. **Read-only baseline inspection.** Run the existing host preflight and collect the allowlisted inventory. This phase must not install packages, mutate firewall/cgroups, start containers, launch fixtures or change daemon settings.
4. **Storage-only journal candidate test.** If separately authorized, run the journal storage harness against an isolated scratch database on the exact candidate filesystem/device. It must not use the active supervisor journal, connect to containerd, start a sandbox, or contain student/hidden-test data. It establishes backend/storage behavior only.
5. **Runtime and containment smoke.** This is not part of read-only preflight. It may run only under a separate signed authorization for the exact disposable host, fixed harmless digest-pinned image, exact runtime identity and verified outer network deny. The probe must be synthetic and must not execute arbitrary commands or student code.
6. **Privileged implementation and integrated fault tests.** Supervisor/journal/watchdog integration tests occur only after a separately scoped implementation authorization, independent privilege review and exact-host service profile approval. The tests use deterministic synthetic attempts and no student/public endpoint.
7. **Phase A calibration.** Requires its own immutable signed authorization and all exact-host prerequisites. It exercises the actual cleanup controller and journal path; mock/alternate implementations do not qualify timing evidence.
8. **Phase B full 35-fixture proof.** Requires a separately approved numeric cleanup deadline, evidence/finalization reserve, clock/reboot behavior and new resource-profile revision after Phase A review.

No stage inherits authorization from a previous stage. Schema validity, CI success, a preflight pass or a host-candidate-qualified record is not a launch authorization.

## 3. Host identity and immutable qualification envelope

Record one host incarnation and never mix evidence from different hosts or re-imaged incarnations. At minimum, freeze:

- Control-plane provider/region/instance reference as non-secret identifiers; `host_instance_id`, boot ID, VM image digest, architecture, virtualization and kernel build.
- OS release, cgroup v2 mount/controllers, CPU topology, memory and PID envelope, outer disk/wall cutoffs and independent stop/rebuild owner.
- Filesystem type, mount options, mount source, stable storage/device identity, volume/storage class, write-cache/barrier/sync characteristics where exposed, and free-space/size quotas.
- Containerd package/build and running daemon identity; effective systemd unit/ExecStart; actual selected configuration file and complete import graph; config digest.
- runsc, shim, runtime handler, kernel and image/fixture provenance; binary hashes and package source IDs.
- Rootless user namespace mappings/subordinate IDs/RootlessKit and cgroup delegation details, or rootful supervisor UID/GID/capabilities/syscall/writable-path/service-hardening inventory.
- Journal backend, exact library source ID/build, Go driver/module version, effective settings on every connection, schema revision, journal path owner/mode, lock mechanism, backup/restore mechanism, retention and quota policy.
- Per-attempt cleanup controller, supervisor liveness watchdog, outer VM safety watchdog identities, owners, privileges, clocks, heartbeats and allowed actions.
- Host profile, runtime profile, resource profile, supervisor/watchdog build, test harness and evidence schema digests.

Provider identity must come from the control plane or authorized operator inventory. Never query cloud metadata from the host to identify the VM. Do not archive raw process command lines or environment values; capture only allowlisted fields and redact secrets, URL user-info, tokens and unrelated arguments.

## 4. Existing preflight: what it does and does not prove

The script `services/execution-runner/scripts/m0-host-preflight.sh` is read-only. It checks Ubuntu 24.04, x86_64, a Linux kernel minimum, unified cgroup v2 presence, containerd 2.3.x, a local `containerd config dump` containing the v3 config and runsc handler, the resolved `runsc` and containerd-shim binaries, and the adjacent `gvisor-bin/` sidecar inventory. Runtime executables and sidecars are checked for the expected owner (default `root`, overridable only through the explicit `M0_RUNTIME_OWNER` inspection setting), executable status and absence of group/world write permission; SHA-256 digests are emitted for the binary inventory. The sidecar directory must be a real non-symlink directory, owned by the expected runtime owner and not group/world writable; symlink entries are rejected. The containerd socket owner and mode are also checked. These checks establish only local installation-integrity signals, not provenance authenticity or runtime compatibility.

That script does **not** prove the live daemon loaded the same configuration/import graph, runtime shim behavior, systrap activation, effective UID/capability isolation, cgroup enforcement, network denial, filesystem boundary, output behavior, watchdog independence, journal durability, backup/restore, or cleanup. A preflight pass is therefore only a baseline inspection result.

Do not modify preflight to silently install or configure host packages/firewall/cgroups/containerd. Any new inspection must remain read-only and emit redacted/allowlisted data. Any destructive/fault-injection test belongs to a separately authorized disposable-host test harness.

## 5. Rootful and rootless equivalence requirements

| Dimension | Rootful containerd + typed host supervisor | Rootless containerd + caller-configured user namespaces | Evidence that must be equivalent |
|---|---|---|---|
| Runner authority | Runner has no rootful containerd access; exact supervisor identity is sole rootful application caller | Dedicated user daemon and helpers; runner cannot control unrelated host/user resources | UID/GID/groups, socket access tests, process inventory, authorization negatives |
| Privilege surface | Exact capability/syscall/writable paths/systemd hardening required | User namespace mappings, subordinate IDs, RootlessKit and helper authority required | Effective privilege inventory and hostile request tests |
| gVisor lifecycle | Exact containerd shim create/start/stop/delete | Same lifecycle through caller-configured userns and exact shim | Per-operation trace and deterministic resource inventory |
| Platform | systrap independently observed | systrap independently observed | Live runtime + host-side platform evidence |
| cgroups | Rootful cgroup v2 controller must enforce CPU/memory/PID | Delegated cgroup v2 controllers/systemd must enforce same ceilings | Identical counter/limit trigger criteria |
| Network | Host network boundary must deny all workload egress and metadata | Rootless network path must deny the same destinations before uplink | Identical IPv4/IPv6/DNS/direct-IP/loopback/metadata probes and host counters |
| Filesystem | Fixed OCI profile, no host path/device/socket | Userns mappings and runtime mount path must expose no host path/device/socket | Identical mount/namespace/sentinel inventory |
| Cleanup/recovery | One privileged host lock, durable journal and three watchdog roles | Equivalent lifecycle ownership and fencing despite user daemon/helper lifecycle | Same crash/pause/restart and resource-absence acceptance |

Decision outcomes are rootful candidate, rootless candidate, reject both, or defer pending evidence. A lower apparent privilege level is not proof that required controls work. If either candidate cannot demonstrate every required control, mark it not qualified.

## 6. Host, runtime and boundary test catalogue

Every test in the common catalogue below is required for either candidate. Candidate B (`rootless-containerd-userns`) must additionally pass all four rootless-only tests in the next table; Candidate A must mark that additional gate `not-applicable` and contain no rootless-only results. Runtime-starting and destructive tests remain blocked until their separate disposable-host authorizations exist.

| Test ID | Test | Required verification | Evidence type |
|---|---|---|---|
| HST-001 | Host incarnation and immutable identity | Control-plane host instance identity, boot ID, image digest and enrollment identity; no host metadata query | host-configuration |
| HST-002 | OS, kernel, architecture and cgroup baseline | OS/kernel/architecture/virtualization and unified cgroup v2 controllers | host-configuration |
| HST-003 | Filesystem, mount and storage identity | Filesystem/mount/device/storage/cache/sync characteristics; identify network/FUSE storage | filesystem-storage |
| HST-004 | Live containerd daemon configuration | Effective unit/ExecStart, process identity, selected config and import graph; redacted allowlisted capture only | host-configuration |
| HST-005 | Runtime package and binary provenance | Exact package versions/source IDs, signatures/provenance and binary hashes | supply-chain |
| AUTH-001 | Runner, supervisor and socket identity separation | Effective identities, socket ACL/peer credentials and negative authorization tests | host-configuration / fault-injection |
| RUN-001 | Live gVisor systrap and lifecycle smoke | Separately authorized harmless digest-pinned image create/start/stop/delete; independently observed systrap | host-runtime / fault-injection |
| CG-001 | Hard cgroup v2 enforcement | Measured CPU, memory and PID ceilings at sandbox and outer host | host-runtime / fault-injection |
| NET-001 | Default-deny egress coverage | Sandbox-originated IPv4/IPv6/DNS/direct-IP/loopback/alternate-interface probes plus host-side drop evidence | network-observation / host-configuration |
| NET-002 | Metadata deny before host uplink | Independently prove outer metadata deny before uplink; probe only in sandbox, never query from host | network-observation / host-configuration |
| FS-001 | Mount, namespace and scratch isolation | Read-only base, bounded scratch, no host path/device/namespace/socket exposure | host-runtime / fault-injection |
| OUT-001 | Output, pipe and inherited-descriptor containment | Concurrent drains, atomic accounting, bounded staging, inherited-pipe and evidence-outage tests | host-runtime / fault-injection |
| WDG-001 | Per-attempt cleanup controller independence | Immediate termination at first trigger, independent resource absence, journal/evidence outage behavior | fault-injection / host-runtime |
| WDG-002 | Supervisor liveness/recovery watchdog fencing | Pause/deadlock/crash; exact service stop, kernel lock release before replacement, generation reconciliation | fault-injection / host-configuration |
| WDG-003 | Outer VM safety boundary and hard stop | Out-of-VM CPU/memory/PID/disk/wall cutoff using an independently operated control-plane/hypervisor time source; demonstrate the hard cutoff and stop/rebuild path still work when guest wall and monotonic clocks are stepped, frozen, unavailable, or rolled back | watchdog-control-plane / operator-record / fault-injection |
| CLK-001 | In-VM CLOCK_BOOTTIME suspend-aware elapsed clock | Exact audited guest clock API includes suspend; in-VM trigger anchor and supervisor-restart re-arm verified; no outer-watchdog authority is derived from this guest clock | host-runtime / fault-injection |
| CLK-002 | Guest reboot, NTP uncertainty and snapshot/restore | Boot identity/time uncertainty/rollback/reboot/restore fail closed and quarantine on ambiguity; guest clock evidence is not accepted as the outer VM cutoff clock | fault-injection / host-runtime |
| EVID-001 | Evidence object read-back and independent integrity | Immutable version/root/size/hash/redaction and independent verifier read-back | host-runtime / fault-injection |

### Rootless-only candidate qualification tests

These four additional tests are mandatory only when `scope.target_architecture` is `rootless-containerd-userns`. They are not replaced by the common RUN-001, CG-001, NET-001 or AUTH-001 tests because they exercise the exact RootlessKit/user-namespace integration points. For a rootful candidate, `rootless_userns_compatibility` must be `not-applicable` and `candidate_specific_test_results` must be empty.

| Test ID | Test | Required verification | Evidence type |
|---|---|---|---|
| RLS-001 | Rootless containerd + runsc shim + caller-userns integration | Pin exact containerd 2.3.x, `containerd-shim-runsc-v1`, runsc and systrap builds; use caller-configured user namespaces via the selected rootless containerd path; prove create/start/status/cancel/delete and restart reconciliation; independently observe systrap and reject fallback | host-runtime / fault-injection |
| RLS-002 | Rootless UID/GID mapping and helper provenance | Verify non-overlapping `/etc/subuid` and `/etc/subgid` ranges, multi-UID mappings, exact `newuidmap`/`newgidmap` binaries/hashes/owners/modes, RootlessKit identity/version/state/socket and AppArmor policy; prove the helper chain cannot control unrelated host users/resources | host-configuration / supply-chain / fault-injection |
| RLS-003 | Rootless cgroup v2 delegation including CPU | Verify the actual user service's delegated `cpu`, `memory` and `pids` controllers, systemd delegation chain and effective cgroup files; under load prove CPU, memory and PID ceilings are enforced by the exact containerd/runsc stack, not merely configured | host-runtime / fault-injection |
| RLS-004 | Rootless network namespace and host abstract-socket isolation | Prove the actual RootlessKit/userns network namespace and selected Netstack/TAP/user-mode path; demonstrate host abstract Unix sockets are not exposed; verify IPv4/IPv6/DNS/direct-IP/loopback/metadata denial and pre-uplink outer boundary | network-observation / host-configuration / fault-injection |

The machine-readable record adds `gates.rootless_userns_compatibility` and `candidate_specific_test_results`. A rootless host can be `candidate-qualified` only when `RLS-001` through `RLS-004` are each passed with independently verified, test-specific evidence and that additional gate is `passed`. A design note, successful common test, or upstream documentation citation cannot mark any of these tests passed.

## 6. Journal backend qualification

### 6.1 Separate storage-only and integrated testing

**Storage-only candidate test** uses an isolated scratch database and synthetic rows on the exact candidate filesystem/device. It tests the SQLite library, driver, PRAGMAs, durability/sync behavior, filesystem/storage semantics, error handling and backup API. It must never open the future live supervisor journal, invoke containerd, spawn sandbox processes, or use student/production data.

**Integrated journal/lifecycle testing** is post-implementation and separately authorized. It verifies the exact supervisor schema/transactions, host process lock, generations/CAS, durable intent ordering, deterministic resource identities, crash recovery, cleanup/evidence branches and terminalization. It uses fixed synthetic attempt identities and reviewed harmless fixtures; no general execution endpoint or ordinary queue is present.

These are not interchangeable. Storage-only success does not qualify supervisor logic; integrated success does not waive the storage power-loss tests.

### 6.2 Candidate profile identity

The current candidate remains SQLite rollback-journal mode with `journal_mode=DELETE` and `synchronous=EXTRA`. It is **not approved**. For every opened connection, read back the effective PRAGMAs and fail closed if they differ. Record exact SQLite version and source ID, Go driver/module/version, compile/build options, filesystem, mount options, stable storage identity, journal path ownership/mode, schema revision, lock mechanism, file-size ceiling, free-space low-watermark, backup method and restore procedure.

Do not silently switch to WAL, `NORMAL`/`OFF`, network storage, a remote database or a custom journal. A changed backend or durability profile requires an updated ADR, schema/profile revision and new independent review.

### 6.3 Deterministic journal test catalogue

Each test runs on a newly identified disposable volume or resettable test image. Capture before/after host identity, exact injection boundary, durable rows/state versions, containerd/process side effects where relevant, recovery owner, integrity output and immutable evidence hashes. A process-kill test never substitutes for abrupt VM power-off.

| Test ID | Test | Required injection/verification | Required outcome | Evidence type |
|---|---|---|---|---|
| JRN-001 | Exact SQLite build and effective settings | Record SQLite version/source ID, Go driver/module version, filesystem/device, schema revision and read back DELETE + EXTRA on every connection. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / host-configuration |
| JRN-002 | Power loss after acknowledged commit | Abrupt VM power-off after acknowledged intent/result commit; reboot and verify acknowledged transaction durability and integrity. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-003 | Rollback journal and directory-sync interruption | Inject interruption during journal write, rollback, journal unlink and directory sync; recovered database must be valid old-or-new atomic state. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-004 | Disk full at each durable transition | Exhaust controlled test volume during intent, operation result, trigger/branch disposition and terminal CAS; no false acknowledgement; cleanup continues. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-005 | BUSY and lock-contention bounded behavior | Inject SQLITE_BUSY and lock contention; bounded policy, no unbounded retry, lock bypass or duplicate side effect. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-006 | IOERR and failed synchronization | Inject SQLITE_IOERR/failed fsync or sync; uncertain commit reconciled by immutable operation identity; no success acknowledgement. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-007 | Corruption and invalid database rejection | Inject malformed header, corruption and SQLITE_NOTADB; host quarantines; no automatic recreate/repair/resume. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-008 | Interrupted schema migration | Interrupt each migration boundary; restart observes complete old or new schema, never a mixed schema; unknown schema fails closed. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-009 | SIGSTOP and exclusive kernel-lock fencing | Pause a supervisor while holding lock; replacement cannot issue containerd or journal mutations until old process exits and lock is released. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | fault-injection / host-configuration |
| JRN-010 | Crash after create/start before observed-result commit | Crash after external side effect and before durable observed result; inspect/reconcile deterministic resource; no blind create/start retry. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | fault-injection / host-runtime |
| JRN-011 | Trigger sealing, output finalization, independent branches and terminal CAS | Race cancellation/deadline/output/policy triggers against terminal sealing; crash before/after the durable seal and output snapshot, after either branch disposition, and before/after terminal CAS. Verify database guards reject watermark rewrites and post-finalization output mutation; trigger sequences through the watermark are contiguous and durable; output counters are monotonic, retained bytes do not exceed observed bytes, combined retained bytes equal stdout plus stderr retained bytes, and the finalized snapshot is write-once; branches are generation-fenced and post-seal incidents append-only. | No trigger/output rewrite, no success after a success-disqualifying breach, no duplicate terminal result; uncertainty quarantines host | fault-injection / journal-durability |
| JRN-012 | Consistent backup during journal activity | Create a reviewed consistent backup during concurrent journal activity; source remains safe; backup byte integrity and manifest verified. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-013 | Isolated restore with non-terminal attempts | Restore onto isolated disposable host; reconcile attempts against actual resources before readiness; no duplicate launch or adoption of unknown resources. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | journal-durability / fault-injection |
| JRN-014 | Journal ownership, permissions and writer exclusivity | Verify root-owned paths, restrictive modes, one supervisor writer, lock FD non-inheritance and no alternate maintenance writer. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | host-configuration / fault-injection |
| JRN-015 | Journal quota, low-watermark and retention behavior | Test max DB size, free-space low-watermark, retention boundaries and no pruning of active/unresolved attempts; fail closed on capacity exhaustion. | No false acknowledgement, duplicate operation, unsafe resume or unverified success; uncertainty quarantines host | filesystem-storage / fault-injection |

### 6.4 Storage durability acceptance

- Every acknowledged commit survives the approved hard-power-loss boundary or the candidate is rejected; record exactly where power was removed and when acknowledgement occurred.
- Every interrupted rollback-journal transition recovers to a valid complete old or new transaction state. Mixed/ambiguous/corrupt state is never interpreted as success.
- SQLITE_FULL, SQLITE_BUSY beyond bounded policy, SQLITE_IOERR, failed fsync/sync, SQLITE_CORRUPT and SQLITE_NOTADB stop admissions and fail closed. Existing termination must not wait for journal I/O.
- Migration is all-or-nothing. Unknown/newer schema, torn migration or failed integrity checks cause quarantine; never auto-delete/recreate/repair to readiness.
- Backup uses SQLite Online Backup API or an independently reviewed quiesced snapshot. A live file copy alone is not a valid backup. Restore runs on an isolated host and reconciles all non-terminal attempts against actual host resources before readiness.
- Lock contention proves the stable kernel process lock, not a database lease, fences a SIGSTOP-paused supervisor. Replacement cannot issue privileged operations until old process exit and lock release.
- A full journal/volume causes rejection of new work, no pruning of unresolved records and continued independent termination/cleanup.

Do not approve a journal backend because a workstation unit test passed. Exact-host power-loss, filesystem and device behavior are part of the result.

## 7. Watchdog and network qualification

Three watchdogs are independent review subjects:

1. **Per-attempt cleanup controller:** issues complete termination at the earliest host-observed trigger, does not wait for database fsync/client/evidence/EOF, verifies complete resource absence and persists cleanup disposition.
2. **Supervisor liveness/recovery watchdog:** detects process death/pause/deadlock, fail-stops the exact named supervisor, waits for kernel lock release, starts one replacement generation and requires reconciliation before admission. It must not become a second containerd writer or generic root command broker.
3. **Outer VM safety watchdog:** lives outside the tested VM failure domain and enforces CPU/memory/PID/disk/wall cutoff plus isolate/stop/rebuild. It is containment only. If it fires, the sample fails and the VM is quarantined/destroyed; it is never successful cleanup evidence.

The common `WDG-002` host qualification test is not passed by a generic supervisor restart demonstration. It is passed only when all seven independently evidenced subtests below pass on the exact host, boot, supervisor/watchdog build, service-manager configuration and candidate profile. These subtest IDs refine WDG-002; they do not add or replace top-level qualification test IDs.

| Subtest | Fault injection | Required pass evidence / fail-closed behavior |
|---|---|---|
| WD-001 | Pause/deadlock the watchdog process and withhold its heartbeat while the supervisor is unhealthy | Independent outer-VM watchdog detects the loss and contains the VM; no in-VM fallback authority is invented |
| WD-002 | Deny the exact service-manager StopUnit/StartUnit authorization | Recovery stops; no shell, systemctl, sudo, arbitrary helper or alternate root-broker path is attempted; admission remains stopped and outer containment is available |
| WD-003 | Substitute the supervisor unit file/drop-ins, executable, configured UID/GID, boot identity or service-manager instance | Digest/identity mismatch blocks every stop/start action; admission stops and mismatch evidence is retained |
| WD-004 | Alter the expected cgroup path or supervisor cgroup membership | No replacement is started until exact complete-cgroup identity and old-process termination can be independently proven |
| WD-005 | Enable or inject an automatic systemd restart race against watchdog-directed recovery | Pinned restart policy prevents dual replacement ownership; exactly one recovery authority may start a replacement |
| WD-006 | Cause the service manager to acknowledge stop before the supervisor exits or releases its kernel lock | Replacement remains blocked until independent process-exit and kernel-lock-release evidence exists |
| WD-007 | Stop, crash or make the watchdog unit unavailable while supervisor recovery is required | No alternate privileged path; admission remains stopped and the outer-VM watchdog is the only containment fallback |

Each subtest must capture the exact injected boundary, service-manager result, unit/executable/cgroup identity, supervisor process/cgroup observations, lock inode and release observation, generation transitions, admission state and immutable evidence references. A missing or ambiguous observation is a failed WDG-002 result, not a waived subtest.
Each WD-001–WD-007 record must include at least one independently retrieved and verified evidence object classified as `fault-injection`, bound to the exact host/boot/build/profile under test. Host-configuration, host-runtime, watchdog-control-plane and operator records may supplement that object but cannot replace proof of the injected fault and observed response.

Network proof is independent of the guest's reported state. Outer deny/blackhole for metadata link-local must be installed and evidenced before uplink. Probe only from inside the disposable sandbox after authorization; never issue a metadata request from the host or accept/store a metadata response. Prove IPv4/IPv6/DNS/direct-IP/loopback/alternate interface denial with host counters or equivalent independent observation.

## 8. Evidence and record rules

The machine-readable qualification record contains one immutable host/profile identity and exactly one result for every test ID in the schema. A passed test requires a non-empty verification method and at least one independently verified evidence reference. Every evidence reference records the accountable `acquired_by_id` principal as well as the immutable object/source reference, exact version, SHA-256, byte count, evidence root, acquisition timestamp/tool/version, redaction result, independent verifier identity and verification note. `acquired_by_id` must identify the human or service principal that actually acquired/uploaded the object; it cannot be omitted or replaced with the acquisition tool name.

**Mandatory evidence re-verification procedure (not a metadata-only check):**

1. The evidence verifier obtains the object through an independently authorized, read-only path using the recorded `evidence_root_id`, `reference_id` and exact immutable `object_version`. A mutable alias, latest-version lookup, uploader-provided local copy or unversioned URL is insufficient.
2. The verifier records the resolved immutable object identity and confirms that it belongs to the declared evidence root and expected evidence type. If the storage system exposes retention lock, object-lock or version-retention metadata, verify and record the effective retention state and expiry.
3. Download the exact object bytes to a controlled verification workspace. Recompute SHA-256 over the complete byte stream and count the exact bytes; compare both values with the record. Do not trust a provider ETag as a SHA-256 unless the provider explicitly documents that exact semantic for the selected upload mode.
4. Verify any detached signature or attestation against the expected signer identity and pinned trust material; record the verification command/tool version, signer identity, trust-root identity and result. A signature reference string or schema-valid record is not signature verification.
5. Inspect redaction and provenance, confirm that the evidence actually supports the named test and reviewed host/boot/profile/commit, then record the verifier's independent result and sanitized note. A mismatch, missing version, inaccessible object, unverifiable signature, digest/size mismatch or ambiguous provenance means `verification_status=failed` or the test remains blocked—not passed.
6. The evidence verifier must be a third role, distinct from both the host owner/acquirer and the independent security reviewer. The same person may not acquire/own the host, verify the evidence and independently review the security decision. The validator enforces that the recorded evidence acquirer, independent verifier, host owner and security reviewer are distinct for every passed common and rootless test.
7. Preserve the verified object version and sanitized verification output in the evidence ledger. Reverification is required if the object is replaced, retention/version identity changes, the host/profile baseline changes, or the reviewed commit changes.

The machine validator checks the record's metadata and role separation, including the explicit acquisition principal; it cannot fetch external evidence objects, recompute their bytes, validate storage retention or cryptographically verify signatures. Those are mandatory human/operator verification steps and must not be represented as CI-proven.

Do not store raw `/proc` cmdline/environment, credentials, private URLs, student code, hidden tests, source archives or metadata responses. Host tests require host/runtime/storage/network/watchdog evidence; design documents, CI and synthetic schema tests are never sufficient to pass them.

Review decisions require distinct host owner and independent reviewer identities, independence/conflict disclosure, reviewed commit and exact host/profile digests, signed/auditable record, expiry and re-review triggers. The evidence verifier is a separate third role as specified above.

## 9. Qualification gate computation

| Gate | Required tests |
|---|---|
| Baseline inspection | HST-001 through HST-005 |
| Runtime smoke | AUTH-001, RUN-001, CG-001, FS-001, OUT-001 |
| Network boundary | NET-001 and NET-002 |
| Watchdog boundary | WDG-001, WDG-002 and WDG-003 |
| Clock/recovery | CLK-001 and CLK-002 |
| Journal durability | JRN-001 through JRN-009 and JRN-012 through JRN-015 |
| Integrated lifecycle | JRN-010 and JRN-011 |
| Evidence integrity | EVID-001 |
| Rootless compatibility (Candidate B only) | RLS-001 through RLS-004; Candidate A must mark not-applicable |

`host-candidate-qualified` requires all common catalogue tests passed, all applicable gates passed, an exact selected host/runtime/storage/journal identity, a completed independent review with no unresolved high/critical findings, and verifiable evidence for each test. Candidate B additionally requires all four RLS tests and its rootless compatibility gate; Candidate A must have no RLS results and mark the gate not-applicable. The record itself always keeps Phase A, Phase B, student and production authorization false.

## 10. Stop, fail and quarantine conditions

- Host identity, boot identity or profile digest mismatch; unapproved host/image/runtime change.
- Unknown daemon configuration import, raw sensitive evidence capture, provenance mismatch or unsupported runtime fallback.
- Any successful forbidden network flow, metadata request/response, host path/device/socket/namespace exposure or secret leak.
- Cgroup/resource control is configured but not independently enforced.
- Journal acknowledged commit lost after power loss; ambiguous rollback recovery; corrupt/unknown schema; IOERR/sync failure; unbounded BUSY; disk full; partial migration; inconsistent backup/restore.
- Any two privileged supervisors can act concurrently; old supervisor retains access after replacement begins; lock inheritance or generation ambiguity.
- Workload resource survives terminal acknowledgement; cleanup cannot be independently verified; stale worker mutates a current generation; false success after outer cutoff.
- Any high/critical security finding, missing evidence, invalid signature, reviewer conflict or unowned risk.

On stop: reject new work, continue best-effort independent termination when applicable, isolate/quarantine the host and preserve sanitized evidence. Do not auto-repair or rejoin the host to a ready pool.

## 11. Authorization boundaries and open inputs

- No provider, region, VM shape, storage class, disk, cost, image, runtime version, SQLite driver, file system or cleanup deadline is selected by this protocol.
- Storage-only journal qualification requires its own exact-host destructive-test authorization; Phase A requires its own separate manifest; Phase B requires a separate reviewed resource profile.
- Privileged supervisor/journal implementation remains blocked by ADR-0019 and the independent review gates.
- No sandbox launch, arbitrary command, student source, student endpoint or general queue consumer is authorized by passing this qualification protocol.

## 12. References

- `docs/specifications/m0-host-preflight-and-proof-runbook.md`
- `docs/specifications/m0-journal-backend-evaluation.md`
- `docs/specifications/m0-supervisor-journal-implementation-contract.md`
- `docs/specifications/m0-proof-resource-profile-v1.md`
- `docs/security/m0-independent-security-review-checklist.md`
- `docs/security/m0-independent-security-review-record.schema.json`
- SQLite PRAGMA documentation: https://www.sqlite.org/pragma.html
- SQLite Online Backup API: https://www.sqlite.org/backup.html

## ADR-0019 candidate decision linkage

`docs/adr/ADR-0019-decision-dossier.md` defines the candidate-specific configuration and evidence rules. Candidate A and Candidate B must each use the same 32 security control IDs and 33 common host qualification tests. Candidate B must additionally pass RLS-001 through RLS-004; these tests are mandatory only for rootless containerd/userns and are not-applicable to Candidate A. A host qualification report is candidate-, host-, commit- and profile-specific; it cannot be transferred between rootful and rootless deployments.

The machine-readable ADR decision record is `docs/schemas/m0-adr-0019-decision-record.template.json`. Its blank state is pending and grants no implementation, Phase A, Phase B, student or production authorization.


## Upstream compatibility evidence

`docs/adr/ADR-0019-upstream-compatibility-evidence.md` records the public upstream component facts and outstanding exact-stack compatibility gates. Its source URLs are mutable branch heads; a signed candidate decision requires exact source commit/tag and archived content digest. Do not mark any host qualification test passed from this ledger alone.

## Rootless host profile identity record

For Candidate B, `host_identity.rootless_profile` is a required structured object, not a free-form note. `host_identity.rootless_profile_digest` must equal its `profile_sha256`. The record captures:

- Non-root daemon UID/GID and a digest of the daemon identity/group membership evidence.
- Explicit `caller-configured-userns` mode; subordinate UID and GID mapping digests and range counts. Preserve sanitized mapping evidence in the reviewer evidence store; do not put unrelated host-user details or secrets in the repository.
- Exact RootlessKit version and SHA-256, `newuidmap` and `newgidmap` SHA-256, plus a helper inventory digest covering ownership, mode, package provenance and permitted privilege bits.
- AppArmor profile digest, RootlessKit state-directory policy digest and daemon socket policy digest.
- Network backend and network-namespace profile digest, including abstract-socket isolation policy.
- Systemd delegation profile digest and the effective delegated controller set. It must include `cpu`, `memory` and `pids`; a configured unit or a generic cgroup-v2 mount is insufficient.
- Rootless profile SHA-256 covering the normalized, redacted profile record. The checksum is defined as SHA-256 over UTF-8 bytes of compact JSON with recursively sorted object keys, separators `(",", ":")` without whitespace, ASCII escaping enabled, non-finite numbers forbidden, and array order preserved. The `profile_sha256` property is excluded from its own hash input. The profile schema restricts values to strings, bounded integers and arrays, so this serialization is deterministic.

The ADR candidate configuration and signed qualification report must carry the same `rootless_profile` object byte-for-byte after canonical serialization.

The verifier recomputes this digest; comparing two caller-supplied digest strings is insufficient. A stale digest after any profile-field change fails qualification. Its `profile_sha256` must match `host_identity.rootless_profile_digest`, candidate `configuration.rootless_profile_digest` and qualification `rootless_profile_digest`. Separately, the overall `host_profile_digest` must match the candidate `configuration.profile_digest`. These are distinct digests with distinct scopes. Any change to daemon UID/GID, mapping, helper binary, AppArmor policy, network backend, socket/state policy, systemd delegation or controller set invalidates the report and requires requalification.

For Candidate A, `rootless_profile` and `rootless_profile_digest` must both be `null`; rootful records cannot claim rootless evidence.

## Immutable upstream source baseline

The immutable upstream source set is recorded in `docs/adr/ADR-0019-upstream-source-manifest.json`; the exact manifest SHA-256 must be embedded in any completed ADR-0019 decision record. A reviewer must check the seven source pins and recorded signature-verification status. The branch-head URLs are discovery references only; the manifest points to immutable commit URLs and records Git blob SHA-1 plus content SHA-256.
