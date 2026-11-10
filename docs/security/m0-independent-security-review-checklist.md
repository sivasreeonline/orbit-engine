# M0 Independent Security and Architecture Review Checklist

- Status: **review package prepared; independent review not yet performed**.
- Review baseline commit: **must be pinned in the signed review record at review kickoff**. The blank template intentionally carries no commit SHA; never reuse a historical baseline for a new review.
- Scope: M0 disposable synthetic proof only. This is not production approval.
- Machine-readable schema: `m0-independent-security-review-record.schema.json`.
- Blank record: `m0-independent-security-review-record.template.json`.
- Implementation remains blocked; `UnconfiguredExecutor` stays active.

## 1. Reviewer instructions

1. Verify the exact reviewed commit and all document/runtime/host digests before assessing claims. A moving branch name is not a review baseline.
2. Review privilege alternatives against the same control IDs. Do not assume rootless automatically satisfies cgroup, network, lifecycle or runtime requirements.
3. Record `not-reviewed`, `pass`, `fail`, or `conditional`. A pass requires a method and independently verified evidence. Missing evidence is not a pass.
4. Distinguish design evidence, CI/schema checks, host configuration evidence, live runtime evidence and fault-injection evidence. CI success cannot substitute for host proof.
5. Record exploit preconditions, impact, severity, remediation owner and residual risk. Do not accept an unowned high/critical risk.
6. Keep review recommendations separate from actual implementation, Phase A, Phase B, student and production authorization. This record is not an authorization token.
7. Sign only after evidence objects and signature references have been independently resolved. Schema validity does not authenticate a reviewer.

## 2. Required decision outcomes

| Decision field | Possible recommendation | What it does not authorize |
|---|---|---|
| Architecture | Rootful candidate / rootless candidate / reject both / defer | No implementation or host deployment |
| Privileged implementation | Recommend after separate authorization / do not implement / defer | No privileged code or socket enablement |
| Phase A | Eligible for separate calibration authorization / not eligible / defer | No calibration run; requires separate signed Phase A manifest |
| Phase B | Eligible after profile approval / blocked / reject | No 35-fixture run; requires separate profile and reviewer approval |
| Student execution | Always false in this record | No student execution |
| Production execution | Always false in this record | No production execution |

An architecture-candidate recommendation is a design recommendation only. All actual authorization flags are structurally fixed to `false` in the record schema.

## 3. Rootful / rootless / no-go comparison

| Dimension | Rootful containerd + typed host supervisor | Rootless containerd + caller-configured user namespaces | Required reviewer evidence |
|---|---|---|---|
| Runner authority | Runner unprivileged; one supervisor accesses rootful socket | Runner unprivileged; daemon confined to dedicated user identity | Effective UID/GID/groups, socket tests and process authority inventory |
| Privilege blast radius | Supervisor compromise may have host-level containerd authority | User namespaces can reduce host privilege, but delegation/helpers remain sensitive | Capability/syscall/writable-path inventory; user namespace and RootlessKit mapping |
| Lifecycle | Expected containerd + shim path; exact versions still need proof | Must prove create/start/stop/delete through caller-configured userns path | Exact runtime versions and lifecycle traces |
| gVisor mode | systrap independently proven | Do not conflate `runsc --rootless` CLI with caller-configured user namespaces | Live runtime platform and process metadata |
| cgroup v2 | Rootful controller must enforce hard limits | systemd/cgroup delegation must demonstrably enforce hard limits | CPU/memory/PID counters and limit-trigger evidence |
| Network | Host-enforced default deny, including metadata before uplink | Rootless networking path must prove equivalent denial | Host counters, packet observations and sentinel tests |
| Filesystem | Fixed OCI profile; no host paths/devices | User namespace mappings/runtime mounts expose no host paths/devices | Effective mounts/namespaces and host sentinels |
| Recovery | Exclusive host lock, journal reconciliation and cleanup watchdog | Equivalent fencing/recovery through user daemon/helper lifecycle | Pause/crash/restart fault injection and post-cleanup inventory |
| Operations | Privileged service, hardening, socket and incident controls | User namespaces, subordinate IDs, RootlessKit, cgroup/network delegation | Exact service config, patch/rollback, recovery ownership |

Do not select a winner from this table alone. Complete the same control findings for the selected candidate and document why alternatives were rejected or deferred.

## 4. Stable security control register

| Control ID | Area | Reviewer question | Minimum evidence required | Class |
|---|---|---|---|---|
| ARCH-001 | Privilege model choice | Compare rootful supervisor with rootless containerd + caller-configured user namespaces; distinguish runsc --rootless CLI mode. | Exact version matrix, equivalent lifecycle/cgroup/network/cleanup evidence, privilege comparison. | design |
| ARCH-002 | M0 scope and authorization boundary | Confirm disposable synthetic proof scope; no implied student or production enablement. | ADR, route inventory, runner readiness and executor wiring. | design |
| AUTH-001 | Runner identity and privilege separation | Can runner/guest obtain containerd socket or host authority? | UID/GID/groups, socket ACL, process identity and negative access tests. | host |
| AUTH-002 | Supervisor private transport | Are socket path/inode/mode, peer credentials, framing and FD policy enforced? | Socket metadata, wrong-UID/GID, symlink, malformed/oversized/FD tests. | host |
| AUTH-003 | Per-operation authorization | Does every operation authorize the exact run/fixture/attempt/profile/idempotency identity? | Authorization matrix, negative tests and durable attempt ownership. | mixed |
| API-001 | Typed request and immutable profile | Are unknown fields rejected and OCI settings resolved only from root-owned profiles? | Request schema, parser/fuzz tests, profile signatures and forbidden-field tests. | design |
| PRIV-001 | Privilege minimization | Are capabilities, syscalls, writable paths and ambient privilege minimal? | Effective capability inventory, process evidence, syscall and writable-path review. | host |
| PRIV-002 | Service hardening | Does the exact service unit allow only required operations? | Effective systemd properties, drop-ins, filesystem restrictions and negative tests. | host |
| RUNTIME-001 | Runtime provenance | Are kernel/containerd/runsc/shim/supervisor versions and builds pinned and verified? | Package versions, source IDs, signatures, SBOM/provenance, advisories and digests. | host |
| RUNTIME-002 | Live systrap assertion | Is systrap observed on the live sandbox, without fallback? | Runtime platform report and independent host-side observation. | host |
| OCI-001 | Image and fixture immutability | Are images/fixtures digest-pinned, provenance-verified and allowlisted? | Image digests, signature/provenance, source revisions and negative registry tests. | host |
| NET-001 | Default-deny network | Are IPv4/IPv6/DNS/direct-IP/loopback/alternate routes denied? | Firewall/routing counters, packet capture and controlled sentinel tests. | host |
| NET-002 | Metadata isolation | Is metadata link-local traffic blocked before host uplink, without host-side metadata queries? | Outer deny rules, packet observations and host-side counters. | host |
| CGROUP-001 | Resource enforcement | Are cgroup v2 CPU/memory/PID limits hard enforced under an outer VM envelope? | Hierarchy/configuration, counters/events, OOM/PID and pressure tests. | host |
| FS-001 | Filesystem and scratch boundary | Are base/mounts read-only and scratch isolated/bounded, with no host paths/devices? | Effective OCI mounts, namespace inventory, sentinel hashes and scratch counters. | host |
| OUTPUT-001 | Output and pipe containment | Are streams concurrently drained with bounded atomic accounting and cleanup independent of EOF? | Byte counters, artifacts, inherited-pipe/stream-flood tests and storage-failure tests. | host |
| LIFE-001 | Trigger arbitration | Are natural exit/cancel/deadline/output triggers ordered with immutable primary and retained secondary events? | State/trigger records, sequence/timestamp traces, race tests. | mixed |
| LIFE-002 | Idempotency and crash recovery | Do deterministic identities and inspect-before-retry prevent duplicate create/start? | Journal/operation IDs, generations, crash-injection and resource inventories. | host |
| LIFE-003 | Cleanup and terminal acknowledgement | Does terminal success require independent absence of all workload resources? | Post-cleanup process/task/shim/namespace/cgroup/mount/scratch/network inventory. | host |
| CLOCK-001 | Within-boot clock | Is the selected elapsed clock suspend-aware and anchored to the earliest trigger? | Clock API, boot ID, raw samples and suspend/resume tests. | host |
| CLOCK-002 | Reboot and clock trust | Are reboot/snapshot/NTP-loss/clock-step cases conservative and fail closed? | Host/boot identity, time-sync uncertainty, snapshot policy and fault evidence. | host |
| JOURNAL-001 | Journal durability | Does exact backend/filesystem/storage preserve acknowledged commits and fail closed? | Library/source ID, effective settings, filesystem/device and power-loss/disk-full/corruption reports. | host |
| JOURNAL-002 | Exclusive supervisor fencing | Can only one privileged supervisor access containerd, including with old process SIGSTOP-paused? | Kernel lock implementation, ownership/inode evidence, process and generation traces. | host |
| JOURNAL-003 | Schema/migration/backup/restore | Are constraints, migrations and consistent backup/restore fail-closed? | Migration/constraint tests, backup/restore and non-terminal reconciliation reports. | host |
| WATCH-001 | Per-attempt cleanup controller | Does termination/cleanup proceed during client, journal and evidence outages? | Trigger/termination timing, host inventory, branch dispositions and fault injection. | host |
| WATCH-002 | Supervisor recovery watchdog | Can a paused/deadlocked supervisor be stopped/replaced without dual privileged access or clock reset? | Watchdog identity/privileges, stop path, lock release, generations and restart evidence. | host |
| WATCH-003 | Outer VM safety watchdog | Are VM resource/wall limits and hard-stop/rebuild independent of in-VM failure domains? | Control-plane configuration, external enforcement and stop/rebuild audit. | host |

`WATCH-002` is not accepted from a generic restart test: independently review and require all seven `WD-001` through `WD-007` watchdog fault-injection subtests in the host qualification protocol. Any missing, ambiguous or bypassed subtest keeps WATCH-002 unpassed.
| EVID-001 | Evidence integrity | Are immutable object version/digest/size/provenance independently verified? | Evidence root, object version, SHA-256, byte count and independent verifier output. | mixed |
| EVID-002 | Evidence redaction and separation | Can evidence failure leak secrets or delay cleanup? | Redaction rules, canary scan, bounded staging and evidence-outage tests. | host |
| SUPPLY-001 | Supply chain | Are actions, Go dependencies, runtime packages, images and fixtures pinned and monitored? | Lockfiles, action pins, SBOM/provenance, vulnerability and patch/rollback reports. | mixed |
| OPS-001 | Operations and recovery ownership | Are operators, emergency stop, patching, rollback, backups and incident duties defined? | Runbooks, role/access matrix, recovery drill and audit evidence. | mixed |
| OPS-002 | Residual risk and release scope | Are risks owned and M0/Phase A/Phase B/student/production decisions kept separate? | Risk register, separate gate record and ADR/release checklist. | design |

## 5. Severity and closure rules

| Severity | Meaning | Required disposition |
|---|---|---|
| Critical | Direct host compromise, credential/metadata access, unbounded execution, false success after unverified cleanup, or safety-gate bypass | Reject/stop; no conditional acceptance for M0 proof |
| High | Privilege escalation, uncontained network/resource risk, ambiguous ownership/recovery, or durability failure affecting acknowledged state | Remediate and re-review before implementation/host proof |
| Medium | Material weakness with bounded impact and concrete mitigation | Named owner, milestone, evidence and reviewer acceptance |
| Low | Limited issue not defeating a core control | Record owner and closure plan |

A finding is not closed merely because a change was committed or CI passed. Closure requires evidence for the exact reviewed version.

## 6. Evidence reference requirements

Each evidence reference identifies the immutable source/object and exact version, SHA-256, byte count, evidence root, accountable `acquired_by_id` principal, acquisition timestamp/tool, redaction status, independent verification status and reviewer note. `acquired_by_id` identifies who actually acquired/uploaded the object, not merely which tool performed the transfer. Do not include private object URLs, credentials, source code, hidden tests or raw sensitive logs.

Evidence verification is an actual byte-level and provenance check, not acceptance of metadata fields: independently retrieve the exact immutable object version; recompute full-object SHA-256 and byte count; confirm the evidence root, retention/version identity and test/host/profile provenance; verify detached signatures/attestations against pinned signer trust material; and retain sanitized verification output. Never treat an ETag as SHA-256 without provider documentation for the exact upload mode. Missing or inaccessible objects, digest/size mismatch, invalid signatures or ambiguous provenance block the evidence.

Evidence acquisition, independent verification and security review are separately attributable roles. The `acquired_by_id` principal must differ from the independent verifier, host owner and independent security reviewer; the verifier must also differ from the host owner and security reviewer. The machine validators enforce these identity-separation rules for passed evidence references; they do not retrieve objects or perform cryptographic verification.

Evidence types: `design-document`, `ci-run`, `schema-test`, `host-runtime`, `host-configuration`, `fault-injection`, `supply-chain`, and `operator-record`.

A host/runtime control cannot pass using documentation, CI or schema tests alone. Host-class controls require independently verified host/runtime/configuration/fault-injection evidence.

## 7. Stop / reject conditions

- Any successful forbidden network flow or metadata response.
- Any host mount, device, privileged socket, credential or host namespace exposure.
- Any best-effort/unbounded resource limit or surviving workload resource after terminal acknowledgement.
- Any duplicate terminal result, stale-generation write or infrastructure failure scored as a student verdict.
- Any evidence containing secrets, student source, hidden tests, raw daemon environment/command lines or private URLs.
- Any unsupported runtime fallback, unknown host identity, failed journal durability assumption or ambiguous crash recovery.
- Any unreviewed change to host baseline, runtime, fixture image, supervisor API, journal, watchdog, network boundary or resource profile.
- Any reviewer conflict, missing independent sign-off, unowned high/critical risk or missing evidence for a required pass.

## 8. Sign-off and re-review triggers

The reviewer records identity, independence basis, conflicts, reviewed commit/scope, review date/expiry, decision rationale, residual-risk owners and signature reference. The host owner and independent reviewer must be different identities.

Re-review is mandatory after a change to host image/kernel/filesystem, containerd/runsc/shim, supervisor/watchdog, journal backend/configuration, fixture digest, network boundary, privilege/service configuration, resource profile, cleanup deadline or material recovery semantics.


## Host and journal qualification linkage

Use `docs/specifications/m0-host-and-journal-qualification-protocol.md` and its machine-readable record under `docs/schemas/` before assessing host/runtime claims. Its baseline inspection, live runtime, network, watchdog, clock, journal, integrated lifecycle and evidence gates map the security controls to exact-host proof. A preflight pass or synthetic CI result is never a host-control pass.

## 10. Current state

**Not reviewed.** The blank machine-readable template is intentionally non-authorizing. No reviewer, host, runtime evidence, signature or approval is pre-populated. Passing CI validates the record contract only; it is not a security review.

## ADR-0019 candidate decision

Add the candidate comparison in `docs/adr/ADR-0019-decision-dossier.md` to the independent review scope. Review both deployment models against the same 32 control IDs and map their evidence to the 33 host qualification tests. Use `docs/schemas/m0-adr-0019-decision-record.schema.json`; a selected candidate must have its own independently reviewed host qualification report.


## Upstream rootless and runtime integration evidence

Include `docs/adr/ADR-0019-upstream-compatibility-evidence.md` in the reviewer packet. In particular, assess RootlessKit helper binaries/subordinate IDs, namespace/socket isolation, network backend, systemd CPU delegation, exact containerd-shim + caller-userns compatibility, and source revision pinning. These are independent review items, not documentation-based passes.


## Rootless-only qualification requirements

For Candidate B, assess RLS-001 exact containerd-shim/caller-userns/systrap integration; RLS-002 subordinate UID/GID mappings and helper provenance; RLS-003 systemd CPU/memory/PID delegation; and RLS-004 RootlessKit network namespace and host abstract-socket isolation. Each requires independently verified host evidence. The shared 33-test catalogue does not replace these additional Candidate B tests. Candidate A must mark the rootless-only gate not-applicable and include no RLS test results.

## Rootless host profile identity review

Verify the exact structured `rootless_profile` in the host qualification record and confirm the same object/digest appears in the ADR candidate and signed qualification report. Review non-root daemon UID/GID, subordinate UID/GID map digests and range counts, RootlessKit/newuidmap/newgidmap binary hashes, helper ownership/modes/provenance, AppArmor profile, private state directory, daemon socket policy, network backend/namespace profile and systemd delegation. Confirm `cpu`, `memory` and `pids` are actually delegated and enforced. Candidate A must have null rootless profile fields.

## Immutable upstream source baseline

The immutable upstream source set is recorded in `docs/adr/ADR-0019-upstream-source-manifest.json`; the exact manifest SHA-256 must be embedded in any completed ADR-0019 decision record. A reviewer must check the seven source pins and recorded signature-verification status. The branch-head URLs are discovery references only; the manifest points to immutable commit URLs and records Git blob SHA-1 plus content SHA-256.
