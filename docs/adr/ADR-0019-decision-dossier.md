# ADR-0019 Architecture Decision Closure Dossier

- Status: **pending independent review; no candidate selected**.
- Candidate A: `rootful-supervisor` — rootful containerd through one narrowly scoped typed host supervisor; the runner remains unprivileged.
- Candidate B: `rootless-containerd-userns` — rootless containerd through caller-configured user namespaces and the actual containerd shim lifecycle.
- Explicitly excluded: gVisor `runsc --rootless` CLI mode is not Candidate B and cannot substitute for the caller-configured user-namespace path.
- Decision record: `docs/schemas/m0-adr-0019-decision-record.template.json`.

## 1. Decision to be made

Select one architecture only if its exact implementation profile, host/runtime proof, security review, privilege inventory, recovery behavior and residual risks satisfy the mandatory M0 controls. Otherwise record `reject-both` or `defer`. There is no default winner and no decision is inferred from convenience, familiarity or nominal privilege level.

The rootful design in ADR-0019 is a candidate, not an accepted decision. Rootless containerd remains an alternative only in the caller-configured user-namespace integration. The separate `runsc --rootless` command-line mode is excluded because its documented lifecycle/network/cgroup limitations conflict with M0 requirements.

## 2. Candidate definitions and trust boundaries

| Boundary | Rootful supervisor | Rootless containerd + caller user namespaces |
|---|---|---|
| Runner | Unprivileged; no containerd socket group or host-root authority | Unprivileged; no unrelated user-daemon/host resource access |
| Lifecycle authority | One dedicated host supervisor is the sole application principal allowed to call rootful containerd | Dedicated rootless daemon, subordinate UID/GID maps and reviewed caller-configured userns path |
| gVisor integration | Exact containerd shim and pinned systrap handler | Same shim/systrap requirement through rootless containerd |
| Privilege boundary | Root-owned private Unix socket, peer credentials, typed API, per-attempt authorization, systemd hardening and capability/syscall/write-path inventory | User namespace mappings, RootlessKit/helper authority, daemon UID, private state/socket paths and delegated cgroups |
| cgroups | Hard cgroup v2 CPU/memory/PID controls in rootful hierarchy | systemd/cgroup v2 delegation must enforce identical hard limits |
| Network | Host firewall and namespace enforcement; metadata deny before uplink | Rootless network backend must prove identical deny behavior before uplink |
| Recovery | Stable kernel lock, journal generations/fencing and one replacement supervisor | Exclusive daemon/helper ownership, journal fencing and no parallel mutation under pause/restart |
| Cleanup | Verify process/task/shim/namespace/cgroup/mount/scratch/network absence before terminal acknowledgement | Same acceptance criteria; user namespaces/helpers do not weaken cleanup proof |

Include the runner, host controller/daemon, containerd shim, runsc, RootlessKit/helper, service manager, network implementation, cgroup delegate, host kernel, local journal, evidence collector and outer VM control plane in each threat model. Record what happens if each is compromised, paused, replaced or unavailable.

## 3. Mandatory equivalence rule

Both candidates use the same 32 independent security control IDs and the same 33 common host qualification test IDs. Candidate B (`rootless-containerd-userns`) must additionally pass RLS-001 through RLS-004; Candidate A must mark the rootless-only gate `not-applicable` and contain no rootless-only results. No control or test may be omitted because it is harder to satisfy under one privilege model. Any not-applicable claim requires a technical rationale and independent reviewer acceptance; required M0 controls cannot be waived.

Design evidence, host configuration evidence, live runtime evidence, fault-injection evidence and signed qualification records must remain distinguishable. CI/schema success is not host evidence. A qualification report for one candidate cannot qualify the other; evidence cannot be mixed across hosts, commits, runtime builds or profile digests.

### Security control IDs

- `ARCH-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `ARCH-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `AUTH-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `AUTH-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `AUTH-003` — see `docs/security/m0-independent-security-review-checklist.md`.
- `API-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `PRIV-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `PRIV-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `RUNTIME-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `RUNTIME-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `OCI-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `NET-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `NET-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `CGROUP-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `FS-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `OUTPUT-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `LIFE-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `LIFE-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `LIFE-003` — see `docs/security/m0-independent-security-review-checklist.md`.
- `CLOCK-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `CLOCK-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `JOURNAL-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `JOURNAL-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `JOURNAL-003` — see `docs/security/m0-independent-security-review-checklist.md`.
- `WATCH-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `WATCH-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `WATCH-003` — see `docs/security/m0-independent-security-review-checklist.md`.
- `EVID-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `EVID-002` — see `docs/security/m0-independent-security-review-checklist.md`.
- `SUPPLY-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `OPS-001` — see `docs/security/m0-independent-security-review-checklist.md`.
- `OPS-002` — see `docs/security/m0-independent-security-review-checklist.md`.

### Host qualification test IDs

| Test ID | Area | Required for both candidates |
|---|---|---|
| HST-001–HST-005 | Host identity, configuration and provenance | Yes |
| AUTH-001 | Runner/controller/socket identity | Yes |
| RUN-001 | Live shim and systrap lifecycle | Yes |
| CG-001 | cgroup v2 enforcement | Yes |
| NET-001–NET-002 | Default-deny and metadata pre-uplink deny | Yes |
| FS-001 / OUT-001 | Mount/scratch and output/pipe containment | Yes |
| WDG-001–WDG-003 | Three watchdog boundaries | Yes |
| CLK-001–CLK-002 | Suspend-aware clock and reboot/restore | Yes |
| JRN-001–JRN-015 | Storage durability and integrated lifecycle | Yes |
| EVID-001 | Evidence integrity and read-back | Yes |

Exact common test IDs: `HST-001`, `HST-002`, `HST-003`, `HST-004`, `HST-005`, `AUTH-001`, `RUN-001`, `CG-001`, `NET-001`, `NET-002`, `FS-001`, `OUT-001`, `WDG-001`, `WDG-002`, `WDG-003`, `CLK-001`, `CLK-002`, `EVID-001`, `JRN-001`, `JRN-002`, `JRN-003`, `JRN-004`, `JRN-005`, `JRN-006`, `JRN-007`, `JRN-008`, `JRN-009`, `JRN-010`, `JRN-011`, `JRN-012`, `JRN-013`, `JRN-014`, `JRN-015`.

Rootless-only Candidate B tests:

| Test ID | Required proof |
|---|---|
| RLS-001 | Exact containerd 2.3.x + `containerd-shim-runsc-v1` + caller-configured userns + systrap lifecycle and recovery |
| RLS-002 | Subordinate UID/GID mappings, `newuidmap`/`newgidmap`, RootlessKit helper provenance, private state/socket and AppArmor policy |
| RLS-003 | Actual systemd/cgroup-v2 delegation and hard CPU, memory and PID enforcement through the rootless containerd/runsc stack |
| RLS-004 | Rootless network namespace, host abstract-socket isolation, Netstack/TAP/user-mode path and default-deny egress proof |

## 4. Candidate-specific evidence checklist

### Candidate A — rootful supervisor

- Exact supervisor UID/GID, memberships, containerd socket principal and negative access tests for runner/guest identities.
- Root-owned socket parent/inode/mode, peer credentials, request framing, descriptor policy and per-attempt authorization evidence.
- Capability bounding, ambient/effective/permitted capability inventory, syscall policy, writable path/device inventory, systemd hardening and service/drop-in digests.
- SIGSTOP/SIGKILL/crash tests, lock retention, lock-FD inheritance and replacement supervisor handoff.
- Evidence that the supervisor cannot become a generic root command broker, arbitrary OCI proxy or second unrestricted containerd writer.

### Candidate B — rootless containerd with caller-configured user namespaces

- Exact rootless daemon UID/GID, subordinate UID/GID mappings, user namespace ownership and collision/overlap analysis.
- RLS-002: exact RootlessKit/helper binaries, `newuidmap`/`newgidmap` provenance, subordinate ID mappings, AppArmor policy, state/socket ownership and helper privilege inventory; retain only allowlisted/redacted evidence.
- RLS-003: systemd/cgroup v2 delegation chain proving CPU/memory/PID hard limits, not merely configured controller values.
- RLS-001: exact create/start/stop/delete and restart recovery through rootless containerd and its shim using caller-configured user namespaces; systrap independently observed.
- RLS-004: network and metadata denial through the actual rootless network backend, including IPv4/IPv6, DNS, direct-IP, loopback-to-host, alternate interfaces and host abstract Unix socket isolation.
- Pause/crash/restart tests for rootless daemon, helpers, mappings, fencing, journal reconciliation and complete cleanup.
- Evidence that unrelated host/user processes, sockets, paths or resources do not become controllable by the runner or sandbox.

Never substitute `runsc --rootless` CLI results for Candidate B evidence. Its integration mode must be exactly `containerd-caller-configured-userns`.

## 5. Selection criteria

A candidate is eligible for selection only when:

1. All 32 security control findings are independently reviewed, with no unresolved high/critical issue.
2. All 33 common qualification tests pass in one host record for that exact candidate, host incarnation and profile set. Candidate B must additionally pass RLS-001 through RLS-004 with the rootless compatibility gate set to `passed`; Candidate A must record those tests as absent and the gate as `not-applicable`.
3. The qualification record is `candidate-qualified`, independently signed/reviewed, unexpired and references the exact reviewed commit.
4. Candidate configuration/profile digests, runtime integration mode, host identity and journal profile digest match the qualification report.
5. Reviewer and host owner are distinct; independence is attested, conflicts disclosed, and the signed decision rationale records accepted/rejected alternatives.
6. No evidence from the other candidate or an earlier host is reused to fill a missing gate.

Only one candidate can be selected. If both qualify, the reviewer compares residual risks and operational blast radius and explicitly selects one. If no candidate meets every requirement, choose `reject-both` or `defer`.

## 6. Decision outcomes

| Outcome | Meaning | ADR status |
|---|---|---|
| `pending` | Review not completed; no architecture chosen | Proposed |
| `select-rootful-for-m0-proof` | Rootful candidate passed all gates and was selected | Accepted for M0 proof boundary only |
| `select-rootless-for-m0-proof` | Rootless containerd/userns candidate passed all gates and was selected | Accepted for M0 proof boundary only |
| `reject-both` | Neither candidate meets mandatory M0 controls | Rejected |
| `defer` | Evidence or review is insufficient | Deferred / Proposed |

ADR acceptance establishes only the M0 architecture boundary. The decision schema hard-codes privileged implementation, Phase A, Phase B, student and production authorization to false. Separate approvals and artifacts remain required.

## 7. Independent decision record

Use `docs/schemas/m0-adr-0019-decision-record.schema.json` and its blank template. It requires both candidate assessments, all security control IDs, candidate-specific configuration identity, an independent qualification report for any selected candidate, reviewer/host-owner separation, expiry and signature reference.

The blank record contains no UUID, reviewed commit, host, evidence digest, reviewer, candidate selection or authorization. Synthetic CI examples are test fixtures only.

## 8. No-go and re-review triggers

- Candidate mode/runtime integration differs from the exact reviewed configuration.
- Runner reaches containerd/host authority outside the reviewed boundary.
- Any host path/device/socket/credential/namespace leak or successful forbidden network/metadata flow.
- cgroup or output limits are best-effort rather than independently enforced.
- Supervisor/rootless daemon/helper can create duplicate or stale operations after pause/crash/restart.
- Journal acknowledged state is lost, recovery is ambiguous, or cleanup cannot verify complete resource absence.
- Candidate evidence is stale, cross-host, cross-commit, missing, unverified, improperly redacted or signed by a conflicted reviewer.
- A high/critical residual risk remains open or unowned.

Any such condition makes the candidate rejected or deferred; it cannot be waived by a passing build, another candidate's evidence or an informal note.

## 9. Current status

**Pending.** No candidate has a host qualification report. No independent reviewer has completed the review. ADR-0019 remains Proposed. No host/provider/spend is selected. No privileged implementation, Phase A, Phase B, student execution or production execution is authorized.

## 10. References

- `docs/adr/ADR-0019-m0-host-launch-boundary.md`
- `docs/security/m0-independent-security-review-checklist.md`
- `docs/security/m0-host-qualification-record.schema.json`
- `docs/specifications/m0-host-and-journal-qualification-protocol.md`
- `docs/specifications/m0-supervisor-journal-implementation-contract.md`
- `docs/specifications/m0-runtime-proof-harness-design.md`

## Upstream compatibility evidence ledger

The dated public-source review is maintained in `docs/adr/ADR-0019-upstream-compatibility-evidence.md`. It distinguishes documented component capabilities from the unproven exact M0 integration, records the RootlessKit/helper/cgroup/network proof obligations, and requires immutable upstream source pins before a signed decision. This ledger does not select or qualify a candidate.
