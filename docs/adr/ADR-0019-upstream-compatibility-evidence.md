# ADR-0019 Upstream Compatibility Evidence Ledger

- Review date: **2026-11-10**.
- Scope: public upstream documentation, not a tested host/runtime combination.
- Status: **documentary evidence only; neither candidate is qualified or selected**.
- Important limitation: upstream `main`/`master` pages are mutable. Before an architecture decision is signed, archive or pin each relevant source revision and content digest in the signed decision evidence bundle.

## 1. Executive finding

Current upstream documentation supports the existence of both the standard rootful containerd + gVisor shim path and a rootless containerd path built on user namespaces/RootlessKit. It does **not** establish that the exact M0 combination—containerd 2.3.x, `containerd-shim-runsc-v1`, gVisor systrap, caller-configured user namespaces, hard CPU/memory/PID enforcement, default-deny egress, and recoverable host lifecycle—works as one integrated stack.

The rootless route has concrete host-side prerequisites and two particularly important proof obligations: (1) gVisor's caller-configured-userns documentation describes higher-level engines such as Docker/Podman, while its containerd quick start documents the shim path separately; the combined caller-userns + containerd-shim path must be demonstrated at the exact pinned versions; and (2) rootless CPU cgroup enforcement is not implied by enabling cgroup v2 alone because user-session delegation may omit the CPU controller.

**Current disposition:** keep both candidates open. Treat rootless as technically plausible but with an explicit compatibility and resource-delegation gate. Treat rootful as the better-documented standard containerd integration path, but with a larger supervisor-compromise blast radius requiring a stronger privilege review. Documentation alone selects neither.

## 2. Evidence ledger

| ID | Upstream source | Documented fact | Architecture implication | Required Orbit Engine proof |
|---|---|---|---|---|
| UP-001 | [gVisor Rootless](https://gvisor.dev/docs/user_guide/rootless/) | `runsc --rootless` CLI mode does not support `create`, does not support gVisor Netstack and ignores cgroup configuration errors | This CLI mode is disqualified as a substitute for either M0 candidate | Static configuration check prevents selecting this mode; runtime mode is independently observed |
| UP-002 | [gVisor Rootless](https://gvisor.dev/docs/user_guide/rootless/) | Caller-configured user namespaces are a distinct higher-level-engine path; examples mention Docker/Podman, multiple UID mappings using subordinate IDs and `newuidmap`; a network namespace is important to protect host abstract Unix sockets; Netstack can be used with TAP and a user-mode network stack such as Slirp | Rootless containerd/userns has real helper, namespace and network dependencies; not equivalent to the `runsc --rootless` CLI mode | Demonstrate exact containerd-shim + caller-userns integration, mappings, network namespace, abstract-socket isolation and Netstack behavior on pinned versions |
| UP-003 | [containerd rootless](https://github.com/containerd/containerd/blob/main/docs/rootless.md) | containerd can run as a non-root user with user namespaces; RootlessKit can create user/mount and optionally network namespaces; the client must execute inside daemon namespaces; cgroup use requires cgroup v2 and systemd | Rootless control-plane client and supervisor need a defined namespace-entry/daemon lifecycle; the daemon socket is namespace-scoped | Prove supervisor connectivity, exact socket permissions, daemon recovery, namespace lifetime and cgroup behavior without granting runner access to unrelated user resources |
| UP-004 | [RootlessKit README](https://github.com/rootless-containers/rootlesskit/blob/master/README.md) | RootlessKit uses user/mount namespaces and `newuidmap`/`newgidmap` with `/etc/subuid` and `/etc/subgid`; its setup documents subordinate-ID prerequisites and network namespace isolation with userspace NAT | Rootless does not mean “no privileged helper”; helper binaries, subordinate-ID allocation, AppArmor policy and RootlessKit state/socket files enter the attack surface | Inventory helper ownership/modes/hashes, mappings, AppArmor policy, state directory, network backend and negative privilege tests |
| UP-005 | [runc cgroup v2](https://github.com/opencontainers/runc/blob/main/docs/cgroup-v2.md) | Rootless cgroup-v2 operation can use systemd delegation; typical default user delegation may expose only memory and pids; CPU/cpuset/io delegation requires systemd configuration | CPU limit enforcement is a specific rootless feasibility gate; “cgroup v2 present” is insufficient | Independently inspect delegated controllers and prove CPU, memory and PID limits through the actual containerd/runsc path under load |
| UP-006 | [gVisor containerd quick start](https://gvisor.dev/docs/user_guide/containerd/quick_start/) | Documents `containerd-shim-runsc-v1` and containerd runtime-handler configuration; containerd 2.x uses the version-3 config header | Standard rootful containerd + runsc shim integration is documented; this does not prove rootless caller-userns interoperability or the chosen 2.3.x tuple | Pin containerd, runsc and shim artifacts; prove create/start/stop/delete, task recovery and systrap on the exact selected host |
| UP-007 | [gVisor platform guide](https://gvisor.dev/docs/user_guide/platforms/) and [security introduction](https://gvisor.dev/docs/architecture_guide/intro/) | systrap is the default platform and is recommended for VM deployments relative to nested KVM in relevant circumstances | Systrap is the M0 platform candidate, not a security claim by itself | Pin the platform flag/config and independently observe the live sandbox platform; any fallback is a failed qualification |
| UP-008 | [gVisor networking](https://gvisor.dev/docs/user_guide/networking/) | gVisor Netstack provides a userspace network stack; network passthrough uses the host stack and decreases isolation | Network mode must be explicit; a rootless network helper or host passthrough must not weaken the default-deny model | Independently test IPv4/IPv6/DNS/direct-IP/loopback/metadata denials, packet counters and outer pre-uplink metadata deny |

## 3. Candidate-by-candidate documentary assessment

### Candidate A — rootful containerd + typed host supervisor

**Documentary support:** gVisor documents the `containerd-shim-runsc-v1` integration and runtime-handler configuration. Its platform guide identifies systrap as the default and describes its fit for virtual-machine deployments.

**Unresolved risks:** the supervisor becomes the one application principal allowed to access the rootful containerd socket. Containerd socket access must be treated as host-level authority. The architecture therefore depends on exact UID/GID/groups, socket parent/inode/mode, peer credentials, request authorization, capability bounding, syscall policy, writable paths, systemd hardening and exclusive process-lock fencing. No upstream quick start proves that these controls are sufficient for this application.

**Disposition:** `design-assessed` only after independent threat review; not host-qualified. Standard shim integration is documented but must still be tested at exact versions.

### Candidate B — rootless containerd + caller-configured user namespaces

**Documentary support:** containerd documents rootless daemon operation using user namespaces/RootlessKit; gVisor documents a separate caller-configured-userns path for higher-level engines; RootlessKit documents user/mount/network namespaces and subordinate-ID/helper dependencies.

**Unresolved compatibility:** the reviewed gVisor caller-userns page names Docker/Podman, while the containerd quick start separately describes the runsc shim. The documents do not explicitly establish the exact caller-configured-userns + rootless-containerd + `containerd-shim-runsc-v1` combination required here. This is a hard integration gate, not an assumed “yes.”

**Unresolved resource/network risks:** systemd rootless cgroup delegation may expose memory/pids but not CPU by default; RootlessKit's network backend, gVisor's Netstack/TAP/Slirp path, abstract host socket isolation and metadata denial need exact-host proof. `newuidmap`/`newgidmap` helpers, subordinate-ID allocation and AppArmor rules remain part of the privileged attack surface.

**Disposition:** `deferred-pending-compatibility-and-host-proof`; not rejected, not host-qualified.

## 4. Decision-impacting proof gaps

| Gap | Blocks candidate selection? | Required result |
|---|---|---|
| Exact containerd 2.3.x + runsc/shim + caller-configured userns compatibility | Yes, rootless candidate | Complete create/start/stop/delete and recovery using the exact selected versions |
| Rootless CPU controller delegation | Yes, rootless candidate | CPU/memory/PID limits independently enforced; no configured-but-ineffective controller |
| Rootless helper and namespace security | Yes, rootless candidate | Exact helper provenance/modes, mappings, private state/socket and abstract-socket isolation |
| Rootless default-deny networking and metadata isolation | Yes, both candidates | All workload paths denied and observed; metadata denial before host uplink |
| Rootful supervisor privilege minimization | Yes, rootful candidate | Exact privilege/systemd/socket inventory; no generic root broker or alternate containerd writer |
| Exact live systrap observation | Yes, both candidates | Host-side proof of systrap on the exact selected runtime build |
| Journal durability and three watchdogs | Yes, both candidates | Exact-host qualification protocol and independently verified evidence |

## 5. What this ledger does not prove

- It does not prove any rootless or rootful candidate is secure.
- It does not prove the exact Orbit Engine runtime/profile combination works.
- It does not qualify cgroups, networking, systrap, cleanup, watchdogs or journal durability.
- It does not authorize host provisioning, package installation, runtime smoke testing, destructive testing, privileged implementation, Phase A, Phase B, student or production execution.
- It does not contain a selected provider, VM shape, storage class or spend.

## 6. Source pinning and review requirements

The source URLs point to upstream documentation branch heads that can change. For a completed independent decision, the reviewer must record for each source: repository, path, exact commit SHA (or release/tag), retrieval time, archived content SHA-256, and the specific fact relied upon. A branch-head URL alone is not a reproducible evidence reference.

Capture a source snapshot only in the review evidence bundle; do not vendor full upstream documents or copy large source excerpts into this repository. The compact statements above are paraphrases with source links.

## 7. Review conclusion

**No architecture choice is made.** Existing ADR-0019 remains Proposed. The current evidence suggests Candidate A has the clearer documented containerd-shim path but carries more host-privilege concentration. Candidate B has a plausible documented building-block stack but an unproven exact gVisor-shim/userns combination and a specific CPU-delegation gate. Both require live-host proof and independent review before any M0 architecture acceptance.

Reviewed: 2026-11-10.