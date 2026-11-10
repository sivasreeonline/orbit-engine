# M0 Sandbox Security Review Packet

- Status: Prepared for independent review; **not reviewed or approved**.
- Scope: M0 disposable-host gVisor proof harness only.
- Related: ADR-0018, M0 host runbook, adversarial fixture contract, runtime proof harness design, and evidence schema.
- Release boundary: `UnconfiguredExecutor` remains active; no student execution, cloud provisioning, or production approval.

## 1. Review objective

Obtain an independent assessment of whether the proposed M0 proof environment and harness can safely test hostile synthetic workloads without exposing the host, credentials, network, or unrelated workloads.

The reviewer must assess both the design and the actual implementation/evidence when available. Reading this packet alone is not a security certification.

## 2. Assets and security objectives

| Asset | Security objective |
|---|---|
| Host root and kernel | Workload cannot obtain host privilege or compromise host integrity |
| containerd daemon and socket | Only a narrowly authorized host boundary can request approved lifecycle operations |
| Runner and supervisor credentials | Never enter the sandbox, fixture image, logs, or evidence bundle |
| Runtime images and fixture catalog | Immutable, provenance-verified, reviewed, and allowlisted |
| Source artifacts and test bundles | Opaque references, least privilege, integrity checked; hidden tests never exposed to workload unless the approved judge contract requires it |
| Host filesystem, devices, namespaces | No unintended visibility, writes, mounts, or device access |
| Network and cloud metadata | No workload egress or access to host/metadata control planes |
| CPU, memory, PIDs, disk, output | Hard bounded per sandbox and by outer VM-level controls |
| Process tree, mounts, namespaces, scratch | Fully terminated and removed before terminal acknowledgement |
| Evidence and audit records | Complete, integrity-verifiable, sanitized, access-controlled, and tamper-evident |

## 3. Threat actors and assumptions

### Threat actors

- Malicious student program intentionally crafted to escape the sandbox.
- Compromised or malicious fixture/image publisher.
- Buggy or compromised runner, coordinator, or host supervisor.
- Attacker with access to a control-plane credential or queue message.
- Compromised dependency, base image, runtime package, or build pipeline.
- Host operator or cloud account compromise.

### Explicit assumptions requiring verification

- The disposable VM is dedicated to the proof and contains no production credentials or student data.
- The host outer cgroup and watchdog are outside the sandbox and cannot be disabled by the guest.
- Containerd and runsc packages come from trusted, integrity-verified sources.
- The actual running daemon configuration is identified, not inferred from a local config file alone.
- Systrap is independently observed on the running sandbox.
- The host network is default-deny for workload egress and has no alternate route to public networks or metadata services.
- Evidence collection does not trust guest-reported security state as sole proof.

If an assumption cannot be demonstrated, record it as an open risk, not as a control.

## 4. Threat and control review matrix

| Threat | Required controls | Evidence reviewer should demand | Current disposition |
|---|---|---|---|
| Arbitrary OCI configuration / privileged launch | Typed allowlisted supervisor API; root-owned immutable profiles; reject unknown fields | API schema, authorization tests, negative tests for every forbidden field | Open: launch boundary not selected/implemented |
| Containerd socket compromise | Root-owned private Unix socket; no runner or guest access | Socket permissions, peer access tests, process/mount inspection | Design requirement only |
| Supervisor socket impersonation / request abuse | Root-owned non-writable socket parent; kernel peer credentials; per-attempt authorization; strict bounded parser; no FD passing | Socket inode/owner/mode checks, wrong-UID/GID tests, malformed/oversized/duplicate-key request tests, unauthorized-attempt tests | Design requirements added; not implemented |
| Privileged supervisor compromise | Minimal capability/syscall/writable-path surface; tested systemd hardening; no generic containerd proxy; independent review | Effective unit and process evidence, capability inventory, negative API tests, threat analysis of rootful socket authority | Open high-risk design gate |
| Host mount or device exposure | No arbitrary bind mounts/devices; fixed minimal mount profile | Effective OCI spec and host-side namespace/mount inventory | Not proven |
| Runtime platform fallback | Explicit systrap profile and fail-closed platform assertion | Runtime-reported platform plus independent host-side evidence | Not proven |
| Network egress / metadata access | Default-deny IPv4/IPv6, DNS, direct IP, loopback-to-host, metadata | Host firewall counters, packet capture, controlled sentinel tests | Not proven |
| Kernel/runtime escape | Supported patched kernel, pinned gVisor, least privilege, disposable VM | Version/provenance, security advisories, threat review, adversarial test evidence | Residual risk remains |
| Resource exhaustion | Per-sandbox cgroups plus independent outer VM cgroup/watchdog | cgroup counters/events, watchdog logs, VM health evidence | Not proven |
| Filesystem traversal / symlink race | Read-only base, isolated scratch, safe path handling, no host bind mounts | Host sentinel hashes and mount inventory before/after | Not proven |
| Image or fixture substitution | Immutable digest, signature/provenance verification, registry allowlist | Signature verification result, digest, provenance and source revision | Requirement only |
| Secret leakage | No credentials in OCI env/mounts; inert canaries; log redaction | Host-side canary scan, env/mount policy, evidence review | Not proven |
| Output/log flooding | Independent stdout/stderr ceilings; bounded storage; safe log encoding | Byte counters, artifact sizes, truncation/termination assertions | Not proven |
| Cancellation race / orphan process | External watchdog, process-tree termination, cleanup-before-ack | Host process/task/cgroup inventory after each cancellation race | Not proven |
| Duplicate delivery / duplicate result | Durable idempotency key and one terminal result per attempt | Concurrent duplicate delivery tests and persistent result assertions | Control-plane integration pending |
| Supervisor/host restart | Durable journal and reconciliation of all non-terminal resources | Fault-injection logs and post-restart host inventory | Not implemented |
| Crash between journal writes and containerd side effects | Persist intent before side effect; deterministic resource identity; reconcile before retry; compare-and-set terminal state | Fault injection at every lifecycle transition, durable journal inspection, containerd/process/cgroup inventory | Design contract added; not implemented |
| Cleanup acknowledgement race | Cleanup independent of client connection; verify process/task/shim/cgroup/namespace/mount/network/scratch absence before terminal success | Post-ack host inventory and cancellation/exit/timeout race tests | Design contract added; not implemented |
| Evidence tampering / incomplete evidence | SHA-256 manifest, access controls, independent reviewer, incomplete status on missing evidence | Manifest validation, hash verification, reviewer signoff | Schema exists; actual evidence absent |
| Dependency/runtime supply-chain compromise | Lockfiles, CI audit, pinned actions/runtime artifacts, provenance verification | CI reports, SBOM/provenance, patch process | Partial; runtime provenance not yet demonstrated |

## 5. Required independent review questions

The reviewer must explicitly answer each item:

1. Can an untrusted caller cause the privileged launch boundary to create arbitrary OCI settings, mounts, devices, namespaces, network access, or runtime binaries?
2. Can the Go runner or any guest process obtain access to the containerd socket or host supervisor authority?
3. Is the actual daemon configuration and runtime handler proven, including imported configuration and matching shim?
4. Is systrap proven on the live sandbox rather than merely configured?
5. Can IPv4, IPv6, DNS, direct-IP, loopback-to-host, or metadata traffic escape by any alternate interface or route?
6. Are all resource ceilings hard limits at both sandbox and outer VM levels?
7. Can any failure path leave an orphan task, process, shim, namespace, mount, scratch directory, or writable artifact?
8. Are cancellation, timeout, restart, duplicate delivery, and cleanup races safe and idempotent?
9. Can logs or evidence expose source, hidden test material, credentials, raw daemon command lines, or private URLs?
10. Are image signatures, package provenance, dependency versions, and update/rollback procedures sufficient?
11. What residual risks remain because gVisor shares the host kernel and because the supervisor privilege boundary is not yet implemented?
12. What exact conditions must be met before integration testing, and which conditions still block production?
13. Can a runner identity spoof or bypass Unix peer-credential checks, socket-path ownership checks, per-attempt authorization, or request framing limits?
14. Can a supervisor crash at every journal/containerd boundary cause duplicate launch, lost ownership, false terminal success, or orphaned resources?
15. Is the supervisor's effective privilege set genuinely minimal, and does its systemd hardening preserve only the required containerd operations?

Every answer must cite evidence or remain marked unresolved.

## 6. Mandatory stop / reject conditions

Reject the proof design or stop testing if any of the following occurs:

- Any successful forbidden network flow or metadata response.
- Any host mount, device, privileged socket, credential, or host namespace exposure.
- Any unexplained runtime platform or version mismatch.
- Any resource limit that is best-effort, unbounded, or not independently measured.
- Any surviving process/task, mount, namespace, or scratch resource after terminal acknowledgement.
- Any duplicate terminal result or scoring of an infrastructure failure as a student verdict.
- Any evidence containing secrets, student source, hidden test content, or unredacted daemon environment/command lines.
- Any missing, inconsistent, or unverifiable evidence for a required fixture.
- Any unreviewed change to the host baseline, runtime, fixture image, supervisor API, or security profile.

## 7. Reviewer deliverables

The independent reviewer should produce:
- Scope, versions, commits, image digests, and evidence bundle hashes reviewed.
- Threat model and trust-boundary assessment.
- Findings with severity, affected component, exploit preconditions, impact, reproduction evidence, and remediation.
- Explicit residual-risk register and accepted-risk owner.
- Pass/fail/conditional decision for M0 proof readiness.
- Separate decision on whether integration testing may begin.
- Reviewer identity, date, and signed approval record.

A pass for disposable-host proof does not constitute production approval. Production execution requires a separate security review after the real host, supervisor, runtime, and operational controls have been implemented and tested.

## 8. Current decision

**Independent review: pending.** No reviewer signoff is recorded. No cloud host has been selected or provisioned. No sandbox workload has been launched. No executor activation is authorized.
