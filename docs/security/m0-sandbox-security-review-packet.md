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
| Runner restart during active attempt | Supervisor-owned lifecycle remains independent; reconnect/retry is idempotent and cannot create a duplicate | Runner restart fault-injection evidence, durable attempt identity, one task and one terminal result | Not implemented |
| Supervisor restart during each lifecycle phase | Durable journal reconciles intent and observed host state; ambiguous ownership quarantines host | Fault-injection logs and post-restart process/task/container/shim/namespace/cgroup/mount/scratch/network inventory | Not implemented |
| Containerd daemon restart or outage | Stop new launches and reconcile all non-terminal attempts after daemon recovery | Daemon identity/version checks and post-recovery inventory prove no duplicate or orphan resource | Not implemented |
| Crash between journal writes and containerd side effects | Persist intent before side effect; deterministic resource identity; reconcile before retry; compare-and-set terminal state | Fault injection at every lifecycle transition, durable journal inspection, containerd/process/cgroup inventory | Design contract added; not implemented |
| Cleanup acknowledgement race | Cleanup independent of client connection; verify process/task/shim/cgroup/namespace/mount/network/scratch absence before terminal success | Post-ack host inventory and cancellation/exit/timeout race tests | Design contract added; not implemented |
| Snapshot rollback / cloned host split-brain | External authority atomically advances a monotonic host-incarnation epoch only after provider-enforced fencing of every predecessor; restore remains quarantined until authenticated epoch/fence evidence is durably accepted | Complete predecessor/clone enumeration, authority key pin and nonce binding, provider-enforced compute/storage/control-path isolation, fence-before-issue chronology, concurrent restore/rollback fault injection | Design contract added; authority/provider not selected or implemented |
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
8. Are cancellation, timeout, runner restart, supervisor restart at each lifecycle phase, containerd daemon restart, duplicate delivery, and cleanup races safe and idempotent? Are the three restart scenarios independently evidenced?
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

## 7. Independent review checklist and decision record

Use `docs/security/m0-independent-security-review-checklist.md` as the controlled reviewer workbook, `docs/security/m0-independent-security-review-record.schema.json` as the machine-readable schema, and `docs/security/m0-independent-security-review-record.template.json` as the blank evidence-bound decision record.

The record starts as `not-reviewed`. Every finding has a stable control ID, evidence class, verification method, severity, remediation owner and immutable evidence references. Host/runtime controls cannot pass based on documentation, CI or schema tests alone.

The record may recommend an architecture candidate and separately record recommendations for implementation, Phase A and Phase B. It hard-codes actual privileged implementation, Phase A, Phase B, student and production authorization flags to `false`; any real authorization requires its own separately reviewed process/artifact.

Compare rootful supervisor and rootless containerd with caller-configured user namespaces against the same control register. Do not conflate the `runsc --rootless` CLI mode with caller-configured user namespaces.

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

## 8. Phase A calibration review requirements

Phase A is a limited cleanup-deadline calibration campaign. It requires an explicit review decision separate from any later approval for the full 35-fixture M0 proof. A reviewer must not infer Phase A authorization from this packet's existence, passing CI, or a passing read-only preflight.

### Required Phase A approval evidence

The independent reviewer must verify and record:

1. Dedicated disposable VM identity and evidence that no student data, production credentials, API secrets, or unrelated tenants are present.
2. Exact VM image, kernel, filesystem, containerd, runsc, shim, supervisor, journal, watchdog, calibration image, and scenario-bundle digests/versions.
3. Independently enforced outer VM CPU, memory, PID, disk, and wall-time ceilings, plus a hard-stop/rebuild path outside the supervisor/journal/containerd failure domain. The outer cutoff is a safety limit only; firing it is a failed/unverified cleanup sample.
4. Default-deny network containment and independent evidence that all workload egress, including metadata link-local traffic, is blocked before host uplink. No metadata request is made by the host or accepted by the proof harness.
5. The candidate journal backend has passed its separate exact-host durability, power-loss, disk-full, corruption, restore, and lock/fencing gates before it is used by calibration.
6. Fixed, source-reviewed, digest-pinned synthetic calibration scenarios; a strict scenario allowlist; no arbitrary source/command/OCI input; no network callback; and no student or hidden-test material.
7. The calibration control path is not exposed through public HTTP, the student API, a general execution endpoint, or the ordinary job queue. It is restricted to the exact signed/approved run manifest.
8. The measurements exercise the same cleanup controller, journal, and host-side absence verifier proposed for M0. Any mock, bypass, or alternate cleanup path invalidates the measurements.
9. The first-trigger monotonic timestamp and boot identity are captured before or at termination; repeated triggers and restarts cannot reset the clock; evidence-store and journal failures cannot delay termination.
10. Cleanup and evidence dispositions are independently supervised and persisted. Any uncertain cleanup, unowned resource, failed outer guard, network uncertainty, clock ambiguity, or evidence leak stops the campaign and quarantines the VM.

### Calibration decision and Phase B separation

The Phase A decision must be recorded as one of: not authorized, authorized with explicit constraints, or rejected. It must include the reviewer, date, scope, host/build digests, scenario allowlist, outer safety cutoff, maximum run count, stop conditions, evidence destination, and expiry. Authorization is invalidated by a change to the host image, kernel, runtime, journal, supervisor, watchdog, fixture digest, network boundary, or material configuration. The authorization manifest must conform to docs/schemas/m0-cleanup-calibration-authorization.schema.json. Its signature reference and evidence hashes must be independently resolved and verified; passing JSON Schema validation does not authenticate the reviewer or prove the host controls.

Phase A results must include raw sanitized trigger-to-verified-cleanup measurements, phase breakdown, outliers, host envelope, uncertainty sources, and the rationale for any candidate engineering margin. Percentiles are descriptive; a p95 or p99 is not a hard deadline. Any sample terminated by the outer VM cutoff or lacking independent absence verification is failed/unverified and cannot support the candidate maximum.

Phase B approval is a separate reviewer decision. It requires approval of the candidate numeric cleanup deadline, evidence/terminal-finalization reserve, original 10-minute admission rule, clock/reboot semantics, watchdog independence, exact resource-profile revision, and Phase A raw evidence. Only then may the full 35-fixture adversarial campaign begin. Neither decision authorizes student or production execution.

## 9. Current decision

**Independent review: pending.** The controlled checklist and machine-readable decision template are available, but no reviewer signoff is recorded. No cloud host has been selected or provisioned. No sandbox workload has been launched. No executor activation is authorized. Passing CI is not a security review or approval.


## ADR-0019 candidate decision

Use `docs/adr/ADR-0019-decision-dossier.md` and `docs/schemas/m0-adr-0019-decision-record.schema.json` for the rootful-versus-rootless candidate decision. The reviewer must assess both candidates against the same 33 controls and 33 host qualification tests. A candidate selection requires its own complete host qualification report and independent sign-off; evidence cannot be borrowed from the other candidate.

The review remains pending. The dossier and its synthetic CI examples are not security approval or host proof.


## Upstream candidate compatibility evidence

Review `docs/adr/ADR-0019-upstream-compatibility-evidence.md` alongside the independent 33-control checklist. The rootless review must explicitly address `newuidmap`/`newgidmap`, subordinate-ID mappings, RootlessKit state/network namespaces, systemd CPU-controller delegation and exact gVisor shim compatibility. Documentary sources do not constitute host proof.


## Immutable upstream source baseline

The immutable upstream source set is recorded in `docs/adr/ADR-0019-upstream-source-manifest.json`; the exact manifest SHA-256 must be embedded in any completed ADR-0019 decision record. A reviewer must check the eight source pins and recorded signature-verification status. The branch-head URLs are discovery references only; the manifest points to immutable commit URLs and records Git blob SHA-1 plus content SHA-256.
