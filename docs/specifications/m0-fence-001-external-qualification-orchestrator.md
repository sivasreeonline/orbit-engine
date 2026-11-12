# FENCE-001 external provider qualification orchestrator

**Status:** Provider-neutral pre-review reconciliation contract. No provider is selected or qualified.
**Command:** `scripts/validate_m0_fence_external_qualification.py`
**Canonical plan schema:** `schemas/fence-001-external-qualification-plan-v2.schema.json` (JSON Schema Draft 2020-12)
**Independent trust-key schema:** `schemas/fence-001-external-qualification-trust-keys-v1.schema.json`
**Production status:** BLOCKED. This command never invokes provider adapters or performs destructive operations.

## Purpose

PRs #92–#106 establish separate contracts and validators for witness append/read semantics, immutable evidence storage, privileged-bypass behavior, restore/recovery and provider-native audit provenance. Separate execution leaves an operational gap: evidence from different runs, accounts or adapter versions could otherwise be assembled into one final package.

This orchestrator validates an operator-created run plan and re-hashes the exact materialized evidence bytes for all required subsystems. It emits only `READY_FOR_INDEPENDENT_REVIEW` when all five stage records are present and bound to one disposable qualification run. It does not call providers.

## Required stages

The plan must contain PASS evidence for:

1. `witness`: real witness adapter conformance and authenticated readback.
2. `evidence_object_store`: immutable-store conformance and independent exact-version readback.
3. `privileged_bypass`: guarded provider-native denied mutation attempts and independent audit readback.
4. `restore_recovery`: isolated disposable restore, post-restore witness re-read and monitor reconciliation.
5. `audit_provenance`: provider audit authentication and request/event correlation.

Every stage is bound to the exact `runId` and `accountId`, names the provider, and references an evidence file by safe basename, SHA-256 and byte count. The orchestrator recomputes the digest and length from bytes on disk. Missing stages, cross-run/account evidence, digest mismatches and unsupported states fail closed. The canonical JSON Schema rejects unknown fields, missing required fields, malformed identifiers/digests, invalid ISO-8601 approval expiry values and incomplete stage/attestation records before the semantic checks run.

## Shared run scope

The plan must declare and independently substantiate:

- `environment=QUALIFICATION`, `production=false`, `disposable=true`.
- An operator-pinned account, unique run ID, approval ID and explicit approval expiry.
- Approval bound to the same run ID; the plan producer must check expiry against independently trusted time before creating the plan.
- A read-only source boundary and `admissionEnabled=false`.
- Provider, account, region, service and adapter SHA-256 pins for witness, evidence store and compute.
- Distinct storage administrator, account owner, organization administrator, recovery administrator, source reader, restore operator, witness reader, collector, independent verifier, provider-approval authority and evidence-retention authority identities.
- Independently verified provider-approval, verifier and evidence-retention attestations bound to the same run/account.

The three external attestations are no longer accepted as a self-asserted `verified=true` flag. Each must carry an Ed25519 signature over an RFC 8785 canonical body with a dedicated domain-separation prefix. The body binds the attestation type, run ID, account ID, approval ID, issue/expiry times, exact attestation evidence digest/byte count and a SHA-256 digest of the shared run/identity/provider-pin scope.

Signatures are verified against a separate `--trust-keys` inventory. That inventory must be provisioned independently of the provider and evidence store; each of the three roles has a distinct active signer, key ID and Ed25519 public key. Their signer identities must also match three separately named plan principals: provider-approval authority, independent verifier and evidence-retention authority. Public-key fingerprints are recomputed. CI creates ephemeral keys only; no production trust key or private key is committed. The exact trust-inventory file bytes must also match `--expected-trust-keys-sha256`, supplied independently from a separate trusted channel. A matching set of self-consistent public-key fingerprints is not sufficient by itself: this out-of-band digest prevents wholesale trust-set substitution. The trust inventory is rejected when stored inside the materialized evidence root. The reconciliation summary records the verified trust-inventory digest.

The validator still cannot prove that a trust authority's real-world governance or statement is truthful. Trust-key governance, signer independence and administrative/failure-domain separation require independent review. The audit-provenance stage is pinned to the same compute provider identity used for privileged-bypass and restore/recovery.

## Invocation

After the five real provider harnesses have been run against approved disposable qualification resources and their raw outputs preserved:

```powershell
python scripts/validate_m0_fence_external_qualification.py `
  --plan ./qualification-plan-v2.json `
  --evidence-root ./materialized-qualification-evidence `
  --trust-keys ./independently-provisioned-qualification-trust-keys.json `
  --expected-trust-keys-sha256 <out-of-band-64-character-sha256-pin> `
  --output ./qualification-summary.json
```

Synthetic self-test (no provider calls):

```sh
python scripts/validate_m0_fence_external_qualification.py --self-test
```

Do not commit qualification plans, provider account identifiers, trust-key inventories, private keys, credentials or raw provider evidence. Keep the trust-key inventory outside the provider/evidence-store trust boundary and outside the materialized evidence root. Deliver its expected SHA-256 pin through a separate trusted channel; do not calculate and accept the pin from the same untrusted file at verification time. Use a restricted evidence directory.

## Output boundary

The strongest result is `READY_FOR_INDEPENDENT_REVIEW`. This command cannot mark independent review complete, set `productionApproval=true`, enable host admission, issue epochs or authorize execution. A successful CI self-test validates only local reconciliation logic.

Provider-native approval, object-lock configuration and retention, audit authenticity/completeness, trust-root governance, identity separation and administrative failure domains still require external verification and independent security review. Production approval remains false.
