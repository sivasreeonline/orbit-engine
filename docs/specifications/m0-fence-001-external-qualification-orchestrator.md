# FENCE-001 external provider qualification orchestrator

**Status:** Provider-neutral pre-review reconciliation contract. No provider is selected or qualified.
**Command:** `scripts/validate_m0_fence_external_qualification.py`
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

Every stage is bound to the exact `runId` and `accountId`, names the provider, and references an evidence file by safe basename, SHA-256 and byte count. The orchestrator recomputes the digest and length from bytes on disk. Missing stages, cross-run/account evidence, digest mismatches and unsupported states fail closed.

## Shared run scope

The plan must declare and independently substantiate:

- `environment=QUALIFICATION`, `production=false`, `disposable=true`.
- An operator-pinned account, unique run ID, approval ID and explicit approval expiry.
- Approval bound to the same run ID; the plan producer must check expiry against independently trusted time before creating the plan.
- A read-only source boundary and `admissionEnabled=false`.
- Provider, account, region, service and adapter SHA-256 pins for witness, evidence store and compute.
- Distinct storage administrator, account owner, organization administrator, recovery administrator, source reader, restore operator, witness reader, collector and independent verifier identities.
- Independently verified provider-approval, verifier and evidence-retention attestations bound to the same run/account.

The validator checks declarations and byte bindings. It cannot prove external attestations are truthful; their provenance, role separation and administrative/failure-domain independence must be reviewed separately.

## Invocation

After the five real provider harnesses have been run against approved disposable qualification resources and their raw outputs preserved:

```powershell
python scripts/validate_m0_fence_external_qualification.py `
  --plan ./qualification-plan.json `
  --evidence-root ./materialized-qualification-evidence `
  --output ./qualification-summary.json
```

Synthetic self-test (no provider calls):

```sh
python scripts/validate_m0_fence_external_qualification.py --self-test
```

Do not commit qualification plans, provider account identifiers, keys, credentials or raw provider evidence. Use a restricted evidence directory.

## Output boundary

The strongest result is `READY_FOR_INDEPENDENT_REVIEW`. This command cannot mark independent review complete, set `productionApproval=true`, enable host admission, issue epochs or authorize execution. A successful CI self-test validates only local reconciliation logic.

Provider-native approval, object-lock configuration and retention, audit authenticity/completeness, trust-root governance, identity separation and administrative failure domains still require external verification and independent security review. Production approval remains false.
