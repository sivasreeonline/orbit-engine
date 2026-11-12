# FENCE-001 provider-side restore and recovery adapter contract

**Status:** Provider-neutral qualification harness. No provider is selected or qualified.
**Harness:** `scripts/validate_m0_fence_provider_restore_recovery.py`.
**Production status:** BLOCKED. External mode is restricted to a disposable, isolated qualification restore target.

## Purpose

The existing restore reconciliation model is deterministic and test-only. This adapter contract defines the provider-facing sequence needed to qualify a real restore path without writing the source authority database:

1. Read an immutable, digest-verified qualification snapshot through a source-reader identity.
2. Create a disposable restore target isolated from the source.
3. Fetch a strong-read witness high-water, the complete checkpoint chain, trust/revocation state and independent monitor heads.
4. Validate contiguous generation/predecessor links and proof-status gates before restore.
5. Restore the snapshot and replay only the verified missing generations into the isolated target.
6. Independently read the restored target, re-read the witness through the strong-read path and re-read independent monitor heads.
7. Require exact agreement and keep admission disabled.

## Mandatory preflight

External mode requires the exact opt-in value:

`FENCE_ENABLE_PROVIDER_RESTORE_TESTS=I_UNDERSTAND_THIS_RUN_RESTORES_A_DISPOSABLE_QUALIFICATION_TARGET`

It also requires a pinned qualification account, unique run ID, provider adapter factory and snapshot ID. Before provider restore calls, the provider scope must assert:

- `environment=QUALIFICATION` and `production=false`;
- a disposable account and read-only source boundary;
- a non-empty provider restore approval ID explicitly bound to this run ID and not expired;
- distinct source-reader, restore-operator, witness-reader and independent-verifier principals.

The provider must enforce these boundaries independently of the harness. The source snapshot must be immutable and its bytes must hash to the declared digest. The target must be disposable, isolated from the source, bound to the same account/run, and independently report host admission disabled both before and after restore.

## Adapter operations

The adapter implements:

- `describe_qualification_scope()`
- `read_source_snapshot(snapshot_id, reader_principal_id=...)`
- `create_disposable_restore_target(run_id)`
- `fetch_verified_recovery_bundle(snapshot, witness_reader_principal_id=..., independent_verifier_principal_id=...)`
- `restore_and_replay(target, snapshot, bundle, restore_operator_principal_id=...)`
- `read_restored_high_water(target, independent_verifier_principal_id=...)`
- `read_admission_state(target, independent_verifier_principal_id=...)`
- `read_latest_witness(witness_reader_principal_id=...)`
- `read_monitor_heads(independent_verifier_principal_id=...)`

The bundle must report a verified strongly consistent latest read, a verified protected-source-to-witness consistency proof when the witness is ahead, verified checkpoint artifacts/signatures, monotonic trust and revocation state, and at least two monitor observations with distinct monitor identities, operators, accounts and failure domains. Every checkpoint must form one exact contiguous predecessor chain terminating at the exact witness generation/digest.

Proof and signature statuses are inputs from provider/cryptographic verifier layers; this harness does not implement cryptographic verification. The external adapter must not translate stale replica reads into `VERIFIED`.

## Synthetic CI

Run without provider calls:

```sh
python scripts/validate_m0_fence_provider_restore_recovery.py --self-test
```

CI exercises a successful isolated replay and rejects stale latest reads, witness rollback, a predecessor fork, monitor lag, production scope, a writable source and an approval not bound to the run ID.

## External qualification invocation

```sh
FENCE_ENABLE_PROVIDER_RESTORE_TESTS=I_UNDERSTAND_THIS_RUN_RESTORES_A_DISPOSABLE_QUALIFICATION_TARGET \
FENCE_EXPECTED_QUALIFICATION_ACCOUNT_ID=<approved-account-id> \
FENCE_QUALIFICATION_RUN_ID=<unique-run-id> \
FENCE_PROVIDER_RESTORE_FACTORY=provider_adapter.module:create_adapter \
python scripts/validate_m0_fence_provider_restore_recovery.py --snapshot-id <immutable-qualification-snapshot-id>
```

The provider adapter and credentials are supplied out-of-band. The report path may be set with `FENCE_RESTORE_REPORT_PATH`; existing reports are never overwritten. Do not commit provider credentials, source snapshots, raw evidence or account identifiers.

## Success and non-claims

Success means the adapter restored/replayed the declared checkpoint range into the disposable target, an independent verifier read back the exact witness high-water, a post-restore strong witness read matched, and independent monitor observations remained consistent. The harness requires the target's admission-disabled state before restore and independently re-reads it after restore; the report explicitly keeps `admissionEnabled=false`.

This does not prove provider audit authenticity, account ownership, actual monitor administrative independence, provider durability, production restore behavior, cryptographic correctness beyond the adapter's asserted verifier results, or safe host admission. The report is not a dual-signed evidence manifest. Raw provider evidence must still be packaged through the FENCE-001 manifest process and independently reviewed. No production approval is granted.
