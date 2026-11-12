# FENCE-001 provider-side privileged-bypass adapter contract

**Status:** Provider-neutral executable contract. No provider is selected or qualified.
**Harness:** `scripts/validate_m0_fence_provider_privileged_bypass.py`.
**Production status:** BLOCKED. Never execute this harness against production evidence or a production account.

## Why this layer exists

The isolation attestation validator checks declared evidence. This harness moves the seven privileged mutation attempts to a provider adapter and requires provider-native responses plus independent audit-event readback. It also verifies that the exact retained bytes remain unchanged before and after the attempts.

The harness is intentionally separate from the ordinary object-store adapter. It requires role-specific privileged credentials and submits mutation requests that must be denied. It is not a safe generic smoke test.

## Mandatory execution guard

External mode refuses to call the adapter unless all of the following hold:

- `FENCE_ENABLE_PRIVILEGED_BYPASS_TESTS` equals the exact opt-in string `I_UNDERSTAND_THIS_RUN_SUBMITS_PRIVILEGED_MUTATION_REQUESTS`.
- `FENCE_EXPECTED_QUALIFICATION_ACCOUNT_ID` pins the one approved isolated account.
- `FENCE_QUALIFICATION_RUN_ID` is a safe unique run identifier.
- `FENCE_PROVIDER_PRIVILEGED_BYPASS_FACTORY` names the provider adapter factory.
- `--output-dir` points to a new or empty restricted evidence directory.
- The adapter's provider-native preflight reports environment `QUALIFICATION`, `production=false`, a disposable account, a non-empty approval ID, an approval explicitly bound to the same qualification run ID, an approved destructive-test window and unexpired approval.
- Storage administrator, account owner, organization administrator, recovery administrator and independent verifier are distinct principals.
- The adapter creates a disposable retained target bound to the pinned account and run ID, with compliance retention extending at least seven days from the run start.

Any missing, mismatched or expired preflight value fails closed before privileged mutation attempts. The provider adapter must independently enforce the same target/account restrictions; harness checks are not a substitute for provider-side authorization boundaries.

## Adapter contract

The factory returns an object implementing these operations:

1. `describe_qualification_scope()`: provider-native account/environment/approval state and role principal IDs.
2. `create_disposable_retained_target(run_id, retention_until)`: creates one run-bound disposable object version under compliance retention.
3. `read_exact_version(target, reader_principal_id=...)`: exact-version bytes read using the independent verifier.
4. `attempt_privileged_bypass(action, target, attempt_id=...)`: submits exactly one action through the designated privileged role's separately provisioned credentials.
5. `read_audit_event(event_id, reader_principal_id=...)`: independently retrieves the provider-native audit event as raw bytes.

The seven actions are the same mandatory actions defined in the evidence-isolation specification. Each response must bind action, actor, request ID, audit event, timestamp and the exact object/version. The independent audit event must match those values. The harness hashes and writes each raw audit event to the output directory. It then re-reads the exact retained version and requires byte-for-byte equality with the pre-attempt read.

The harness does not automatically delete the qualification object: compliance retention is expected to prevent deletion, and a cleanup path must not weaken that property. Operators must account for storage cost and retention expiry when approving a run.

## Running

Synthetic harness self-tests (no provider calls):

```sh
python scripts/validate_m0_fence_provider_privileged_bypass.py --self-test
```

External provider execution (example; use only an approved disposable account):

```sh
FENCE_ENABLE_PRIVILEGED_BYPASS_TESTS=I_UNDERSTAND_THIS_RUN_SUBMITS_PRIVILEGED_MUTATION_REQUESTS \
FENCE_EXPECTED_QUALIFICATION_ACCOUNT_ID=<approved-account-id> \
FENCE_QUALIFICATION_RUN_ID=<unique-run-id> \
FENCE_PROVIDER_PRIVILEGED_BYPASS_FACTORY=provider_adapter.module:create_adapter \
python scripts/validate_m0_fence_provider_privileged_bypass.py --output-dir /secure/restricted/fence-run
```

The provider adapter and credentials are supplied out-of-band. Never commit credentials, secrets, production account IDs or raw audit artifacts to this repository.

## Output and qualification boundary

The output directory contains `provider-privileged-bypass-run.json` and one raw audit artifact per action. These are collection outputs, not a FENCE-001 isolation attestation or dual-signed evidence manifest. The independent collector/verifier must package them with provider-native request/response evidence, account and role identity evidence, monitor independence evidence and the existing signed manifest workflow.

A successful harness run establishes only that this adapter execution returned seven denied results, the independent reader retrieved matching audit records, and exact-version bytes remained unchanged during the run. It does not independently prove provider audit authenticity, account ownership, role assignment, WORM enforcement outside the tested operations, independent administrative domains, retention-bypass resistance across every recovery path, remote durability or production suitability. Independent review remains mandatory; production approval remains blocked.
