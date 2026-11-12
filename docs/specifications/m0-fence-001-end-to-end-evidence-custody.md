# FENCE-001 end-to-end evidence custody gate

The script scripts/validate_m0_fence_end_to_end_custody.py is the final local reconciliation command for the evidence-custody chain.

## External invocation

```sh
python scripts/validate_m0_fence_end_to_end_custody.py \
  --record /secure/qualification/qualification-record.json \
  --manifest /secure/evidence/evidence-manifest.json \
  --manifest-trusted-keys /secure/trust/evidence-manifest-keys.json \
  --audit-report /secure/audit/provider-audit-provenance-run.json \
  --audit-binding /secure/audit/audit-provenance-binding.json \
  --binding-trusted-keys /secure/trust/audit-binding-keys.json \
  --artifact-root /secure/materialized-evidence/run-123
```

The command fails closed unless the record is READY_FOR_INDEPENDENT_REVIEW, all fourteen WIT controls are PASS, and productionApproval is explicitly false. It then invokes the independent audit-provenance binding validator (manifest signatures, exact report digest, provider/verifier scope, one-to-one artifact mapping and materialized bytes) and the qualification validator (record schema/semantics, provider and adapter pins, PASS-evidence-to-manifest reconciliation and all materialized manifest bytes).

The trusted-key files must be provisioned independently of the evidence being checked. Keep private signing keys outside the evidence directory and never commit credentials, keys, provider output or qualification records.

## What a PASS means

A PASS means only that the supplied local record, signed manifest, audit report, binding envelope and materialized bytes are internally consistent under the checked-in validators. It does not establish provider truth or audit completeness, remote object-lock enforcement, trust-root governance, actual administrative/failure-domain independence, or the correctness of external provider adapters. Those require independent provider-native evidence and security review.

The gate never changes productionApproval, enables host admission, or authorizes execution. CI runs synthetic fixtures only.
