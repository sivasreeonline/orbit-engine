# FENCE-001 AWS STS caller identity evidence

**Status:** Injected read-only verifier with synthetic clients. No live AWS identity qualification.  
**Implementation:** `scripts/aws_sts_caller_identity.py`  
**Tests:** `scripts/test_m0_fence_aws_sts_caller_identity.py`

## Purpose

The CloudTrail and S3 adapters accept injected clients. This slice adds an explicit preflight that verifies the actual caller identity returned by AWS STS against the expected AWS account and IAM role before those clients are used for provider qualification.

## Checks

- Requires a 12-digit expected AWS account ID.
- Requires a supported IAM role ARN in the same account.
- Calls only the injected STS client's `GetCallerIdentity`.
- Requires the returned account and partition to match the pinned scope.
- Requires the caller ARN to be an assumed-role principal, not an IAM user or root principal.
- Requires the assumed role name to match the pinned IAM role name.
- Requires the `UserId` session suffix to match the assumed-role ARN session name.
- Requires the STS response RequestId for the evidence record.
- Emits a structured report containing the expected role ARN, actual caller ARN, account, session, UserId and request ID.

The verifier does not discover credentials, create sessions, assume roles or switch identities. The caller supplies an already-configured STS client.

## Important limitation

A single successful GetCallerIdentity result proves which principal made that one STS call, but it does not prove that the collector and independent verifier use different principals. Production FENCE-001 qualification must collect separate STS identity evidence through separately governed clients and require distinct allowed roles before dual-signing the manifest.

The returned RequestId is provenance metadata, not a cryptographic AWS response signature. Transport security and the caller's AWS SDK trust chain remain part of the environment qualification.

## Synthetic validation

CI uses an injected fake STS client. It checks a valid assumed-role identity and rejects:
- wrong AWS account;
- unexpected assumed role;
- IAM user principal;
- missing RequestId;
- expected role ARN in a different account;
- non-boolean testOnly report classification.

No AWS account, credentials, network access or provider API calls are used.

## Dual-principal manifest binding

The manifest extension adds `AWS_STS_CALLER_IDENTITY` artifacts and CT-009. The identity-manifest validator requires exactly two separately captured reports:
- `COLLECTOR`
- `INDEPENDENT_VERIFIER`

Both reports must match the signed manifest account and test-only classification. Each must include the expected IAM role ARN, actual assumed-role ARN, UserId/session binding and STS RequestId. The validator rejects a shared IAM role, shared caller ARN, shared request ID, malformed identity or tampered report bytes.

This proves distinct role identities were reported and bound into the signed manifest. It does not prove the two STS clients were operated by separate human operators or separate administrative control planes; those governance controls remain external qualification requirements.
