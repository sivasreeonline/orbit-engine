# M0 signed verification audit checkpoints

## Purpose

This specification defines a backend-neutral contract for externally signed checkpoints of the verification audit ledger. A checkpoint binds a ledger incarnation and exact audit-chain head to a policy version, timestamp, signer identity, and detached Ed25519 signature.

A signature proves that the trusted key signed the checkpoint payload. It does not prove that the checkpoint is the newest checkpoint, that the audit ledger is complete, or that the signer acted independently. Those properties require external governance and independently retained checkpoints.

## Payload and canonicalization

The signed payload contains:

- `ledger_id` and `ledger_epoch`: stable ledger identity and incarnation.
- `sequence` and `record_sha256`: exact audit-chain head.
- `created_at`: RFC 3339 timestamp asserted by the checkpoint signer.
- `previous_checkpoint_sha256`: digest of the immediately preceding accepted checkpoint; empty only for the first checkpoint of an epoch.
- `policy_version`: exact trust-policy version under which the checkpoint was produced.

The implementation signs UTF-8 JSON produced from the Go payload struct in declaration order, with the standard Go `encoding/json` rules. The signature input is a JSON object containing the payload and signer principal, role, and key ID. The checkpoint digest is SHA-256 over the complete checkpoint JSON with `checkpoint_sha256` blank. Cross-language implementations MUST reproduce this representation byte-for-byte; a future format version must be introduced for any canonicalization change.

## Trust policy

The verifier receives its trust policy from outside this package. Each trusted key binds a key ID, principal, required role, Ed25519 public key, validity interval, and optional revocation time. The package contains no production trust roots, default key IDs, key-distribution endpoint, or private key.

- The key must be valid at the checkpoint's signing time.
- Expiry is evaluated at signing time, so a historical signature remains verifiable after normal key expiry.
- Revocation is checked at verification time and invalidates signatures at/after the policy's revocation instant.
- The checkpoint policy version must equal the verifier's selected policy version.
- Optional distinct-signer policy requires the next checkpoint signer principal to differ from its predecessor signer.

The verifier's `verifiedAt` input is supplied by the caller. This contract does not provide a trusted clock or timestamp authority.

## Monotonicity, rotation, and recovery

For the first checkpoint in a ledger epoch, the predecessor digest must be empty. Every later checkpoint must:

1. Preserve ledger ID and epoch.
2. Advance the audit sequence strictly beyond the previous checkpoint sequence.
3. Link to the digest of the exact previously accepted checkpoint.
4. Have a timestamp no earlier than its predecessor.
5. Satisfy the configured signer-separation rule.

Checkpoint rotation is a trust-policy operation: publish the new key and its validity/revocation metadata through an independently authenticated policy channel before relying on it. During recovery, retrieve the latest checkpoint from an independently controlled retention location, verify its signature and policy, then require the restored ledger to match its ledger ID, epoch, sequence, and record digest. Never accept a lower sequence, alternate predecessor, or new epoch solely because a local ledger requests it. Starting a new epoch requires a separately authorized recovery decision and a retained cross-epoch transition record; this package does not define that authority.

A previous checkpoint passed to the validator must already have been independently retained and verified. This function does not recursively establish the trustworthiness of an unverified checkpoint history.

## Required qualification cases

- Valid initial checkpoint and valid successor.
- Payload tampering, signature corruption, digest corruption.
- Unknown key, principal mismatch, wrong role, invalid key validity interval.
- Revocation effective before verification.
- Historical signature after key expiry remains valid when not revoked and otherwise within policy.
- Policy-version mismatch, stale checkpoint, future timestamp.
- Ledger ID or epoch substitution.
- Sequence rollback, same-sequence replay, predecessor mismatch, alternate fork.
- Timestamp rollback and optional same-signer rejection.
- Rotation between two independently trusted keys.

## Explicit non-goals and gates

This is a contract and in-process verifier only. It does not implement key custody, HSM/KMS integration, policy distribution, checkpoint persistence, WORM storage, replication, trusted timestamps, external custodian procedures, recovery authorization, or a production trust root. Ed25519 test keys are test fixtures only. A signed checkpoint is not immutable evidence and does not independently prove that no later checkpoint exists.

No database adapter, host deployment, privileged execution, Phase A/B, or student workload execution is authorized by this specification.
