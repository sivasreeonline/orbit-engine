# M0 independent checkpoint custody and retention contract

## Purpose

This contract defines a custodian-signed receipt and a backend-neutral compare-and-store interface for externally signed verification-audit checkpoints. It adds a second trust assertion: a custodian claims to have accepted a specific checkpoint under a named retention policy.

The receipt binds the exact checkpoint digest, custody domain, retention policy identity/version, retained time, asserted immutability horizon, custodian principal/role/key, and detached Ed25519 signature.

## Trust separation

Checkpoint signing and custody attestation are separate roles and should be administered independently. When enabled, the verifier rejects a receipt whose custodian principal equals the checkpoint signer principal. Test fixtures use distinct signing keys. Production governance must additionally ensure distinct organizations, administrators, credentials, infrastructure, and approval paths; distinct principal strings alone do not establish organizational independence.

Custody public keys and policy are injected from outside this package. No production key, trust root, custodian identity, or policy distribution mechanism is embedded. Normal key expiry is evaluated at receipt signing time; revocation is evaluated at verification time. The caller supplies verification time.

## Receipt validation

The verifier checks:
- exact checkpoint digest and non-empty custody domain;
- exact custody policy ID/version;
- trusted custodian key ID, principal, role, and key size;
- retained timestamp within key validity and not before checkpoint creation;
- verification time not before retention time;
- immutable-until strictly after retention time and at least the policy's minimum retention duration;
- current revocation state;
- Ed25519 signature and receipt digest;
- optional principal separation from the checkpoint signer.

A receipt is a signed assertion. It does not prove that a provider actually enforced immutability, that the custody domain is independent, or that the storage is available. Those claims require independent provider evidence, audit access, fault injection, legal/operational controls, and independent qualification.

## Storage contract

`CheckpointCustodyStore` exposes `ReadLatest` and `StoreIfCurrent`. A conforming durable adapter must atomically:
1. Read and compare the current checkpoint for the ledger ID/epoch with the caller's expected predecessor digest.
2. Validate the new checkpoint's sequence, predecessor, and ledger identity against that exact current checkpoint.
3. Persist the checkpoint and matching signed custody receipt together, or persist neither.
4. Reject stale writes, same-sequence replays, forks, cross-epoch substitution, and receipt/checkpoint mismatch.
5. Make successful writes durable according to an explicitly qualified retention profile before acknowledging success.

A lost acknowledgement is an unknown outcome. Callers must re-read the exact ledger/epoch head and reconcile by checkpoint digest; they must not blindly issue a new sequence or create a fork.

## Required backend qualification

A future adapter must test concurrent writers, stale expected heads, lost acknowledgements, process termination before/during/after commit, storage unavailability, corrupted checkpoint/receipt bytes, retention-horizon enforcement, backup/restore, deletion attempts, rollback, fork attempts, and cross-region or cross-account recovery. Evidence must identify the actual provider, account/tenant, region, storage class, retention mode, policy configuration, test commands, timestamps, and independently verified outcomes.

## Explicit non-goals and gates

This is a contract and in-process receipt verifier only. It does not implement a storage adapter, WORM/object-lock configuration, replication, KMS/HSM, trusted timestamp, provider API, external monitoring, independent custodian agreement, or retention enforcement. A signed receipt does not prove the underlying storage behavior.

No database backend, host deployment, privileged execution, Phase A/B, or student workload execution is enabled or authorized.
