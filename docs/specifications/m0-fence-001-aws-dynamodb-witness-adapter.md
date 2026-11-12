# FENCE-001 AWS DynamoDB witness adapter

**Status:** Implemented adapter surface with synthetic DynamoDB API tests. No AWS account or resource is connected.
**Adapter:** \`scripts/aws_dynamodb_witness_adapter.py\`
**Shared contract:** \`scripts/validate_m0_fence_witness_provider_adapter_conformance.py\`
**Live mode:** Disabled by default; explicit operator opt-in and run-bound local approval required.
**Qualification status:** NOT QUALIFIED. Production approval remains false.

## 1. Design

The adapter implements the existing provider-neutral \`WitnessAdapter\` interface using one DynamoDB table with a string partition key \`PK\` and string sort key \`SK\`.

For each logical witness scope, the partition key is:

\`SCOPE#SHA256(JCS({trustDomainId,witnessId,authorityId,hostId}))\`

The table uses four record types:

| Sort key | Purpose | Mutation rule |
|---|---|---|
| \`HEAD\` | Current high-water checkpoint and receipt | Replaced only by one successful conditional transaction comparing the expected predecessor |
| \`GEN#<20-digit-generation>\` | Immutable checkpoint generation | Insert-only; existing generation rejects a second write |
| \`OP#<SHA256(operationId)>\` | Immutable exact operation lookup | Insert-only; operation IDs cannot be reused |
| \`IDEMP#<SHA256(idempotencyKey)>\` | Durable retry binding | Insert-only; binds the caller's idempotency key to exact canonical checkpoint bytes and the original receipt |

All four writes occur in a single \`TransactWriteItems\` call. The HEAD write uses a conditional compare of the exact expected generation and checkpoint digest. Genesis requires the HEAD item to be absent. All other records use \`attribute_not_exists(PK)\` as insert-only guards.

The adapter's only read method is DynamoDB \`GetItem\` against the base table with \`ConsistentRead=True\`. It does not use a GSI, stream, cache or eventual read as the authoritative high-water or operation lookup.

## 2. Idempotency and ambiguous transactions

The adapter derives a deterministic UUIDv4-shaped \`ClientRequestToken\` from the scope and caller idempotency key. This makes the native request token stable for retries with identical inputs. DynamoDB's native transaction idempotency window is only ten minutes, so the adapter does **not** depend on that window for long-lived replay protection.

The separate \`IDEMP#\` record is stored in the same atomic transaction as the checkpoint. It has no TTL. A retry first performs a strongly consistent read of that durable item:

- same idempotency key + same canonical checkpoint bytes: return the original receipt without a second transaction;
- same idempotency key + different checkpoint bytes: reject with \`IdempotencyConflict\`;
- a different idempotency key for an existing operation ID: reject;
- stale predecessor or competing successor: reject with \`AppendConflict\`.

If a network timeout makes the transaction outcome ambiguous, the adapter raises \`AmbiguousCommit\` and requires the caller to retry the exact checkpoint and exact idempotency key. It never invents a replacement generation or key.

The receipt's \`consistencyToken\` is explicitly labelled as a DynamoDB client-token correlation handle. It is **not** an independently verified consistency proof. Strong consistency derives from DynamoDB's transaction condition and the subsequent \`ConsistentRead=True\` readback. The existing cryptographic witness-receipt profile still requires an independently verified, provider-specific consistency proof before trusting a production receipt.

## 3. Scope and account boundaries

DynamoDB transactions cannot span accounts or Regions. Therefore the witness table, HEAD and immutable operation records must remain in one explicitly pinned qualification account and one Region. A design requiring a transaction across accounts/Regions is not implemented here.

The live factory additionally checks:
- exact operator-pinned AWS account ID;
- run ID, Region, table name and full table ARN;
- a matching local read-only preflight report;
- a short-lived approval file bound to the exact preflight report SHA-256 and table ARN;
- STS caller account and live \`DescribeTable\` result;
- ACTIVE table state and exact string \`PK\` hash / \`SK\` range key schema.

The approval file is an operator-controlled local gate, not an independently signed authority statement. It does not replace the repository's Ed25519 provider-approval, independent-verifier, evidence-retention attestations or security review.

## 4. Live write gate

The adapter is not a script that automatically writes to AWS. Its factory is used by the provider-neutral harness only when **all** required environment variables are supplied and the exact write opt-in is set.

Required environment:

| Variable | Meaning |
|---|---|
| \`FENCE_AWS_DDB_ENABLE_WRITES\` | Must equal \`I_APPROVE_DYNAMODB_WITNESS_CONFORMANCE_WRITES_TO_THIS_DISPOSABLE_TABLE\` |
| \`FENCE_AWS_DDB_EXPECTED_ACCOUNT_ID\` | 12-digit approved disposable account |
| \`FENCE_AWS_DDB_REGION\` | Approved table Region |
| \`FENCE_AWS_DDB_TABLE_NAME\` | Existing purpose-built witness test table |
| \`FENCE_AWS_DDB_EXPECTED_TABLE_ARN\` | Exact table ARN |
| \`FENCE_AWS_DDB_QUALIFICATION_RUN_ID\` | Unique approved run ID |
| \`FENCE_AWS_DDB_PREFLIGHT_REPORT\` | Local JSON output from the read-only AWS preflight |
| \`FENCE_AWS_DDB_APPROVAL_FILE\` | Local approval file bound to that preflight report |

Approval-file profile: \`sky-high-fence-aws-dynamodb-witness-write-approval-v1\`.

The approval object must include \`profile\`, \`runId\`, \`accountId\`, \`region\`, \`tableArn\`, \`operation\`, \`preflightReportSha256\`, \`approvedBy\`, \`issuedAt\` and \`expiresAt\`. The approval validity window cannot exceed eight hours.

Do not create this approval file, set the live-write environment variable, or use an AWS credential profile until the account owner has approved the exact disposable table and test window. No credentials, approval files, account IDs or provider outputs belong in Git.

## 5. Synthetic CI

CI installs the pinned AWS SDK package but does not create a boto3 Session or contact AWS. The adapter's \`--self-test\` uses a thread-safe in-memory DynamoDB API double. It exercises the same provider-neutral harness cases:

- genesis atomic transaction and strong readback;
- exact retry and lost acknowledgement recovery;
- stale/forked predecessor and generation gap rejection;
- operation and idempotency uniqueness;
- eight concurrent compare-and-append contenders with exactly one winner;
- immutable exact operation lookup;
- receipt field binding;
- durable idempotency recovery through a separate adapter instance, with no TTL and no second transaction;
- explicit refusal to create the live adapter when the operator write opt-in is absent.

The fake rejects any read without \`ConsistentRead=True\` and permits only \`GetItem\` and \`TransactWriteItems\`. These fixtures test adapter logic and its use of the SDK request contract. They do not prove AWS transaction semantics, account isolation, DynamoDB durability, IAM policy enforcement, regional outage behavior or production consistency.

Run locally without AWS credentials:

~~~sh
python scripts/aws_dynamodb_witness_adapter.py --self-test
~~~

## 6. Table provisioning deferred

The repository does not create the DynamoDB table. Before a table is provisioned, an approved infrastructure plan must specify:
- account and Region;
- table name and exact ARN;
- \`PK\` (String, HASH) and \`SK\` (String, RANGE);
- point-in-time recovery and encryption;
- deletion protection and backup/restore policy;
- billing mode and capacity/cost limits;
- IAM resource scoping for the live writer and independent strong-read verifier;
- retention and cleanup expectations for qualification data.

Use no production authority data and no student/personal data. The first external test must use fresh synthetic IDs and a dedicated disposable account.

## 7. References and non-claims

- [DynamoDB TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html)
- [DynamoDB transaction API behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html)
- [DynamoDB read consistency](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html)

This adapter is an implementation candidate, not external qualification. It does not sign witness receipts or operate the independent trust root, does not prove provider-native consistency evidence, does not qualify anti-equivocation, restore, monitor independence or privileged bypass, and does not enable host admission.

**No AWS account is required to run CI or continue provider-neutral engineering.**
