# FENCE-001 first-provider plan: AWS read-only preflight

**Decision:** AWS is the first disposable qualification target. Google Cloud is the fallback if AWS cannot satisfy a mandatory contract.
**Current phase:** Read-only environment discovery. This change does not create or change any AWS account, Region, table, bucket, trail or IAM role.
**Command:** scripts/inspect_m0_fence_aws_qualification_environment.py
**Output:** A local JSON report only. Do not commit it; it contains account and resource identifiers.

## 1. AWS service mapping

| FENCE-001 requirement | First AWS implementation | Required contract behavior |
|---|---|---|
| Witness compare-and-append | DynamoDB base table and TransactWriteItems | One atomic conditional transaction compares the exact predecessor and inserts one immutable successor. Strongly consistent base-table reads are authoritative; GSIs and streams are not. |
| Long-lived idempotency | Durable operation/idempotency item in the same DynamoDB transaction | DynamoDB ClientRequestToken is only a 10-minute idempotency window. The durable operation record must prevent a second commit when the same operation is retried after that window. A retry then reads back the exact operation with a strongly consistent base-table read. |
| Evidence WORM | Versioned S3 bucket with Object Lock compliance mode | Retain exact VersionId, digest and byte count. Read and inspect the exact version. Do not treat the current key version as authoritative; a new version or delete marker can still be added over a retained version. |
| Provider audit | Multi-Region CloudTrail trail with log-file validation | Enable the required S3 object and DynamoDB table data events. Preserve raw log and digest bytes, verify signatures and log hashes independently, and follow the digest chain. |
| Qualification isolation | Separate disposable AWS account/roles and distinct evidence/audit buckets | Pin account, Region, role, service ARNs, resource IDs and independent identities before any write or destructive test. Production is never an eligible target. |

### Important AWS limitations

- DynamoDB transactions are atomic within one AWS account and Region; they cannot span accounts or Regions.
- DynamoDB's native transaction client token is valid for 10 minutes after the first completed request. It is not the only idempotency mechanism in our adapter.
- S3 Object Lock protects the specified object version. A later object version or delete marker may become current while the protected version remains retained.
- CloudTrail digest delivery is periodic. A successful CloudTrail status read is not proof that the required event window has a complete, independently verified digest chain.
- CloudTrail data events are not enabled by default. The exact S3 and DynamoDB resource selectors must cover the qualification evidence bucket and witness table, including writes.

## 2. Read-only preflight

The preflight requires a non-secret JSON configuration file with these exact fields:

~~~json
{
  "profile": "sky-high-fence-aws-read-only-preflight-v1",
  "qualificationRunId": "replace-with-run-id",
  "accountId": "123456789012",
  "region": "ap-south-1",
  "expectedCallerArnPrefix": "arn:aws:sts::123456789012:assumed-role/SkyHighFenceReadOnly/",
  "dynamodbTableName": "sky-high-fence-witness",
  "evidenceBucketName": "sky-high-fence-evidence",
  "cloudTrailArn": "arn:aws:cloudtrail:ap-south-1:123456789012:trail/sky-high-fence-audit",
  "cloudTrailLogBucketName": "sky-high-fence-cloudtrail-logs"
}
~~~

Replace every sample account, Region, role and resource name with values explicitly approved by the account owner. The caller ARN prefix pins the expected assumed role while allowing a changing STS session name. Use a read-only role for this phase.

The inspector performs only these read operations:

- STS GetCallerIdentity;
- DynamoDB DescribeTable and DescribeContinuousBackups;
- S3 GetBucketLocation, GetBucketVersioning, GetObjectLockConfiguration, GetEncryptionConfiguration, and GetBucketPublicAccessBlock;
- CloudTrail DescribeTrails, GetTrailStatus, and GetEventSelectors.

It verifies:
- exact caller account and assumed-role ARN prefix;
- exact DynamoDB table ARN, ACTIVE state, encryption and point-in-time recovery;
- evidence-bucket Region, versioning, default compliance retention of at least seven days and all four bucket-level Block Public Access settings;
- explicit bucket default encryption when the API reports it (a missing/unknown result is a warning for manual confirmation);
- exact CloudTrail ARN and destination log bucket, multi-Region and global-service logging, log-file integrity validation, active logging and digest-delivery error state;
- data-event write coverage for the pinned S3 evidence bucket and DynamoDB table.

A blocker means the environment is not ready for adapter implementation. Warnings require explicit review. A passing result means only READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION; it does not qualify AWS or authorize any resource mutation.

### Install and run on Windows PowerShell

Use the AWS CLI or another approved login method to establish the read-only role session first. Do not place access keys in the JSON config, repository, shell history or logs.

~~~powershell
python -m pip install "boto3==1.43.114"
aws sts get-caller-identity --profile <approved-read-only-profile>
python scripts/inspect_m0_fence_aws_qualification_environment.py \`
  --config C:\SkyHighSecure\aws-fence-preflight.json \`
  --output C:\SkyHighSecure\aws-fence-preflight-report.json \`
  --profile-name <approved-read-only-profile>
~~~

The output directory must be access-controlled. The report is local evidence and must not be committed to GitHub. The script refuses to overwrite an existing report.

## 3. Minimal read-only IAM permissions

The account administrator should create or provide a dedicated read-only inspection role, scoped to the named resources wherever AWS supports resource-level permissions. The following is an action checklist, not a complete deployable policy; validate resource-level support and add the required DescribeTrails scope for the account:

- sts:GetCallerIdentity
- dynamodb:DescribeTable
- dynamodb:DescribeContinuousBackups
- s3:GetBucketLocation
- s3:GetBucketVersioning
- s3:GetBucketObjectLockConfiguration
- s3:GetEncryptionConfiguration
- s3:GetBucketPublicAccessBlock
- cloudtrail:DescribeTrails
- cloudtrail:GetTrailStatus
- cloudtrail:GetEventSelectors

No create, update, put, delete, restore, retention-bypass or IAM-policy mutation permission is required for this preflight.

## 4. Explicitly deferred work

The preflight does not:
- create or configure any AWS resource;
- write a DynamoDB item or S3 object;
- call a privileged mutation API;
- change CloudTrail selectors or enable logging;
- test a retention bypass, perform a restore, or alter a source snapshot;
- verify an AWS signature/digest chain, prove provider audit completeness, or establish administrative independence.

After the account owner supplies and approves the disposable account, Region, resource inventory and role boundary, the next engineering slices are: (1) DynamoDB witness adapter with durable idempotency records and strong reads; (2) S3 exact-version compliance adapter; (3) CloudTrail log/digest verifier; and only then (4) separately approved destructive bypass and restore tests.

**Production approval remains false. Host admission remains disabled.**

## 5. AWS documentation references

- [DynamoDB TransactWriteItems API](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html) — atomic transaction limits and the 10-minute ClientRequestToken idempotency window.
- [DynamoDB transaction behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html) — transaction conflict and retry guidance.
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) — exact-version compliance retention and the fact that later versions/delete markers can still be created.
- [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) — basic and advanced selectors for S3 objects and DynamoDB tables.
- [DynamoDB CloudTrail data events](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html) — DynamoDB TransactWriteItems is among the table data events that CloudTrail can record.
- [CloudTrail digest structure](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html) — digest files contain file hashes and the previous digest signature.
