# FENCE-001 AWS account readiness and secure onboarding

**Decision:** AWS is the first external qualification provider; Google Cloud is the fallback.
**Current repository state:** No AWS account, Region, credentials, role, table, bucket or trail has been supplied or provisioned.
**Execution boundary:** Account registration is performed by the account owner directly with AWS. Never send account passwords, MFA codes, payment details, identity documents, access keys or session tokens to this repository or an AI assistant.

## 1. What the full qualification actually needs

The current AWS candidate requires:
- DynamoDB witness compare-and-append and strongly consistent readback;
- S3 versioning and Object Lock compliance retention for exact evidence versions;
- a multi-Region CloudTrail trail with log-file integrity validation and data-event selectors for the exact witness table and evidence bucket;
- separate identities for witness writes, evidence custody, audit collection, approval and independent verification;
- a disposable account and explicit approval before any privileged-bypass or restore test.

A standard standalone AWS account with advanced service/Region access is the straightforward route for this complete qualification. The workload resources can be pinned to one approved operating Region (proposed: \`ap-south-1\`), while the CloudTrail trail remains multi-Region so the independent audit package does not silently omit events outside that workload Region. Resource operations must still be constrained to the approved qualification scope.

## 2. Important distinction: AWS Free plan versus full AWS account

AWS currently offers a new Free account plan and a Paid account plan.

### New Free account plan

AWS describes the Free account plan as no-charge experimentation for up to six months or until the Free Tier credits are exhausted, whichever occurs first. New customers receive USD 100 at signup and may earn up to another USD 100 through eligible activities. At the end of the Free plan, the account is suspended; AWS retains content for 90 days, after which the account and its content are permanently deleted if it has not been upgraded. See [AWS Free Tier plans](https://docs.aws.amazon.com/us_en/awsaccountbilling/latest/aboutv2/free-tier-plans.html) and [Free Tier FAQs](https://aws.amazon.com/free/free-tier-faqs/).

The new Free plan includes DynamoDB, S3, CloudTrail, IAM, STS and AWS Budgets in its supported-service list. However, AWS explicitly states that **multi-Region and cross-Region features are not supported for any services** in the new Free plan. For an India-based contact address, new-experience project resources are assigned to \`ap-southeast-2\` (Sydney); this is not the same as choosing Mumbai (\`ap-south-1\`). See [supported services](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html) and [AWS Regions for projects](https://docs.aws.amazon.com/accounts/latest/reference/project-regions.html).

That means the new Free plan is useful for learning and limited single-Region experiments, but it does **not** meet the current full FENCE-001 multi-Region CloudTrail qualification target.

### Do not casually activate advanced features on a Free-plan project

AWS says that activating advanced features requires upgrading the account to a Paid plan. Activation is irreversible, gives access to additional services and multi-Region capabilities, removes existing spend limits, and replaces those limits with the broader Billing and Cost Management tools. AWS also warns that after activation the account owner is responsible for all resource costs and cannot create a spend limit in that new experience. See [Activate advanced AWS features](https://docs.aws.amazon.com/accounts/latest/reference/activate-advanced-features.html).

**Recommendation:** Do not create a Free-plan project and then click “Explore advanced features” as an experiment. For the full qualification route, first decide whether a standard full-access AWS account and its pay-as-you-go exposure are acceptable. If not, continue provider-neutral engineering and defer live qualification rather than enabling an irreversible paid path.

## 3. India-specific registration notes

If the account contact and billing address are in India, AWS India is the local seller and the invoice is issued in INR. AWS India requires customer identity verification before granting service access. The registration flow asks for contact and billing information, a payment method, and an accepted identity document. AWS India currently describes a temporary INR 2 card verification charge that is refunded after verification. It may also redirect to the bank for OTP verification. See [Manage accounts in India](https://docs.aws.amazon.com/accounts/latest/reference/managing-accounts-india.html).

AWS lists personal-account verification document options including PAN, Voter ID/EPIC and driving licence. The name must match the relevant contact or billing identity and the document. Keep all such information inside AWS's official signup and account-verification workflow; do not upload it to this repository or share it in chat.

The AWS India guide says personal and business accounts have the same AWS features and functions. Select the ownership type that truthfully matches the account owner. For a personal qualification account, use the personal option and a personal email address that you control. For an organization-owned account, use an organization-controlled email and contact details so access does not depend on one employee.

## 4. Secure-account checklist

Complete these steps directly in AWS before requesting the read-only preflight role:

1. Register through [AWS advanced signup](https://signin.aws.amazon.com/signup?request_type=register) if proceeding with the full-access qualification path. Read the AWS Customer Agreement and the account billing terms before accepting.
2. Secure the root user with a unique password and MFA. Keep the recovery email and phone current. Do not create root access keys and do not use root for everyday work.
3. Create a separate administrative identity for normal account administration. Prefer temporary role credentials or IAM Identity Center where available; do not create long-lived access keys for the root user.
4. Keep this qualification account standalone for now. Do not join AWS Organizations, create a Control Tower landing zone, or activate optional advanced organizational features as an experiment. These can change account-plan and billing behavior.
5. Configure AWS Budgets email alerts and Free Tier usage alerts where applicable. Budget notifications are monitoring, not a guaranteed hard spend cap. Review [AWS Budgets pricing](https://aws.amazon.com/aws-cost-management/aws-budgets/pricing/); standard budget monitoring and notifications are free, while action-enabled budgets and reports have additional pricing conditions.
6. Do not create any workload resource yet. Do not create a DynamoDB table, S3 bucket, CloudTrail trail, KMS key, IAM role, or access policy until the exact resource plan and cost estimate are reviewed and explicitly approved.

AWS recommends root MFA, not using root for everyday activity, avoiding root access keys, using temporary credentials and applying least privilege. See [Root user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html) and [IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).

## 5. What the first approved environment should look like

| Item | Proposed value / boundary |
|---|---|
| Account purpose | Dedicated disposable FENCE-001 qualification only |
| Account owner | User-controlled identity; not an AI, shared tool or repository secret |
| Account type | Standalone full-access AWS account; no organization enrollment for initial qualification |
| Workload Region | \`ap-south-1\` (proposed only; confirm account eligibility and current service availability) |
| CloudTrail | Multi-Region trail with log-file integrity validation |
| Witness | DynamoDB base table; no GSI or stream as the authoritative high-water read |
| Evidence store | S3 versioning and Object Lock compliance; exact version IDs required |
| Audit log store | Separate S3 destination for CloudTrail logs and digest files |
| Identity | Separate least-privilege roles for read-only inspection, witness, storage, collection and independent verification |
| Data | Synthetic qualification fixtures only; no student, personal or production data |
| Host admission | Disabled |
| Production approval | False |

The read-only preflight in [AWS read-only preflight](m0-fence-001-aws-read-only-preflight.md) will verify actual account/role identity and existing service configuration. Its \`READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION\` result is not provider qualification and does not authorize writes.

## 6. Cost approval required before resource creation

Do not estimate a final monthly amount until the exact retention period, evidence volume, event count, Region, request rates and test duration are known. At minimum, the account owner must approve:
- S3 storage for both evidence and CloudTrail logs, including retained versions;
- S3 request and retrieval charges;
- DynamoDB storage, reads, writes, backups and point-in-time recovery;
- CloudTrail data-event charges (the first copy of management events has different pricing from S3/DynamoDB data events);
- any KMS requests or other optional services;
- the irreversible S3 Object Lock compliance retention duration and the owner of the retained data until expiry.

AWS currently lists CloudTrail data events at USD 0.10 per 100,000 events for the paid tier, while the first copy of management events in each Region is free; S3 usage is charged separately. Confirm current rates at [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) and [S3 pricing](https://aws.amazon.com/s3/pricing/) before approval.

An AWS Budget email alert is not an unconditional ceiling that stops all services at the selected amount. Any automated deny/stop action would itself need a carefully tested control design and could break the qualification environment. Do not mistake an alert for a hard spending limit.

## 7. Explicit stop conditions

Stop and do not provision if:
- the account plan does not permit the required multi-Region CloudTrail feature;
- account identity, billing or customer verification is incomplete;
- the account owner has not approved the resource inventory, retention duration and cost envelope;
- IAM cannot guarantee a separately pinned read-only role and distinct test identities;
- required service features are unavailable in the selected Region;
- the only way forward appears to be an irreversible upgrade or advanced-feature activation that has not been explicitly approved.

If AWS cannot meet the mandatory contracts within the approved account and cost boundary, stop the AWS qualification and evaluate Google Cloud as the fallback. Do not weaken the witness, evidence-retention or audit-completeness contracts merely to make AWS fit a Free-plan restriction.

**Current state remains: no AWS account connected, no credentials held by the project, no provider resources created, no privileged tests run, production approval false, and host admission disabled.**
