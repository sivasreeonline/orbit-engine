# FENCE-001 provider capability review and qualification candidate proposal

**Decision status:** Proposal only. No provider is selected, contracted, provisioned or qualified.
**Preferred first candidate to investigate:** AWS, subject to explicit approval and disposable-account availability.
**Alternative:** Google Cloud.
**Not approved:** Production use, production credentials, host admission or execution authorization.

## 1. Why a provider decision is now the critical path

The FENCE-001 repository now has local contracts and validators for:

- atomic witness append and strong readback;
- immutable, exact-version evidence storage;
- provider-native privileged-bypass attempts and audit readback;
- isolated restore/recovery and monitor reconciliation;
- provider-native audit provenance, signature verification and evidence custody;
- cryptographic attestation verification against an independently pinned trust inventory.

Synthetic CI validates that these contracts reject malformed packages. It does not establish that any cloud service actually implements the required guarantees. The next real qualification must therefore exercise one chosen provider's actual APIs, identities, immutable store and audit service in an approved disposable environment.

This document is a capability review, not a selection or authorization. The provider must not be wired into the executable adapters until the qualification account, region, service configuration, roles, spend/retention window and test approval have been explicitly authorized.

## 2. Capability comparison from official documentation

| Required capability | AWS candidate | Google Cloud alternative | Azure alternative |
|---|---|---|---|
| Atomic witness transition | DynamoDB `TransactWriteItems` is atomic all-or-nothing; use conditional writes and strong reads on the base table or an LSI. | Spanner serializable read-write transactions are externally consistent. | Cosmos DB requires a specifically configured consistency and write-region design; transactional guarantees must be verified for the selected API/account topology. |
| Read-after-write | DynamoDB base-table and LSI reads can request strong consistency; GSIs and streams are eventually consistent. | Cloud Storage object writes are globally strongly consistent after successful completion; Spanner provides external consistency for transactions. | Must be qualified for the selected storage/database service and consistency configuration. |
| Immutable evidence bytes | S3 Object Lock compliance mode protects an exact version; S3 versioning is required. | Cloud Storage Bucket Lock permanently prevents reducing or removing a locked retention policy. | Azure Blob time-based retention policies provide WORM after the policy is locked. |
| Provider-native audit integrity | CloudTrail log-file integrity validation hashes delivered log files and signs hourly digest files; each digest links to the previous digest. | Cloud Audit Logs are available; Admin Activity is always written, while Data Access is disabled by default for most services. The reviewed docs describe immutable log entries but did not establish an equivalent provider-signed digest chain. | Azure has Activity Logs, resource logs and retention-policy audit logs; customers must configure persistent storage and account for documented audit coverage limits. |
| Irreversible controls / operational caveats | S3 Object Lock is version-specific: a new version or delete marker can still be created. Exact version IDs must be retained and independently read back. | Bucket Lock is irreversible; retention cannot later be reduced or removed. | A locked time-based retention policy cannot be removed or shortened. Version-level retention policy changes are not included in the documented container policy audit log. |

### AWS evidence reviewed

- [DynamoDB TransactWriteItems API](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html): transaction actions are atomic; the API cannot span AWS accounts or Regions.
- [DynamoDB read consistency](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html): base tables and local secondary indexes support strongly consistent reads; global secondary indexes and streams do not.
- [DynamoDB transaction API behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html): use transactional reads where serializable multi-item reads are needed, and strongly consistent reads for immediate current-state verification after a successful write.
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html): Object Lock requires versioning; compliance mode prevents an object version from being overwritten or deleted during retention, including by the account root user. Protection applies to the specified version, not future versions or delete markers.
- [CloudTrail log-file integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html): SHA-256 log hashes and RSA-signed digest files are delivered hourly; the digest chain includes the previous digest signature.
- [CloudTrail digest file structure](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html): digest objects describe delivered log files, their hashes and the prior digest signature.

### Google Cloud evidence reviewed

- [Spanner transactions](https://docs.cloud.google.com/spanner/docs/transactions): default serializable read-write transactions are externally consistent.
- [Spanner external consistency](https://docs.cloud.google.com/spanner/docs/true-time-external-consistency): Spanner's external consistency orders transactions consistently with their real-time commit order.
- [Cloud Storage consistency](https://docs.cloud.google.com/storage/docs/consistency): object read-after-write and listing are globally strongly consistent after a successful write.
- [Cloud Storage Bucket Lock](https://docs.cloud.google.com/storage/docs/bucket-lock): locking a retention policy permanently prevents reducing or removing it.
- [Cloud Audit Logs overview](https://docs.cloud.google.com/logging/docs/audit): Admin Activity logs are always written; Data Access logs must be explicitly enabled for most services.
- [Cloud Audit Logs best practices](https://docs.cloud.google.com/logging/docs/audit/best-practices): Data Access logs are configurable and chargeable, so their service coverage and cost need deliberate qualification.

### Azure evidence reviewed

- [Azure Blob immutable storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview): time-based retention and legal holds support WORM; a time-based policy must be locked for the documented compliant immutable state.
- The same documentation notes that the container-level retention-policy audit log records up to seven retention commands and that version-level retention-policy changes are not audited. Azure Activity and resource logs require the customer to store them persistently.

## 3. Proposal: evaluate AWS first, without selecting it yet

AWS is the strongest first candidate in this source review because the witness, exact-version WORM storage and provider audit-integrity layers have complementary documented primitives:

1. **Witness:** use a DynamoDB base table with conditional writes and an idempotency key. Keep each atomic witness transaction within one account and Region. Use strongly consistent `GetItem`/`Query` reads on the base table or an LSI for readback. Do not use a GSI or stream as the authoritative latest-state read.
2. **Immutable evidence:** use a versioned S3 bucket with Object Lock in compliance mode for the qualification evidence objects. Every receipt must preserve the exact object version ID, retention mode and retain-until timestamp. Independent reads must specify that version ID; never silently resolve an alias such as `latest`.
3. **Audit provenance:** enable CloudTrail log-file integrity validation and configure the exact audit/data-event coverage required for the test. Preserve raw logs and digest files. An independent verifier must validate the digest signature, the chain to the independently pinned starting digest, every referenced log hash and the expected account/Region inventory.
4. **Separation:** keep the witness runtime, immutable evidence custody and trust-key governance under separately controlled identities and, where the approved account structure permits, separate administrative accounts. The trust-key inventory and its expected SHA-256 pin must be delivered outside the provider/evidence-store trust boundary.
5. **Qualification only:** run the adapter conformance, seven privileged-bypass attempts and restore/recovery harness only against a disposable, run-bound qualification account after explicit approval. Keep host admission disabled.

### Known AWS caveats that must be tested

- DynamoDB `TransactWriteItems` cannot span accounts or Regions. The witness operation must be designed around that boundary; the qualification cannot assume a transaction across multiple account/Region resources.
- Strong consistency is not universal: global secondary indexes and streams are eventually consistent. An implementation that uses them for the authoritative high-water read is not acceptable.
- S3 Object Lock protects an exact version. A later version or delete marker can coexist with a protected version. The adapter must capture and verify exact version IDs and must reject any fallback to the current key version.
- Compliance-mode retention is an irreversible operational commitment for the protected version and requires a correctly controlled retention window. The test plan must include expiry/cost ownership and must never point at production evidence.
- CloudTrail digest files arrive hourly, not synchronously with a privileged mutation. The adapter must define a bounded collection wait, correlate the exact request IDs, detect missing hours/files, validate the previous-digest chain and fail closed when the audit window is incomplete.
- CloudTrail integrity validation proves the delivered log files and digest chain have not been modified after delivery. It does not, by itself, prove that every relevant API event was configured for capture or that the provider's logging service is truthful. Data-event selectors and source coverage must be independently reviewed.
- S3 and DynamoDB documented primitives do not prove administrative independence, account ownership, role separation, remote retention behavior or restore correctness. Those remain actual test and external-review outcomes.

## 4. Google Cloud remains a credible alternative

Google Cloud is not rejected. Spanner's externally consistent transactions and Cloud Storage's globally strong object read-after-write consistency are strong primitives for the witness and evidence-storage portions. Bucket Lock supplies irreversible retention-policy locking.

The main qualification work is audit-provenance design: explicitly enable required Data Access logs, validate service/event coverage, export and retain the raw logs, and demonstrate an independent authentication and completeness mechanism acceptable to the reviewer. The reviewed sources establish immutable audit log entries and Cloud Logging audit categories, but this review did not establish a provider-signed, chained digest mechanism comparable to CloudTrail's documented hourly digest flow. Do not interpret that limited review as proof that no other Google Cloud audit-integrity feature exists; investigate the exact candidate service and evidence path before deciding.

## 5. Provider selection gate — required before implementation

No vendor-specific adapter may be enabled until the operator has approved all of the following in writing:

- provider and target Region;
- disposable qualification account/project/subscription and the account owner;
- witness service, exact transaction/read topology and tested consistency mode;
- evidence-store service, versioning, retention mode, exact-version readback and immutable audit configuration;
- provider audit service, event selectors, log destination, signature/trust-root source and completeness window;
- independent trust-root administrator and out-of-band trust-key digest delivery channel;
- distinct storage, owner, organization, recovery, collector and independent-verifier principals;
- destructive-test window, retention expiry, cost owner and cleanup constraints;
- explicit confirmation that the account is non-production, restore source remains read-only and host admission stays disabled.

The first external qualification run must capture provider-native receipts, raw responses, request IDs, audit artifacts, exact object-version identifiers and independent readback evidence. Only then may the existing manifest/binding/orchestrator chain consume the materialized evidence package.

## 6. Current decision

**No provider is selected.** AWS is proposed as the first candidate to evaluate because its documented witness/read, version-specific compliance retention and signed audit-digest capabilities align well with the current contracts. Google Cloud remains the principal alternative. Azure remains viable for immutable blob retention but needs further qualification of the full witness and audit-integrity chain.

This document authorizes no cloud account creation, subscription, API call, data upload, privileged mutation, restore operation, production deployment or host admission. All FENCE-001 production gates remain closed.
