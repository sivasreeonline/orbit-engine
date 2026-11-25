# Private Runner Artifact Delivery

**Status:** Database-backed runner artifact delivery implemented; Go client integration and process execution remain disabled.

## Endpoint

`POST /internal/v1/runner/artifact`

The request is signed with the registered Ed25519 runner key and one-time nonce. The exact JSON request contains only:

```json
{
  "dispatchId": "uuid",
  "executionId": "uuid",
  "attemptId": "uuid",
  "leaseToken": "uuid"
}
```

Runner ID and key ID are derived from the authenticated machine identity, never accepted in the body.

## Authorization gates

The repository requires all of the following before resolving source or tests:

- active registered runner and signing key;
- dispatch and execution-job identify the same execution and attempt;
- both current leases belong to that runner and carry the exact supplied token;
- both lease expiries are still in the future;
- execution job state is `RUNNING`;
- durable acceptance and start receipts exist for this exact dispatch/lease generation and runner/key.

The query locks dispatch and job rows while it resolves the artifact. A stale token, expired lease, missing start receipt, wrong runner/key, or mismatched attempt fails closed.

## Artifact response

The response contains:
- execution/attempt/problem-version identity;
- language, trusted runtime version and action;
- opaque source artifact ID, verified SHA-256 and source text;
- action-scoped test-bundle ID and SHA-256;
- test case ID, sequence, visibility, input and expected output.

The source is independently hashed and checked against both the immutable source-snapshot digest and execution-attempt digest before returning.

#### Protocol v2 request handoff

For a v2 dispatch, the same authenticated endpoint additionally returns:

- `protocolRequest.requestBytesBase64`: base64 of the exact immutable UTF-8 bytes stored in `execution_protocol_requests.request_bytes`;
- `protocolRequest.requestSha256`: SHA-256 of those exact bytes.

The repository does not reconstruct or reserialize the protocol request. Before returning it, the repository checks the stored digest, fatal UTF-8/JSON decoding, exact top-level field set, execution/attempt/correlation identity, problem/action/language/runtime/source identity, canonical test-bundle identity, and the trusted persisted deadline. A v1 dispatch must not have a v2 request row; a v2 dispatch without a valid request row fails closed.

The request bytes are base64-wrapped only for transport inside the existing signed runner artifact response. The runner must base64-decode and verify the digest before interpreting the v2 JSON. This API addition does not make v2 dispatches claimable: all current dispatch lease queries remain v1-only, and the Go v2 consumer is not yet implemented.

## Run versus Submit

- **RUN** returns PUBLIC test cases only. Hidden cases and expected outputs are not included.
- **SUBMIT** returns PUBLIC and HIDDEN cases to the authenticated runner so the trusted evaluator can calculate the final verdict.

This policy is enforced by the database query/repository, not by the browser or runner client. No student-facing endpoint returns hidden test cases or expected outputs.

## Test-bundle digest format

The test-bundle SHA-256 is independent of JavaScript/Go JSON escaping. Both services use the same versioned binary encoding:

1. A 32-bit big-endian length followed by UTF-8 bytes for the magic string `SKYHIGH-TEST-BUNDLE-V1`.
2. A 32-bit big-endian test-case count.
3. For each case in ascending sequence order:
   - 32-bit length + UTF-8 test-case UUID;
   - 32-bit big-endian sequence number;
   - one visibility byte (`1` = PUBLIC, `2` = HIDDEN);
   - 32-bit length + UTF-8 input;
   - 32-bit length + UTF-8 expected output.

The SHA-256 is calculated over the complete byte sequence. This avoids JSON escaping differences between the TypeScript control plane and Go runner.

## Bounds and storage

- Source: maximum 256 KiB.
- Test count: 1–200.
- Combined raw test input/output bytes: maximum 1 MiB.
- Inputs and expected outputs must be valid UTF-8 in this version.
- Only private PostgreSQL `DATABASE` source snapshots are supported.
- `R2` source snapshots return a storage-unavailable response until private R2 retrieval, object-key authorization and content-hash verification are implemented.
- No public object URL, database credential or hidden fixture is returned to the student.

## Lifecycle

The current control-plane sequence is:

1. Claim dispatch metadata.
2. Fsync a local acceptance receipt.
3. Persist authenticated `RUNNER_ACCEPTED`.
4. Persist the lease-fenced `RUNNER_STARTED` transition.
5. Renew the active lease using authenticated heartbeat.
6. Fetch the private source and action-scoped test bundle.
7. Only after separate sandbox qualification may the runner execute the program.

Artifact retrieval does not itself start a process or create an execution verdict. The Go runner remains loopback-only and health-only with an unconfigured executor. Result submission, cancellation, cleanup attestation and expired-RUNNING recovery remain separate gates.
