import canonicalize from "canonicalize";
import {
  validateMonitorReplayCheckpointBody,
  type MonitorReplayCheckpointBody,
  type WitnessReceiptEnvelope,
  type WitnessTreeHeadEnvelope,
  type WitnessTrustBundleEnvelope,
} from "../../../api/src/witness/witness-profile-verifier";
import type { WitnessCheckpointScope } from "../provider/witness-provider-adapter";

/**
 * Request to the independently administered evidence authority. This is
 * intentionally separate from WitnessProviderAdapter: the storage provider
 * performs atomic append/readback, while this authority signs receipts and
 * publishes transparency evidence under separately controlled keys.
 */
export interface WitnessEvidenceAuthorityRequest {
  readonly scope: WitnessCheckpointScope;
  readonly checkpointBody: MonitorReplayCheckpointBody;
  readonly canonicalCheckpointBodyBytes: Uint8Array;
  readonly checkpointDigest: string;
}

export interface WitnessEvidenceAuthorityBundle {
  /** Exact body bytes read back by the evidence authority for this operation. */
  readonly canonicalCheckpointBodyBytes: Uint8Array;
  readonly checkpointDigest: string;
  readonly trustBundleEnvelope: WitnessTrustBundleEnvelope;
  readonly receiptEnvelope: WitnessReceiptEnvelope;
  readonly treeHeadEnvelope: WitnessTreeHeadEnvelope;
  readonly leafIndex: number;
  readonly inclusionProofHex: readonly string[];
  readonly consistencyProofHex: readonly string[];
}

/**
 * Implementations must be independently administered from the replay storage
 * provider and gateway. issueOrRecoverEvidence is idempotent by exact
 * scope/operation/checkpoint digest. readEvidenceByOperation must return the
 * immutable evidence bundle or null; it must never mint a replacement for an
 * operation already bound to different bytes.
 */
export interface WitnessEvidenceAuthority {
  issueOrRecoverEvidence(
    request: WitnessEvidenceAuthorityRequest,
  ): Promise<WitnessEvidenceAuthorityBundle>;

  readEvidenceByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<WitnessEvidenceAuthorityBundle | null>;
}

export class WitnessEvidenceAuthorityUnavailableError extends Error {
  constructor(message = "independent witness evidence authority is unavailable") {
    super(message);
    this.name = "WitnessEvidenceAuthorityUnavailableError";
  }
}

export class WitnessEvidenceAuthorityAmbiguousCommitError extends Error {
  constructor(message = "evidence issuance acknowledgement is ambiguous") {
    super(message);
    this.name = "WitnessEvidenceAuthorityAmbiguousCommitError";
  }
}

export class WitnessEvidenceAuthorityOperationConflictError extends Error {
  constructor(message = "evidence authority operation is bound to different checkpoint bytes") {
    super(message);
    this.name = "WitnessEvidenceAuthorityOperationConflictError";
  }
}

function sameScope(a: WitnessCheckpointScope, b: WitnessCheckpointScope): boolean {
  return a.trustDomainId === b.trustDomainId &&
    a.witnessId === b.witnessId &&
    a.authorityId === b.authorityId &&
    a.hostId === b.hostId;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a[index]! ^ b[index]!;
  }
  return difference === 0;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", owned));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Structural and byte-level identity checks only. Cryptographic trust-bundle,
 * receipt-signature, tree-head-signature, inclusion and consistency checks
 * remain mandatory through the gateway's verifyEvidence path.
 */
export async function assertEvidenceAuthorityBundleMatchesRequest(
  request: WitnessEvidenceAuthorityRequest,
  bundle: WitnessEvidenceAuthorityBundle,
): Promise<void> {
  try {
    validateMonitorReplayCheckpointBody(request.checkpointBody);
  } catch {
    throw new WitnessEvidenceAuthorityOperationConflictError("request checkpoint body is malformed");
  }

  const canonical = canonicalize(request.checkpointBody);
  if (typeof canonical !== "string") {
    throw new WitnessEvidenceAuthorityOperationConflictError("request checkpoint body is not canonical JSON");
  }
  const canonicalBytes = new TextEncoder().encode(canonical);
  if (
    !sameScope(request.scope, {
      trustDomainId: request.checkpointBody.trustDomainId,
      witnessId: request.checkpointBody.witnessId,
      authorityId: request.checkpointBody.authorityId,
      hostId: request.checkpointBody.hostId,
    }) ||
    !bytesEqual(request.canonicalCheckpointBodyBytes, canonicalBytes) ||
    await sha256Hex(canonicalBytes) !== request.checkpointDigest ||
    bundle.checkpointDigest !== request.checkpointDigest ||
    !bytesEqual(bundle.canonicalCheckpointBodyBytes, request.canonicalCheckpointBodyBytes)
  ) throw new WitnessEvidenceAuthorityOperationConflictError();

  const receipt = bundle.receiptEnvelope.body;
  const trust = bundle.trustBundleEnvelope.body;
  const treeHead = bundle.treeHeadEnvelope.body;
  if (
    receipt.profile !== "sky-high-fence-witness-v1" ||
    receipt.witnessId !== request.scope.witnessId ||
    receipt.authorityId !== request.scope.authorityId ||
    receipt.hostId !== request.scope.hostId ||
    receipt.generation !== request.checkpointBody.generation ||
    receipt.operationId !== request.checkpointBody.operationId ||
    receipt.checkpointDigest !== request.checkpointDigest ||
    receipt.previousCheckpointDigest !== request.checkpointBody.previousCheckpointDigest ||
    trust.profile !== "sky-high-fence-witness-v1" ||
    trust.trustDomainId !== request.scope.trustDomainId ||
    trust.witnessId !== request.scope.witnessId ||
    treeHead.profile !== "sky-high-fence-witness-merkle-v1" ||
    treeHead.witnessId !== request.scope.witnessId ||
    treeHead.authorityId !== request.scope.authorityId ||
    treeHead.hostId !== request.scope.hostId ||
    !Number.isSafeInteger(bundle.leafIndex) ||
    bundle.leafIndex < 0 ||
    !Number.isSafeInteger(treeHead.treeSize) ||
    bundle.leafIndex >= treeHead.treeSize ||
    !Array.isArray(bundle.inclusionProofHex) ||
    !bundle.inclusionProofHex.every((node) => /^[0-9a-f]{64}$/.test(node)) ||
    !Array.isArray(bundle.consistencyProofHex) ||
    !bundle.consistencyProofHex.every((node) => /^[0-9a-f]{64}$/.test(node))
  ) throw new WitnessEvidenceAuthorityOperationConflictError(
    "evidence bundle scope, receipt, tree-head or proof metadata does not bind the requested checkpoint",
  );
}

/** Issue evidence once; after an ambiguous acknowledgement, recover by exact operation ID. */
export async function issueOrRecoverWitnessEvidence(
  authority: WitnessEvidenceAuthority,
  request: WitnessEvidenceAuthorityRequest,
): Promise<WitnessEvidenceAuthorityBundle> {
  try {
    const issued = await authority.issueOrRecoverEvidence(request);
    await assertEvidenceAuthorityBundleMatchesRequest(request, issued);
    return issued;
  } catch (error) {
    if (error instanceof WitnessEvidenceAuthorityOperationConflictError) throw error;
    // RPC/service-binding errors may not preserve custom Error prototypes.
    // Always perform immutable operation lookup after a failed issuance call;
    // this is safe because the lookup is exact and cannot mint or rebase.
    let recovered: WitnessEvidenceAuthorityBundle | null;
    try {
      recovered = await authority.readEvidenceByOperation(
        request.scope,
        request.checkpointBody.operationId,
      );
    } catch {
      throw new WitnessEvidenceAuthorityUnavailableError(
        "evidence issuance failed and immutable operation lookup is unavailable",
      );
    }
    if (recovered) {
      await assertEvidenceAuthorityBundleMatchesRequest(request, recovered);
      return recovered;
    }
    if (error instanceof WitnessEvidenceAuthorityAmbiguousCommitError ||
        error instanceof WitnessEvidenceAuthorityUnavailableError) {
      throw new WitnessEvidenceAuthorityUnavailableError(
        "ambiguous evidence issuance has no immutable operation record",
      );
    }
    throw error;
  }
}
