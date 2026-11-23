import { WorkerEntrypoint } from "cloudflare:workers";
import canonicalize from "canonicalize";
import {
  authenticateWorkloadCall,
  type TrustedWorkloadKey,
  type WorkloadAuthenticationResult,
  type WorkloadProof,
} from "../../api/src/witness/workload-identity";
import { DurableWorkloadNonceStore } from "../../api/src/auth/durable-workload-nonce-store";
import { DurableWitnessTrustStateStore } from "./durable-witness-trust-state-store";
import {
  verifyReceiptAgainstTrustedBundle,
  verifyReceiptInclusion,
  verifySignedTreeHead,
  verifyTreeHeadExtension,
  verifyTrustBundleEnvelope,
  type ExpectedTrustBundleState,
  type ExpectedWitnessScope,
  type PinnedRootKey,
  type VerifiedTrustBundle,
  type VerifiedTreeHead,
  type WitnessCheckpointBody,
  type WitnessReceiptEnvelope,
  type WitnessTreeHeadEnvelope,
  type WitnessTrustBundleEnvelope,
} from "../../api/src/witness/witness-profile-verifier";
import type {
  WitnessEvidenceVerificationResult,
  WitnessGatewayRpc,
  WitnessReplayCheckpointResult,
} from "../../api/src/witness/witness-gateway-contract";

const AUDIENCE = "sky-high-witness-gateway";
const AUTH_SCOPE = "witness:authorize";
const AUTH_METHOD = "POST";
const AUTH_PATH = "/rpc/authenticate";
const VERIFY_SCOPE = "witness:verify-evidence";
const VERIFY_METHOD = "POST";
const VERIFY_PATH = "/rpc/verify-evidence";
const CHECKPOINT_SCOPE = "witness:checkpoint-replay";
const CHECKPOINT_METHOD = "POST";
const CHECKPOINT_PATH = "/rpc/checkpoint-replay";
const MAX_CHECKPOINT_BYTES = 640 * 1024;
const ZERO_DIGEST = "0".repeat(64);
const MAX_EVIDENCE_BYTES = 256 * 1024;

interface AllowedWitnessScope extends ExpectedWitnessScope {
  readonly trustDomainId: string;
}

interface EvidenceRequest {
  readonly trustBundle: WitnessTrustBundleEnvelope;
  readonly checkpointBody: WitnessCheckpointBody;
  readonly checkpointDigest: string;
  readonly receiptEnvelope: WitnessReceiptEnvelope;
  readonly treeHeadEnvelope: WitnessTreeHeadEnvelope;
  readonly leafIndex: number;
  readonly inclusionProofHex: readonly string[];
  readonly consistencyProofHex: readonly string[];
}

export interface GatewayEnv {
  readonly WORKLOAD_NONCE_REPLAY: DurableObjectNamespace;
  readonly WITNESS_TRUST_STATE: DurableObjectNamespace;
  /** JSON array of pinned API Worker public-key records; never private keys. */
  readonly WORKLOAD_CALLER_KEYS?: string;
  /** JSON array of pinned root public keys. */
  readonly WITNESS_ROOT_KEYS?: string;
  /** JSON array of exact trust-domain/witness/authority/host scopes. */
  readonly WITNESS_TRUST_SCOPES?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === required.length && required.every((key) => Object.hasOwn(value, key));
}

/** Parse the pinned API Worker public-key allowlist. Missing or malformed config fails closed. */
export function parseTrustedWorkloadKeys(
  serialized: string | undefined,
): readonly TrustedWorkloadKey[] | null {
  if (!serialized) return null;
  try {
    const parsed: unknown = JSON.parse(serialized);
    if (!Array.isArray(parsed) || parsed.length === 0) return null;
    for (const entry of parsed) {
      if (
        !isRecord(entry) ||
        typeof entry.callerId !== "string" ||
        typeof entry.keyId !== "string" ||
        typeof entry.publicKeyBase64Url !== "string" ||
        !Array.isArray(entry.audiences) ||
        !entry.audiences.every((value: unknown) => typeof value === "string") ||
        !Array.isArray(entry.scopes) ||
        !entry.scopes.every((value: unknown) => typeof value === "string") ||
        !Number.isSafeInteger(entry.notBefore) ||
        !Number.isSafeInteger(entry.notAfter)
      ) return null;
    }
    return parsed as TrustedWorkloadKey[];
  } catch {
    return null;
  }
}

export function parsePinnedWitnessRoots(serialized: string | undefined): readonly PinnedRootKey[] | null {
  if (!serialized) return null;
  try {
    const parsed: unknown = JSON.parse(serialized);
    if (!Array.isArray(parsed) || parsed.length === 0) return null;
    const result: PinnedRootKey[] = [];
    for (const entry of parsed) {
      if (
        !isRecord(entry) ||
        typeof entry.keyId !== "string" ||
        !/^[0-9a-f]{64}$/.test(entry.keyId) ||
        typeof entry.publicKeyBase64Url !== "string" ||
        entry.publicKeyBase64Url.length === 0
      ) return null;
      result.push({
        keyId: entry.keyId,
        publicKeyBase64Url: entry.publicKeyBase64Url,
      });
    }
    if (new Set(result.map((root) => root.keyId)).size !== result.length) return null;
    return result;
  } catch {
    return null;
  }
}

export function parseAllowedWitnessScopes(
  serialized: string | undefined,
): readonly AllowedWitnessScope[] | null {
  if (!serialized) return null;
  try {
    const parsed: unknown = JSON.parse(serialized);
    if (!Array.isArray(parsed) || parsed.length === 0) return null;
    const scopes: AllowedWitnessScope[] = [];
    for (const entry of parsed) {
      if (
        !isRecord(entry) ||
        !["trustDomainId", "witnessId", "authorityId", "hostId"].every(
          (key) => typeof entry[key] === "string" && (entry[key] as string).length > 0,
        )
      ) return null;
      scopes.push({
        trustDomainId: entry.trustDomainId as string,
        witnessId: entry.witnessId as string,
        authorityId: entry.authorityId as string,
        hostId: entry.hostId as string,
      });
    }
    const identities = scopes.map((scope) =>
      JSON.stringify([scope.trustDomainId, scope.witnessId, scope.authorityId, scope.hostId]),
    );
    if (new Set(identities).size !== identities.length) return null;
    return scopes;
  } catch {
    return null;
  }
}

function parseCanonicalEvidenceBody(bytes: Uint8Array): EvidenceRequest | null {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_EVIDENCE_BYTES) {
    return null;
  }
  try {
    const serialized = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed: unknown = JSON.parse(serialized);
    if (
      !isRecord(parsed) ||
      !exactKeys(parsed, [
        "trustBundle",
        "checkpointBody",
        "checkpointDigest",
        "receiptEnvelope",
        "treeHeadEnvelope",
        "leafIndex",
        "inclusionProofHex",
        "consistencyProofHex",
      ])
    ) return null;
    const canonical = canonicalize(parsed);
    if (typeof canonical !== "string" || canonical !== serialized) return null;
    if (
      !isRecord(parsed.trustBundle) ||
      !isRecord(parsed.trustBundle.body) ||
      !isRecord(parsed.checkpointBody) ||
      !isRecord(parsed.receiptEnvelope) ||
      !isRecord(parsed.receiptEnvelope.body) ||
      !isRecord(parsed.treeHeadEnvelope) ||
      !isRecord(parsed.treeHeadEnvelope.body) ||
      typeof parsed.checkpointDigest !== "string" ||
      !Number.isSafeInteger(parsed.leafIndex) ||
      (parsed.leafIndex as number) < 0 ||
      !Array.isArray(parsed.inclusionProofHex) ||
      !parsed.inclusionProofHex.every((item: unknown) => typeof item === "string") ||
      !Array.isArray(parsed.consistencyProofHex) ||
      !parsed.consistencyProofHex.every((item: unknown) => typeof item === "string")
    ) return null;
    return parsed as unknown as EvidenceRequest;
  } catch {
    return null;
  }
}

function trustedBundleState(
  snapshot: Awaited<ReturnType<DurableWitnessTrustStateStore["readSnapshot"]>>,
  scope: { trustDomainId: string; witnessId: string },
): ExpectedTrustBundleState {
  return {
    generation: snapshot.trustBundle?.generation ?? 0,
    digest: snapshot.trustBundle?.digest ?? ZERO_DIGEST,
    trustDomainId: scope.trustDomainId,
    witnessId: scope.witnessId,
  };
}

async function verifyStoredTrustBundle(
  envelope: WitnessTrustBundleEnvelope,
  digest: string,
  roots: readonly PinnedRootKey[],
  scope: { trustDomainId: string; witnessId: string },
): Promise<VerifiedTrustBundle> {
  if (
    !isRecord(envelope) ||
    !isRecord(envelope.body) ||
    envelope.bundleDigest !== digest ||
    !Number.isSafeInteger(envelope.body.generation) ||
    (envelope.body.generation as number) < 1 ||
    typeof envelope.body.previousBundleDigest !== "string"
  ) throw new TypeError("stored trust bundle state is malformed");
  return verifyTrustBundleEnvelope(envelope, roots, {
    generation: (envelope.body.generation as number) - 1,
    digest: envelope.body.previousBundleDigest,
    trustDomainId: scope.trustDomainId,
    witnessId: scope.witnessId,
  });
}

async function canonicalEnvelopeDigest(value: unknown): Promise<string> {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") throw new TypeError("stored envelope is not canonicalizable");
  const digest = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(serialized),
  ));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Private RPC-only gateway. The default HTTP surface is closed; evidence
 * verification requires an authenticated workload proof and pinned trust scope.
 */
export class WitnessGateway extends WorkerEntrypoint<GatewayEnv> implements WitnessGatewayRpc {
  async authenticate(
    proof: WorkloadProof,
    body: Uint8Array,
  ): Promise<WorkloadAuthenticationResult> {
    const trustedKeys = parseTrustedWorkloadKeys(this.env.WORKLOAD_CALLER_KEYS);
    if (!trustedKeys) return { authenticated: false, reason: "unknown_key" };
    if (!(body instanceof Uint8Array)) return { authenticated: false, reason: "malformed_proof" };

    return authenticateWorkloadCall(
      proof,
      {
        audience: AUDIENCE,
        scope: AUTH_SCOPE,
        method: AUTH_METHOD,
        path: AUTH_PATH,
        body,
      },
      trustedKeys,
      Math.floor(Date.now() / 1_000),
      new DurableWorkloadNonceStore(this.env.WORKLOAD_NONCE_REPLAY),
    );
  }

  async verifyEvidence(
    proof: WorkloadProof,
    canonicalEvidenceBody: Uint8Array,
  ): Promise<WitnessEvidenceVerificationResult> {
    const trustedKeys = parseTrustedWorkloadKeys(this.env.WORKLOAD_CALLER_KEYS);
    if (!trustedKeys || !(canonicalEvidenceBody instanceof Uint8Array)) {
      return { verified: false, reason: "workload_authentication_failed" };
    }

    const trustedNow = Math.floor(Date.now() / 1_000);
    const auth = await authenticateWorkloadCall(
      proof,
      {
        audience: AUDIENCE,
        scope: VERIFY_SCOPE,
        method: VERIFY_METHOD,
        path: VERIFY_PATH,
        body: canonicalEvidenceBody,
      },
      trustedKeys,
      trustedNow,
      new DurableWorkloadNonceStore(this.env.WORKLOAD_NONCE_REPLAY),
    );
    if (!auth.authenticated) {
      return { verified: false, reason: "workload_authentication_failed" };
    }

    const request = parseCanonicalEvidenceBody(canonicalEvidenceBody);
    if (!request) return { verified: false, reason: "malformed_request" };

    const trustDomainId = request.trustBundle.body.trustDomainId;
    const witnessId = request.trustBundle.body.witnessId;
    const authorityId = request.checkpointBody.authorityId;
    const hostId = request.checkpointBody.hostId;
    if (
      typeof trustDomainId !== "string" ||
      typeof witnessId !== "string" ||
      typeof authorityId !== "string" ||
      typeof hostId !== "string"
    ) return { verified: false, reason: "malformed_request" };

    const allowedScopes = parseAllowedWitnessScopes(this.env.WITNESS_TRUST_SCOPES);
    const roots = parsePinnedWitnessRoots(this.env.WITNESS_ROOT_KEYS);
    if (!allowedScopes || !roots) {
      return { verified: false, reason: "trust_configuration_unavailable" };
    }
    const scope: ExpectedWitnessScope = { witnessId, authorityId, hostId };
    if (!allowedScopes.some((item) =>
      item.trustDomainId === trustDomainId &&
      item.witnessId === witnessId &&
      item.authorityId === authorityId &&
      item.hostId === hostId
    )) return { verified: false, reason: "trust_scope_denied" };

    const stateStore = new DurableWitnessTrustStateStore(this.env.WITNESS_TRUST_STATE);
    let snapshot: Awaited<ReturnType<DurableWitnessTrustStateStore["readSnapshot"]>>;
    try {
      snapshot = await stateStore.readSnapshot({ trustDomainId, witnessId });
    } catch {
      return { verified: false, reason: "trust_state_unavailable" };
    }

    const currentState = trustedBundleState(snapshot, { trustDomainId, witnessId });
    let verifiedBundle: VerifiedTrustBundle;
    let trustBundleNeedsAdvance = false;
    try {
      const storedBundle = snapshot.trustBundle;
      if (storedBundle && storedBundle.generation > 0 && storedBundle.envelope) {
        const verifiedStored = await verifyStoredTrustBundle(
          storedBundle.envelope as WitnessTrustBundleEnvelope,
          storedBundle.digest,
          roots,
          { trustDomainId, witnessId },
        );
        if (request.trustBundle.bundleDigest === storedBundle.digest) {
          verifiedBundle = verifiedStored;
        } else {
          verifiedBundle = await verifyTrustBundleEnvelope(
            request.trustBundle,
            roots,
            currentState,
          );
          trustBundleNeedsAdvance = true;
        }
      } else {
        if (snapshot.treeHead) return { verified: false, reason: "trust_state_unavailable" };
        verifiedBundle = await verifyTrustBundleEnvelope(
          request.trustBundle,
          roots,
          currentState,
        );
        trustBundleNeedsAdvance = true;
      }
    } catch {
      return { verified: false, reason: "trust_bundle_invalid" };
    }

    let receipt: WitnessReceiptEnvelope;
    try {
      receipt = await verifyReceiptAgainstTrustedBundle(
        request.checkpointBody,
        request.checkpointDigest,
        request.receiptEnvelope,
        verifiedBundle,
        trustedNow,
      );
    } catch {
      return { verified: false, reason: "receipt_invalid" };
    }

    let currentHead: VerifiedTreeHead;
    try {
      currentHead = await verifySignedTreeHead(
        request.treeHeadEnvelope,
        verifiedBundle,
        trustedNow,
        scope,
      );
    } catch {
      return { verified: false, reason: "tree_head_invalid" };
    }

    let receiptLeafHash: string;
    try {
      receiptLeafHash = await verifyReceiptInclusion(
        receipt,
        request.leafIndex,
        currentHead,
        request.inclusionProofHex,
      );
    } catch {
      return { verified: false, reason: "inclusion_invalid" };
    }

    if (snapshot.treeHead) {
      try {
        const storedHead = snapshot.treeHead;
        if (
          !storedHead.trustBundleEnvelope ||
          !storedHead.trustBundleDigest ||
          await canonicalEnvelopeDigest(storedHead.envelope) !== storedHead.digest
        ) throw new TypeError("stored tree-head snapshot integrity mismatch");

        const priorTrust = await verifyStoredTrustBundle(
          storedHead.trustBundleEnvelope as WitnessTrustBundleEnvelope,
          storedHead.trustBundleDigest,
          roots,
          { trustDomainId, witnessId },
        );
        const priorEnvelope = storedHead.envelope as WitnessTreeHeadEnvelope;
        const priorTimestamp = Date.parse(priorEnvelope.body.timestamp);
        if (!Number.isFinite(priorTimestamp)) throw new TypeError("stored tree-head timestamp malformed");
        const priorHead = await verifySignedTreeHead(
          priorEnvelope,
          priorTrust,
          Math.floor(priorTimestamp / 1_000),
          scope,
        );
        await verifyTreeHeadExtension(
          priorHead,
          currentHead,
          request.consistencyProofHex,
        );
      } catch {
        return { verified: false, reason: "consistency_invalid" };
      }
    } else if (request.consistencyProofHex.length !== 0) {
      return { verified: false, reason: "consistency_invalid" };
    }

    if (trustBundleNeedsAdvance) {
      const bundleWrite = await stateStore.advanceTrustBundle({
        scope: { trustDomainId, witnessId },
        expectedGeneration: currentState.generation,
        expectedDigest: currentState.digest,
        envelope: request.trustBundle,
      });
      if (!bundleWrite.stored) {
        return { verified: false, reason: "trust_state_conflict" };
      }
    }

    const headWrite = await stateStore.advanceTreeHead({
      scope: { trustDomainId, witnessId },
      expectedPriorHeadDigest: snapshot.treeHead?.digest ?? null,
      envelope: request.treeHeadEnvelope,
    });
    if (!headWrite.stored) {
      return { verified: false, reason: "trust_state_conflict" };
    }

    return {
      verified: true,
      trustBundleGeneration: verifiedBundle.body.generation,
      trustBundleDigest: verifiedBundle.digest,
      treeHeadDigest: headWrite.digest,
      treeSize: currentHead.body.treeSize,
      receiptLeafHash,
    };
  }

  /**
   * Authenticated replay-checkpoint RPC. This deployment intentionally has no
   * configured append provider yet: after validating caller and canonical
   * request bindings it fails closed rather than fabricating a checkpoint.
   */
  async checkpointReplay(
    proof: WorkloadProof,
    canonicalCheckpointBody: Uint8Array,
  ): Promise<WitnessReplayCheckpointResult> {
    const trustedKeys = parseTrustedWorkloadKeys(this.env.WORKLOAD_CALLER_KEYS);
    if (!trustedKeys || !(canonicalCheckpointBody instanceof Uint8Array) ||
        canonicalCheckpointBody.length === 0 ||
        canonicalCheckpointBody.length > MAX_CHECKPOINT_BYTES) {
      return { checkpointed: false, reason: "malformed_request" };
    }

    const auth = await authenticateWorkloadCall(
      proof,
      {
        audience: AUDIENCE,
        scope: CHECKPOINT_SCOPE,
        method: CHECKPOINT_METHOD,
        path: CHECKPOINT_PATH,
        body: canonicalCheckpointBody,
      },
      trustedKeys,
      Math.floor(Date.now() / 1_000),
      new DurableWorkloadNonceStore(this.env.WORKLOAD_NONCE_REPLAY),
    );
    if (!auth.authenticated) {
      return { checkpointed: false, reason: "workload_authentication_failed" };
    }

    try {
      const serialized = new TextDecoder("utf-8", { fatal: true }).decode(canonicalCheckpointBody);
      const parsed: unknown = JSON.parse(serialized);
      if (
        !isRecord(parsed) ||
        !exactKeys(parsed, [
          "version",
          "scope",
          "operationId",
          "phase",
          "expectedPredecessor",
          "snapshotDigest",
          "canonicalSnapshotBase64Url",
        ]) ||
        canonicalize(parsed) !== serialized ||
        parsed.version !== 1 ||
        parsed.phase !== "MONITOR_GOSSIP_REPLAY_V1" ||
        typeof parsed.operationId !== "string" ||
        !/^fence-monitor-replay-[0-9a-f]{64}$/.test(parsed.operationId) ||
        typeof parsed.snapshotDigest !== "string" ||
        !/^[0-9a-f]{64}$/.test(parsed.snapshotDigest) ||
        parsed.operationId !== `fence-monitor-replay-${parsed.snapshotDigest}` ||
        !isRecord(parsed.scope) ||
        !exactKeys(parsed.scope, ["trustDomainId", "witnessId", "authorityId", "hostId"]) ||
        !Object.values(parsed.scope).every((value) => typeof value === "string" && value.length > 0) ||
        !isRecord(parsed.expectedPredecessor) ||
        !exactKeys(parsed.expectedPredecessor, ["generation", "digest"]) ||
        !Number.isSafeInteger(parsed.expectedPredecessor.generation) ||
        (parsed.expectedPredecessor.generation as number) < 0 ||
        typeof parsed.expectedPredecessor.digest !== "string" ||
        !/^[0-9a-f]{64}$/.test(parsed.expectedPredecessor.digest) ||
        typeof parsed.canonicalSnapshotBase64Url !== "string" ||
        !/^[A-Za-z0-9_-]+$/.test(parsed.canonicalSnapshotBase64Url)
      ) return { checkpointed: false, reason: "malformed_request" };

      const requestedScope = parsed.scope as Record<string, unknown>;
      const allowedScopes = parseAllowedWitnessScopes(this.env.WITNESS_TRUST_SCOPES);
      if (!allowedScopes || !allowedScopes.some((scope) =>
        scope.trustDomainId === requestedScope.trustDomainId &&
        scope.witnessId === requestedScope.witnessId &&
        scope.authorityId === requestedScope.authorityId &&
        scope.hostId === requestedScope.hostId
      )) return { checkpointed: false, reason: "trust_scope_denied" };

      const encoded = parsed.canonicalSnapshotBase64Url;
      const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - (encoded.length % 4)) % 4);
      const binary = atob(padded);
      const snapshotBytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      const canonicalEncoding = btoa(String.fromCharCode(...snapshotBytes))
        .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      if (canonicalEncoding !== encoded) return { checkpointed: false, reason: "malformed_request" };
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", snapshotBytes));
      const digestHex = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      if (digestHex !== parsed.snapshotDigest) return { checkpointed: false, reason: "malformed_request" };
    } catch {
      return { checkpointed: false, reason: "malformed_request" };
    }

    // No concrete provider adapter is configured in this release. Keep the
    // caller's durable intent pending until a provider is independently
    // integrated and its append/readback receipt can be verified.
    return { checkpointed: false, reason: "provider_unavailable" };
  }
}

export type { WitnessGatewayRpc } from "../../api/src/witness/witness-gateway-contract";
export { WorkloadNonceReplayDO } from "../../api/src/auth/workload-nonce-replay-do";
export { WitnessTrustStateDO } from "./witness-trust-state-do";

/** Default HTTP surface is deliberately inert; RPC uses the named entrypoint. */
export default {
  async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  },
};
