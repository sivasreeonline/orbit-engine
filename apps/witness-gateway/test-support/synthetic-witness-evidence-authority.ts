import canonicalize from "canonicalize";
import {
  inclusionProof,
  merkleTreeHash,
  type PinnedRootKey,
  type WitnessReceiptEnvelope,
  type WitnessTreeHeadEnvelope,
  type WitnessTrustBundleEnvelope,
  type WitnessSigningKey,
  verifyReceiptAgainstTrustedBundle,
  verifyReceiptInclusion,
  verifySignedTreeHead,
  verifyTrustBundleEnvelope,
} from "../../api/src/witness/witness-profile-verifier";
import {
  WitnessEvidenceAuthorityOperationConflictError,
  type WitnessEvidenceAuthority,
  type WitnessEvidenceAuthorityBundle,
  type WitnessEvidenceAuthorityRequest,
} from "../src/evidence/witness-evidence-authority";
import type { WitnessCheckpointScope } from "../src/provider/witness-provider-adapter";

const RECEIPT_PREFIX = "SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\0";
const TRUST_BUNDLE_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\0";
const TREE_HEAD_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TREE-HEAD-V1\0";
const ZERO_DIGEST = "0".repeat(64);

function canonicalBytes(value: unknown): Uint8Array {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") throw new TypeError("synthetic evidence is not canonicalizable");
  return new TextEncoder().encode(serialized);
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function fingerprint(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", owned.buffer)));
}

async function sign(
  key: CryptoKey,
  prefix: string,
  body: unknown,
): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    key,
    new Uint8Array([...new TextEncoder().encode(prefix), ...canonicalBytes(body)]),
  );
  return base64url(new Uint8Array(signature));
}

async function generateSigningKey(): Promise<{
  readonly privateKey: CryptoKey;
  readonly publicKey: Uint8Array;
  readonly keyId: string;
}> {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicKey, keyId: await fingerprint(publicKey) };
}

export class SyntheticWitnessEvidenceAuthority implements WitnessEvidenceAuthority {
  private readonly records = new Map<string, WitnessEvidenceAuthorityBundle>();
  private readonly rootKeyPromise = generateSigningKey();
  private readonly receiptKeyPromise = generateSigningKey();
  private readonly logKeyPromise = generateSigningKey();

  private operationKey(scope: WitnessCheckpointScope, operationId: string): string {
    return canonicalize({ scope, operationId }) ?? "";
  }

  async issueOrRecoverEvidence(
    request: WitnessEvidenceAuthorityRequest,
  ): Promise<WitnessEvidenceAuthorityBundle> {
    const key = this.operationKey(request.scope, request.checkpointBody.operationId);
    const existing = this.records.get(key);
    if (existing) {
      if (existing.checkpointDigest !== request.checkpointDigest ||
          canonicalize(request.checkpointBody) !== new TextDecoder().decode(request.canonicalCheckpointBodyBytes)) {
        throw new WitnessEvidenceAuthorityOperationConflictError();
      }
      return existing;
    }

    const [root, receiptSigning, logSigning] = await Promise.all([
      this.rootKeyPromise,
      this.receiptKeyPromise,
      this.logKeyPromise,
    ]);
    const now = new Date().toISOString();
    const notBefore = "2026-01-01T00:00:00Z";
    const notAfter = "2036-01-01T00:00:00Z";
    const signingKeys: WitnessSigningKey[] = [
      {
        keyId: receiptSigning.keyId,
        publicKeyBase64Url: base64url(receiptSigning.publicKey),
        purpose: "WITNESS_RECEIPT_SIGNING",
        witnessId: request.scope.witnessId,
        authorityIds: [request.scope.authorityId],
        notBefore,
        notAfter,
      },
      {
        keyId: logSigning.keyId,
        publicKeyBase64Url: base64url(logSigning.publicKey),
        purpose: "WITNESS_LOG_SIGNING",
        witnessId: request.scope.witnessId,
        authorityIds: [request.scope.authorityId],
        notBefore,
        notAfter,
      },
    ];
    const trustBody = {
      profile: "sky-high-fence-witness-v1" as const,
      schemaVersion: 1 as const,
      trustDomainId: request.scope.trustDomainId,
      witnessId: request.scope.witnessId,
      generation: 1,
      previousBundleDigest: ZERO_DIGEST,
      keys: signingKeys,
      revocations: [],
    };
    const trustBundleEnvelope: WitnessTrustBundleEnvelope = {
      body: trustBody,
      bundleDigest: await fingerprint(canonicalBytes(trustBody)),
      rootKeyId: root.keyId,
      rootSignature: await sign(root.privateKey, TRUST_BUNDLE_PREFIX, trustBody),
    };
    const receiptBody = {
      profile: "sky-high-fence-witness-v1" as const,
      schemaVersion: 1 as const,
      witnessId: request.scope.witnessId,
      authorityId: request.scope.authorityId,
      hostId: request.scope.hostId,
      generation: request.checkpointBody.generation,
      operationId: request.checkpointBody.operationId,
      checkpointDigest: request.checkpointDigest,
      previousCheckpointDigest: request.checkpointBody.previousCheckpointDigest,
      keyId: receiptSigning.keyId,
      committedAt: now,
      consistencyToken: "synthetic-test-only",
    };
    const receiptEnvelope: WitnessReceiptEnvelope = {
      body: receiptBody,
      signature: await sign(receiptSigning.privateKey, RECEIPT_PREFIX, receiptBody),
    };
    const leafBytes = canonicalBytes(receiptEnvelope);
    const rootHash = hex(await merkleTreeHash([leafBytes]));
    const treeHeadBody = {
      profile: "sky-high-fence-witness-merkle-v1" as const,
      schemaVersion: 1 as const,
      witnessId: request.scope.witnessId,
      authorityId: request.scope.authorityId,
      hostId: request.scope.hostId,
      logId: "synthetic-test-log",
      treeSize: 1,
      rootHash,
      timestamp: now,
      keyId: logSigning.keyId,
    };
    const treeHeadEnvelope: WitnessTreeHeadEnvelope = {
      body: treeHeadBody,
      signature: await sign(logSigning.privateKey, TREE_HEAD_PREFIX, treeHeadBody),
    };
    const bundle: WitnessEvidenceAuthorityBundle = {
      canonicalCheckpointBodyBytes: request.canonicalCheckpointBodyBytes.slice(),
      checkpointDigest: request.checkpointDigest,
      trustBundleEnvelope,
      receiptEnvelope,
      treeHeadEnvelope,
      leafIndex: 0,
      inclusionProofHex: (await inclusionProof(0, [leafBytes])).map(hex),
      consistencyProofHex: [],
    };
    this.records.set(key, bundle);
    return bundle;
  }

  async readEvidenceByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<WitnessEvidenceAuthorityBundle | null> {
    return this.records.get(this.operationKey(scope, operationId)) ?? null;
  }

  async verifyIssuedBundle(
    request: WitnessEvidenceAuthorityRequest,
    bundle: WitnessEvidenceAuthorityBundle,
  ): Promise<void> {
    const root = await this.rootKeyPromise;
    const pinnedRoots: PinnedRootKey[] = [{
      keyId: root.keyId,
      publicKeyBase64Url: base64url(root.publicKey),
    }];
    const now = Math.floor(Date.now() / 1_000);
    const trust = await verifyTrustBundleEnvelope(bundle.trustBundleEnvelope, pinnedRoots, {
      generation: 0,
      digest: ZERO_DIGEST,
      trustDomainId: request.scope.trustDomainId,
      witnessId: request.scope.witnessId,
    });
    const receipt = await verifyReceiptAgainstTrustedBundle(
      request.checkpointBody,
      request.checkpointDigest,
      bundle.receiptEnvelope,
      trust,
      now,
    );
    const head = await verifySignedTreeHead(
      bundle.treeHeadEnvelope,
      trust,
      now,
      {
        witnessId: request.scope.witnessId,
        authorityId: request.scope.authorityId,
        hostId: request.scope.hostId,
      },
    );
    await verifyReceiptInclusion(receipt, bundle.leafIndex, head, bundle.inclusionProofHex);
  }
}
