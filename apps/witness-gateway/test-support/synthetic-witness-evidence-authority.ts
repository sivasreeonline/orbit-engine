import canonicalize from "canonicalize";
import {
  consistencyProof,
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
  verifyTreeHeadExtension,
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

interface SyntheticSigningKey {
  readonly privateKey: CryptoKey;
  readonly publicKey: Uint8Array;
  readonly keyId: string;
}

async function generateSigningKey(): Promise<SyntheticSigningKey> {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicKey, keyId: await fingerprint(publicKey) };
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("test signing key material is malformed");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

/** Import a test-harness root keypair; private bytes remain inside this authority instance. */
async function importRootSigningKey(
  privateKeyPkcs8Base64Url: string,
  publicKeyBase64Url: string,
): Promise<SyntheticSigningKey> {
  const publicKey = decodeBase64Url(publicKeyBase64Url);
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    ownedArrayBuffer(decodeBase64Url(privateKeyPkcs8Base64Url)),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  return { privateKey, publicKey, keyId: await fingerprint(publicKey) };
}

export class SyntheticWitnessEvidenceAuthority implements WitnessEvidenceAuthority {
  private readonly records = new Map<string, WitnessEvidenceAuthorityBundle>();
  private readonly logEntries: Uint8Array[] = [];
  private readonly rootKeyPromise: Promise<SyntheticSigningKey>;
  private readonly receiptKeyPromise = generateSigningKey();
  private readonly logKeyPromise = generateSigningKey();
  private readonly inFlight = new Map<string, {
    readonly requestFingerprint: string;
    readonly promise: Promise<WitnessEvidenceAuthorityBundle>;
  }>();

  constructor(rootKeyPromise: Promise<SyntheticSigningKey> = generateSigningKey()) {
    this.rootKeyPromise = rootKeyPromise;
  }

  /** Test-only factory for injecting a root whose public half is pinned by the gateway. */
  static withRootKeyMaterial(
    privateKeyPkcs8Base64Url: string,
    publicKeyBase64Url: string,
  ): SyntheticWitnessEvidenceAuthority {
    return new SyntheticWitnessEvidenceAuthority(
      importRootSigningKey(privateKeyPkcs8Base64Url, publicKeyBase64Url),
    );
  }

  private operationKey(scope: WitnessCheckpointScope, operationId: string): string {
    return canonicalize({ scope, operationId }) ?? "";
  }

  issueOrRecoverEvidence(
    request: WitnessEvidenceAuthorityRequest,
  ): Promise<WitnessEvidenceAuthorityBundle> {
    const key = this.operationKey(request.scope, request.checkpointBody.operationId);
    const requestFingerprint = canonicalize({
      checkpointDigest: request.checkpointDigest,
      checkpointBody: request.checkpointBody,
      canonicalCheckpointBodyBytes: Array.from(request.canonicalCheckpointBodyBytes),
    }) ?? "";
    const inFlight = this.inFlight.get(key);
    if (inFlight) {
      if (inFlight.requestFingerprint !== requestFingerprint) {
        return Promise.reject(new WitnessEvidenceAuthorityOperationConflictError());
      }
      return inFlight.promise;
    }

    const promise = this.issueOrRecoverEvidenceOnce(request).finally(() => {
      if (this.inFlight.get(key)?.promise === promise) this.inFlight.delete(key);
    });
    this.inFlight.set(key, { requestFingerprint, promise });
    return promise;
  }

  private async issueOrRecoverEvidenceOnce(
    request: WitnessEvidenceAuthorityRequest,
  ): Promise<WitnessEvidenceAuthorityBundle> {
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
    const priorTreeSize = this.logEntries.length;
    this.logEntries.push(leafBytes);
    const entries = this.logEntries.map((entry) => entry.slice());
    const leafIndex = entries.length - 1;
    const rootHash = hex(await merkleTreeHash(entries));
    const treeHeadBody = {
      profile: "sky-high-fence-witness-merkle-v1" as const,
      schemaVersion: 1 as const,
      witnessId: request.scope.witnessId,
      authorityId: request.scope.authorityId,
      hostId: request.scope.hostId,
      logId: "synthetic-test-log",
      treeSize: entries.length,
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
      leafIndex,
      inclusionProofHex: (await inclusionProof(leafIndex, entries)).map(hex),
      consistencyProofHex: priorTreeSize > 0
        ? (await consistencyProof(priorTreeSize, entries)).map(hex)
        : [],
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


  /**
   * Expose only the ephemeral public trust anchor to test harnesses. The
   * private root key remains confined to this synthetic authority instance.
   * Production gateway configuration must continue to use independently
   * pinned roots and must never discover trust from an authority RPC.
   */
  async getPinnedRootKey(): Promise<PinnedRootKey> {
    const root = await this.rootKeyPromise;
    return {
      keyId: root.keyId,
      publicKeyBase64Url: base64url(root.publicKey),
    };
  }


  async verifyIssuedBundleExtension(
    priorBundle: WitnessEvidenceAuthorityBundle,
    currentBundle: WitnessEvidenceAuthorityBundle,
  ): Promise<void> {
    const root = await this.rootKeyPromise;
    const pinnedRoots: PinnedRootKey[] = [{
      keyId: root.keyId,
      publicKeyBase64Url: base64url(root.publicKey),
    }];
    const now = Math.floor(Date.now() / 1_000);
    const trust = await verifyTrustBundleEnvelope(priorBundle.trustBundleEnvelope, pinnedRoots, {
      generation: 0,
      digest: ZERO_DIGEST,
      trustDomainId: priorBundle.trustBundleEnvelope.body.trustDomainId,
      witnessId: priorBundle.trustBundleEnvelope.body.witnessId,
    });
    const priorHead = await verifySignedTreeHead(priorBundle.treeHeadEnvelope, trust, now, {
      witnessId: priorBundle.treeHeadEnvelope.body.witnessId,
      authorityId: priorBundle.treeHeadEnvelope.body.authorityId,
      hostId: priorBundle.treeHeadEnvelope.body.hostId,
    });
    const currentHead = await verifySignedTreeHead(currentBundle.treeHeadEnvelope, trust, now, {
      witnessId: currentBundle.treeHeadEnvelope.body.witnessId,
      authorityId: currentBundle.treeHeadEnvelope.body.authorityId,
      hostId: currentBundle.treeHeadEnvelope.body.hostId,
    });
    await verifyTreeHeadExtension(priorHead, currentHead, currentBundle.consistencyProofHex);
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
