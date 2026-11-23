import { readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";
import {
  consistencyProof,
  inclusionProof,
  merkleTreeHash,
  verifyReceiptAgainstTrustedBundle,
  verifySignedTreeHead,
  verifyTrustBundleEnvelope,
  verifyTreeHeadExtension,
  verifyWitnessEvidence,
  type WitnessTrustBundleBody,
  type WitnessTreeHeadBody,
} from "./witness-profile-verifier";

const receiptVector = JSON.parse(readFileSync(
  new URL("../../../../docs/test-vectors/fence-witness-v1-001.json", import.meta.url),
  "utf8",
)) as Record<string, any>;
const trustVector = JSON.parse(readFileSync(
  new URL("../../../../docs/test-vectors/fence-witness-v1-003-trust-bundle.json", import.meta.url),
  "utf8",
)) as Record<string, any>;

const TRUST_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\0";
const TREE_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TREE-HEAD-V1\0";
const ZERO_DIGEST = "0".repeat(64);
const trustedNow = Math.floor(Date.parse("2026-01-02T03:05:01Z") / 1_000);

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (part) => Number.parseInt(part, 16));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function privateKeyFromSeed(seedHex: string): Promise<CryptoKey> {
  const prefix = hexBytes("302e020100300506032b657004220420");
  const seed = hexBytes(seedHex);
  const der = new Uint8Array([...prefix, ...seed]);
  return crypto.subtle.importKey(
    "pkcs8",
    toArrayBuffer(der),
    { name: "Ed25519" } as AlgorithmIdentifier,
    true,
    ["sign"],
  );
}

async function publicKeyBytes(privateKey: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  if (!jwk.x) throw new Error("Ed25519 public coordinate missing");
  const binary = atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "==");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function sign(privateKey: CryptoKey, prefix: string, body: unknown): Promise<string> {
  const canonical = canonicalize(body);
  if (typeof canonical !== "string") throw new Error("test body is not canonicalizable");
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" } as AlgorithmIdentifier,
    privateKey,
    toArrayBuffer(new TextEncoder().encode(prefix + canonical)),
  ));
  return b64(signature);
}

async function fixtures() {
  const rootPrivateKey = await privateKeyFromSeed(trustVector.testRootKey.privateSeedHex);
  const rootPublicKeyBase64Url = trustVector.testRootKey.publicKeyBase64Url;
  const logPrivateKey = await privateKeyFromSeed("a1".repeat(32));
  const logPublicKey = await publicKeyBytes(logPrivateKey);
  const logKeyId = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(logPublicKey))));

  const trustBody = structuredClone(trustVector.generation1.body) as WitnessTrustBundleBody & {
    keys: Array<Record<string, unknown>>;
  };
  trustBody.keys.push({
    keyId: logKeyId,
    publicKeyBase64Url: b64(logPublicKey),
    purpose: "WITNESS_LOG_SIGNING",
    witnessId: trustBody.witnessId,
    authorityIds: ["authority-vector-01"],
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2030-01-01T00:00:00Z",
  });

  const canonicalTrustBody = canonicalize(trustBody);
  if (typeof canonicalTrustBody !== "string") throw new Error("trust body is not canonicalizable");
  const trustDigest = hex(new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalTrustBody),
  )));
  const rootSignature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" } as AlgorithmIdentifier,
    rootPrivateKey,
    toArrayBuffer(new TextEncoder().encode(TRUST_PREFIX + canonicalTrustBody)),
  ));
  const trustEnvelope = {
    body: trustBody,
    bundleDigest: trustDigest,
    rootKeyId: trustVector.testRootKey.keyId,
    rootSignature: b64(rootSignature),
  };
  const receiptEnvelope = {
    body: receiptVector.receiptBody,
    signature: receiptVector.signatureBase64Url,
  };
  const checkpointBody = receiptVector.checkpointBody;
  const checkpointDigest = receiptVector.checkpointDigest;

  const receiptBytes = new TextEncoder().encode(canonicalize(receiptEnvelope)!);
  const secondLeaf = new TextEncoder().encode("synthetic second receipt envelope");
  const entries = [receiptBytes, secondLeaf];
  const currentRoot = hex(await merkleTreeHash(entries));
  const priorRoot = hex(await merkleTreeHash(entries.slice(0, 1)));
  const scope = {
    witnessId: trustBody.witnessId,
    authorityId: "authority-vector-01",
    hostId: receiptVector.receiptBody.hostId,
  };
  const currentHeadBody: WitnessTreeHeadBody = {
    profile: "sky-high-fence-witness-merkle-v1",
    schemaVersion: 1,
    ...scope,
    logId: "synthetic-log-01",
    treeSize: 2,
    rootHash: currentRoot,
    timestamp: "2026-01-02T03:05:00Z",
    keyId: logKeyId,
  };
  const priorHeadBody: WitnessTreeHeadBody = {
    ...currentHeadBody,
    treeSize: 1,
    rootHash: priorRoot,
  };
  const currentHead = {
    body: currentHeadBody,
    signature: await sign(logPrivateKey, TREE_PREFIX, currentHeadBody),
  };
  const priorHead = {
    body: priorHeadBody,
    signature: await sign(logPrivateKey, TREE_PREFIX, priorHeadBody),
  };
  const rootPublicKey = rootPublicKeyBase64Url;
  return {
    trustBody,
    trustEnvelope,
    pinnedRoots: [{ keyId: trustVector.testRootKey.keyId, publicKeyBase64Url: rootPublicKey }],
    expectedTrustState: {
      generation: 0,
      digest: ZERO_DIGEST,
      trustDomainId: trustBody.trustDomainId,
      witnessId: trustBody.witnessId,
    },
    checkpointBody,
    checkpointDigest,
    receiptEnvelope,
    scope,
    currentHead,
    priorHead,
    logPrivateKey,
    entries,
    logKeyId,
  };
}

describe("FENCE-001 Worker cryptographic profile verifier", () => {
  it("verifies the existing root-signed trust bundle, receipt and signed tree-head vectors", async () => {
    const f = await fixtures();
    const trust = await verifyTrustBundleEnvelope(
      f.trustEnvelope,
      f.pinnedRoots,
      f.expectedTrustState,
    );
    expect(trust.digest).toBe(f.trustEnvelope.bundleDigest);

    const receipt = await verifyReceiptAgainstTrustedBundle(
      f.checkpointBody,
      f.checkpointDigest,
      f.receiptEnvelope,
      trust.body,
      trustedNow,
    );
    expect(receipt.body.checkpointDigest).toBe(f.checkpointDigest);

    const current = await verifySignedTreeHead(
      f.currentHead,
      trust.body,
      trustedNow,
      f.scope,
    );
    expect(current.treeSize).toBe(2);
    await expect(verifySignedTreeHead(f.priorHead, trust.body, trustedNow, f.scope))
      .resolves.toMatchObject({ treeSize: 1 });
  });

  it("verifies full-envelope receipt inclusion and prior-head consistency", async () => {
    const f = await fixtures();
    const inclusion = await inclusionProof(0, f.entries);
    const priorConsistency = await consistencyProof(1, f.entries);
    const current = f.currentHead.body;
    const leafHash = hex(new Uint8Array(await crypto.subtle.digest(
      "SHA-256",
      toArrayBuffer(new Uint8Array([0, ...new TextEncoder().encode(canonicalize(f.receiptEnvelope)!)])),
    )));
    expect(inclusion).toHaveLength(1);
    expect(leafHash).toHaveLength(64);

    const trust = await verifyTrustBundleEnvelope(f.trustEnvelope, f.pinnedRoots, f.expectedTrustState);
    const receipt = await verifyReceiptAgainstTrustedBundle(
      f.checkpointBody, f.checkpointDigest, f.receiptEnvelope, trust.body, trustedNow,
    );
    const verifiedHead = await verifySignedTreeHead(f.currentHead, trust.body, trustedNow, f.scope);
    const proofHex = inclusion.map(hex);
    const verified = await verifyWitnessEvidence({
      checkpointBody: f.checkpointBody,
      checkpointDigest: f.checkpointDigest,
      receiptEnvelope: receipt,
      trustBundle: f.trustEnvelope,
      pinnedRoots: f.pinnedRoots,
      expectedTrustState: f.expectedTrustState,
      trustedNow,
      treeHeadEnvelope: f.currentHead,
      expectedScope: f.scope,
      leafIndex: 0,
      inclusionProofHex: proofHex,
      priorTreeHead: f.priorHead.body,
      consistencyProofHex: priorConsistency.map(hex),
    });
    expect(verified.treeHead).toEqual(verifiedHead);
    expect(verified.receiptLeafHash).toBe(leafHash);
    expect(current.rootHash).toBe(f.currentHead.body.rootHash);
  });

  it("rejects wrong trust generation, root pin, and altered receipt signature", async () => {
    const f = await fixtures();
    await expect(verifyTrustBundleEnvelope(
      f.trustEnvelope,
      f.pinnedRoots,
      { ...f.expectedTrustState, generation: 1 },
    )).rejects.toThrow("generation");
    await expect(verifyTrustBundleEnvelope(
      f.trustEnvelope,
      [{ ...f.pinnedRoots[0], keyId: "f".repeat(64) }],
      f.expectedTrustState,
    )).rejects.toThrow("root key");

    const trust = await verifyTrustBundleEnvelope(f.trustEnvelope, f.pinnedRoots, f.expectedTrustState);
    await expect(verifyReceiptAgainstTrustedBundle(
      f.checkpointBody,
      f.checkpointDigest,
      { ...f.receiptEnvelope, signature: "A".repeat(86) },
      trust.body,
      trustedNow,
    )).rejects.toThrow();
  });

  it("rejects receipt-purpose keys for tree heads and invalid inclusion paths", async () => {
    const f = await fixtures();
    const wrongPurpose = structuredClone(f.trustBody);
    const logKey = wrongPurpose.keys.find((key) => key.keyId === f.logKeyId);
    if (!logKey) throw new Error("log key fixture missing");
    logKey.purpose = "WITNESS_RECEIPT_SIGNING";
    await expect(verifySignedTreeHead(
      f.currentHead,
      wrongPurpose as WitnessTrustBundleBody,
      trustedNow,
      f.scope,
    )).rejects.toThrow("purpose");

    const trust = await verifyTrustBundleEnvelope(f.trustEnvelope, f.pinnedRoots, f.expectedTrustState);
    const head = await verifySignedTreeHead(f.currentHead, trust.body, trustedNow, f.scope);
    await expect(import("./witness-profile-verifier").then(({ verifyReceiptInclusion }) =>
      verifyReceiptInclusion(f.receiptEnvelope, 0, head, ["f".repeat(64)]),
    )).rejects.toThrow("inclusion");
  });

  it("rejects tree-size rollback, same-size conflicting roots and altered consistency paths", async () => {
    const f = await fixtures();
    await expect(verifyTreeHeadExtension(
      { ...f.priorHead.body, treeSize: 3 },
      f.currentHead.body,
      [],
    )).rejects.toThrow("rollback");
    await expect(verifyTreeHeadExtension(
      f.currentHead.body,
      { ...f.currentHead.body, rootHash: "f".repeat(64) },
      [],
    )).rejects.toThrow("consistency");
    await expect(verifyTreeHeadExtension(
      f.priorHead.body,
      f.currentHead.body,
      ["f".repeat(64)],
    )).rejects.toThrow("consistency");
  });
});
