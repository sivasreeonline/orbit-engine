import { env } from "cloudflare:workers";
import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";
import type { WitnessGatewayRpc } from "../src/witness/witness-gateway-contract";
import { createApiWorkloadProof } from "../src/witness/workload-proof-signer";
import {
  authenticateApiWorkerWithWitnessGateway,
  verifyEvidenceViaWitnessGateway,
} from "../src/witness/witness-gateway-client";
import {
  consistencyProof,
  inclusionProof,
  merkleTreeHash,
} from "../src/witness/witness-profile-verifier";

interface IntegrationEnv {
  readonly WITNESS_GATEWAY: WitnessGatewayRpc;
  readonly FENCE_TEST_CALLER_ID: string;
  readonly FENCE_TEST_CALLER_KEY_ID: string;
  readonly FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8: string;
}

function testEnv(): IntegrationEnv {
  return env as unknown as IntegrationEnv;
}

function signerConfig(callerId = testEnv().FENCE_TEST_CALLER_ID) {
  const current = testEnv();
  return {
    callerId,
    keyId: current.FENCE_TEST_CALLER_KEY_ID,
    privateKeyPkcs8: current.FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8,
  };
}

function apiCallerEnv() {
  const current = testEnv();
  return {
    WITNESS_GATEWAY: current.WITNESS_GATEWAY,
    WORKLOAD_CALLER_ID: current.FENCE_TEST_CALLER_ID,
    WORKLOAD_CALLER_KEY_ID: current.FENCE_TEST_CALLER_KEY_ID,
    WORKLOAD_CALLER_PRIVATE_KEY_PKCS8: current.FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8,
  };
}

const RECEIPT_PREFIX = "SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\0";
const TRUST_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\0";
const TREE_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TREE-HEAD-V1\0";
const TEST_ROOT_SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TEST_ROOT_KEY_ID = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c";
const RECEIPT_KEY_ID = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
const RECEIPT_PUBLIC_KEY = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (part) => Number.parseInt(part, 16));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signCanonical(
  privateKey: CryptoKey,
  prefix: string,
  body: unknown,
): Promise<string> {
  const canonical = canonicalize(body);
  if (typeof canonical !== "string") throw new Error("evidence fixture is not canonicalizable");
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" } as AlgorithmIdentifier,
    privateKey,
    toArrayBuffer(new TextEncoder().encode(prefix + canonical)),
  ));
  return base64Url(signature);
}

async function buildEvidenceFixtures() {
  const receiptBody = {
    profile: "sky-high-fence-witness-v1",
    schemaVersion: 1,
    witnessId: "witness-vector-01",
    authorityId: "authority-vector-01",
    hostId: "host-vector-01",
    generation: 1,
    operationId: "operation-vector-01",
    checkpointDigest: "05ad1de59f9c76354739640a0012eaaa45a2432dab7f656a5f9f444ac0019832",
    previousCheckpointDigest: "0".repeat(64),
    keyId: RECEIPT_KEY_ID,
    committedAt: "2026-01-02T03:04:05Z",
    consistencyToken: "test-only-token-generation-1",
  };
  const receiptEnvelope = {
    body: receiptBody,
    signature: "dovaVFLJJ0-wdsquBQMb5qFYaWTTskb7dCXs3Nq_GHx00SD68fISBMoVbe_I3ql_74ltie_fPsNgrVInH-9FDw",
  };
  const checkpointBody = {
    profile: "sky-high-fence-witness-v1",
    schemaVersion: 1,
    authorityId: "authority-vector-01",
    hostId: "host-vector-01",
    generation: 1,
    phase: "ISSUED",
    operationId: "operation-vector-01",
    previousCheckpointDigest: "0".repeat(64),
    authorityStateDigest: "1".repeat(64),
    responseDigest: "2".repeat(64),
    epoch: 1,
    recordVersion: 1,
  };
  const checkpointDigest = "05ad1de59f9c76354739640a0012eaaa45a2432dab7f656a5f9f444ac0019832";

  const rootPrefix = hexBytes("302e020100300506032b657004220420");
  const rootPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    toArrayBuffer(new Uint8Array([...rootPrefix, ...hexBytes(TEST_ROOT_SEED)])),
    { name: "Ed25519" } as AlgorithmIdentifier,
    false,
    ["sign"],
  );
  const logPair = await crypto.subtle.generateKey(
    { name: "Ed25519" } as AlgorithmIdentifier,
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const logPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", logPair.publicKey));
  const logKeyId = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(logPublicKey))));

  const trustBody = {
    profile: "sky-high-fence-witness-v1",
    schemaVersion: 1,
    trustDomainId: "test-trust-domain-vector-01",
    witnessId: "witness-vector-01",
    generation: 1,
    previousBundleDigest: "0".repeat(64),
    keys: [
      {
        keyId: RECEIPT_KEY_ID,
        publicKeyBase64Url: RECEIPT_PUBLIC_KEY,
        purpose: "WITNESS_RECEIPT_SIGNING",
        witnessId: "witness-vector-01",
        authorityIds: ["authority-vector-01", "authority-é-雪"],
        notBefore: "2026-01-01T00:00:00Z",
        notAfter: "2030-01-01T00:00:00Z",
      },
      {
        keyId: logKeyId,
        publicKeyBase64Url: base64Url(logPublicKey),
        purpose: "WITNESS_LOG_SIGNING",
        witnessId: "witness-vector-01",
        authorityIds: ["authority-vector-01"],
        notBefore: "2026-01-01T00:00:00Z",
        notAfter: "2030-01-01T00:00:00Z",
      },
    ],
    revocations: [],
  };
  const trustCanonical = canonicalize(trustBody);
  if (typeof trustCanonical !== "string") throw new Error("trust fixture is not canonicalizable");
  const trustDigest = hex(new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(trustCanonical),
  )));
  const trustBundle = {
    body: trustBody,
    bundleDigest: trustDigest,
    rootKeyId: TEST_ROOT_KEY_ID,
    rootSignature: await signCanonical(rootPrivateKey, TRUST_PREFIX, trustBody),
  };

  const receiptBytes = new TextEncoder().encode(canonicalize(receiptEnvelope)!);
  const entriesTwo = [
    receiptBytes,
    new TextEncoder().encode("synthetic witness log leaf 2"),
  ];
  const entriesThree = [
    ...entriesTwo,
    new TextEncoder().encode("synthetic witness log leaf 3"),
  ];
  const timestamp = new Date((Math.floor(Date.now() / 1_000) - 1) * 1_000).toISOString();

  async function evidenceFor(
    entries: Uint8Array[],
    treeSize: number,
    consistency: readonly Uint8Array[],
  ): Promise<Uint8Array> {
    const rootHash = hex(await merkleTreeHash(entries));
    const treeHeadBody = {
      profile: "sky-high-fence-witness-merkle-v1",
      schemaVersion: 1,
      witnessId: "witness-vector-01",
      authorityId: "authority-vector-01",
      hostId: "host-vector-01",
      logId: "synthetic-worker-integration-log",
      treeSize,
      rootHash,
      timestamp,
      keyId: logKeyId,
    };
    const treeHeadEnvelope = {
      body: treeHeadBody,
      signature: await signCanonical(logPair.privateKey, TREE_PREFIX, treeHeadBody),
    };
    const inclusion = await inclusionProof(0, entries);
    const request = {
      trustBundle,
      checkpointBody,
      checkpointDigest,
      receiptEnvelope,
      treeHeadEnvelope,
      leafIndex: 0,
      inclusionProofHex: inclusion.map(hex),
      consistencyProofHex: consistency.map(hex),
    };
    const serialized = canonicalize(request);
    if (typeof serialized !== "string") throw new Error("evidence request is not canonicalizable");
    return new TextEncoder().encode(serialized);
  }

  return {
    first: await evidenceFor(entriesTwo, 2, []),
    second: await evidenceFor(entriesThree, 3, await consistencyProof(2, entriesThree)),
  };
}

describe("API-to-private-witness-gateway RPC integration", () => {
  it("authenticates a real API-signed proof through the named WorkerEntrypoint binding", async () => {
    const body = new TextEncoder().encode('{"operationId":"rpc-integration-001","digest":"abc123"}');
    const result = await authenticateApiWorkerWithWitnessGateway(
      apiCallerEnv(),
      body,
    );
    expect(result).toMatchObject({
      authenticated: true,
      callerId: testEnv().FENCE_TEST_CALLER_ID,
      scope: "witness:authorize",
      keyId: testEnv().FENCE_TEST_CALLER_KEY_ID,
    });
  });

  it("persists nonce consumption in the gateway-owned Durable Object across RPC calls", async () => {
    const body = new TextEncoder().encode('{"operationId":"rpc-replay-001"}');
    const created = await createApiWorkloadProof(signerConfig(), body);
    expect(created.created).toBe(true);
    if (!created.created) return;

    const gateway = testEnv().WITNESS_GATEWAY;
    const first = await gateway.authenticate(created.proof, body);
    const replay = await gateway.authenticate(created.proof, body);
    expect(first.authenticated).toBe(true);
    expect(replay).toEqual({
      authenticated: false,
      reason: "replayed_nonce",
    });
  });

  it("rejects body substitution without consuming the valid proof nonce", async () => {
    const body = new TextEncoder().encode('{"operationId":"rpc-body-001"}');
    const substituted = new TextEncoder().encode('{"operationId":"substituted"}');
    const created = await createApiWorkloadProof(signerConfig(), body);
    expect(created.created).toBe(true);
    if (!created.created) return;

    const gateway = testEnv().WITNESS_GATEWAY;
    expect(await gateway.authenticate(created.proof, substituted)).toEqual({
      authenticated: false,
      reason: "request_binding_mismatch",
    });
    expect((await gateway.authenticate(created.proof, body)).authenticated).toBe(true);
  });

  it("rejects a correctly signed proof from a caller absent from the pinned allowlist", async () => {
    const body = new TextEncoder().encode('{"operationId":"rpc-unknown-caller"}');
    const created = await createApiWorkloadProof(
      signerConfig("unlisted-api-worker"),
      body,
    );
    expect(created.created).toBe(true);
    if (!created.created) return;

    expect(await testEnv().WITNESS_GATEWAY.authenticate(created.proof, body)).toEqual({
      authenticated: false,
      reason: "unknown_key",
    });
  });

  it("rejects a tampered signature over the real RPC boundary", async () => {
    const body = new TextEncoder().encode('{"operationId":"rpc-signature-001"}');
    const created = await createApiWorkloadProof(signerConfig(), body);
    expect(created.created).toBe(true);
    if (!created.created) return;

    const tampered = {
      ...created.proof,
      signature: "A".repeat(86),
    };
    expect(await testEnv().WITNESS_GATEWAY.authenticate(tampered, body)).toEqual({
      authenticated: false,
      reason: "invalid_signature",
    });
  });
  it("verifies receipts, signed heads and Merkle consistency using durable gateway state", async () => {
    const evidence = await buildEvidenceFixtures();
    const first = await verifyEvidenceViaWitnessGateway(apiCallerEnv(), evidence.first);
    expect(first).toMatchObject({
      verified: true,
      trustBundleGeneration: 1,
      treeSize: 2,
    });

    const second = await verifyEvidenceViaWitnessGateway(apiCallerEnv(), evidence.second);
    expect(second).toMatchObject({
      verified: true,
      trustBundleGeneration: 1,
      treeSize: 3,
    });

    const tamperedObject = JSON.parse(new TextDecoder().decode(evidence.second));
    tamperedObject.inclusionProofHex[0] = "f".repeat(64);
    const tamperedBody = new TextEncoder().encode(canonicalize(tamperedObject)!);
    const created = await createApiWorkloadProof(signerConfig(), tamperedBody, "verify_evidence");
    expect(created.created).toBe(true);
    if (!created.created) return;

    const gateway = testEnv().WITNESS_GATEWAY;
    expect(await gateway.verifyEvidence(created.proof, tamperedBody)).toEqual({
      verified: false,
      reason: "inclusion_invalid",
    });
    expect(await gateway.verifyEvidence(created.proof, tamperedBody)).toEqual({
      verified: false,
      reason: "workload_authentication_failed",
    });
  });

});
