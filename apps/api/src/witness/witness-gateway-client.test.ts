import { describe, expect, it } from "vitest";
import {
  authenticateApiWorkerWithWitnessGateway,
  checkpointReplayViaWitnessGateway,
  verifyEvidenceViaWitnessGateway,
} from "./witness-gateway-client";

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function signerConfig() {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" } as AlgorithmIdentifier,
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(publicBytes)));
  return {
    callerId: "api-worker-test",
    keyId: [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
    privateKeyPkcs8: encodeBase64Url(privateBytes),
  };
}

describe("private witness gateway client", () => {
  it("sends only the signed proof and exact body through the RPC binding", async () => {
    const config = await signerConfig();
    const body = new TextEncoder().encode('{"digest":"test"}');
    let receivedProof: unknown;
    let receivedBody: Uint8Array | undefined;
    const env = {
      ...{
        WORKLOAD_CALLER_ID: config.callerId,
        WORKLOAD_CALLER_KEY_ID: config.keyId,
        WORKLOAD_CALLER_PRIVATE_KEY_PKCS8: config.privateKeyPkcs8,
      },
      WITNESS_GATEWAY: {
        async authenticate(proof: unknown, requestBody: Uint8Array) {
          receivedProof = proof;
          receivedBody = requestBody;
          return {
            authenticated: true as const,
            callerId: "api-worker-test",
            scope: "witness:authorize",
            keyId: config.keyId,
          };
        },
        async verifyEvidence() {
          return {
            verified: false as const,
            reason: "malformed_request" as const,
          };
        },
        async checkpointReplay() {
          return { checkpointed: false as const, reason: "provider_unavailable" as const };
        },
      },
    };

    const result = await authenticateApiWorkerWithWitnessGateway(env, body);
    expect(result).toEqual({
      authenticated: true,
      callerId: "api-worker-test",
      scope: "witness:authorize",
      keyId: config.keyId,
    });
    expect(receivedProof).toMatchObject({
      callerId: "api-worker-test",
      audience: "sky-high-witness-gateway",
      scope: "witness:authorize",
      method: "POST",
      path: "/rpc/authenticate",
    });
    expect(receivedBody).toBe(body);
  });

  it("does not call the gateway when caller secrets are missing", async () => {
    let called = false;
    const result = await authenticateApiWorkerWithWitnessGateway({
      WITNESS_GATEWAY: {
        async authenticate() {
          called = true;
          return { authenticated: false as const, reason: "unknown_key" as const };
        },
        async verifyEvidence() {
          called = true;
          return { verified: false as const, reason: "malformed_request" as const };
        },
        async checkpointReplay() {
          return { checkpointed: false as const, reason: "provider_unavailable" as const };
        },
      },
    }, new Uint8Array());

    expect(result).toEqual({
      authenticated: false,
      reason: "caller_identity_unconfigured",
    });
    expect(called).toBe(false);
  });

  it("fails closed when the private gateway binding is absent", async () => {
    const result = await authenticateApiWorkerWithWitnessGateway({}, new Uint8Array());
    expect(result).toEqual({
      authenticated: false,
      reason: "gateway_unavailable",
    });
  });
  it("signs the evidence-verification operation with its dedicated scope and path", async () => {
    const config = await signerConfig();
    const body = new TextEncoder().encode('{"checkpointDigest":"test"}');
    let receivedProof: unknown;
    let receivedBody: Uint8Array | undefined;
    const env = {
      WORKLOAD_CALLER_ID: config.callerId,
      WORKLOAD_CALLER_KEY_ID: config.keyId,
      WORKLOAD_CALLER_PRIVATE_KEY_PKCS8: config.privateKeyPkcs8,
      WITNESS_GATEWAY: {
        async authenticate() {
          return { authenticated: false as const, reason: "unknown_key" as const };
        },
        async verifyEvidence(proof: unknown, requestBody: Uint8Array) {
          receivedProof = proof;
          receivedBody = requestBody;
          return {
            verified: true as const,
            trustBundleGeneration: 1,
            trustBundleDigest: "1".repeat(64),
            treeHeadDigest: "2".repeat(64),
            treeSize: 2,
            receiptLeafHash: "3".repeat(64),
          };
        },
        async checkpointReplay() {
          return { checkpointed: false as const, reason: "provider_unavailable" as const };
        },
      },
    };

    const result = await verifyEvidenceViaWitnessGateway(env, body);
    expect(result).toMatchObject({ verified: true, treeSize: 2 });
    expect(receivedProof).toMatchObject({
      audience: "sky-high-witness-gateway",
      scope: "witness:verify-evidence",
      method: "POST",
      path: "/rpc/verify-evidence",
    });
    expect(receivedBody).toBe(body);
  });

  it("signs the replay-checkpoint operation with its dedicated scope and exact body", async () => {
    const config = await signerConfig();
    const body = new TextEncoder().encode('{"operationId":"fence-monitor-replay-test"}');
    let receivedProof: unknown;
    let receivedBody: Uint8Array | undefined;
    const env = {
      WORKLOAD_CALLER_ID: config.callerId,
      WORKLOAD_CALLER_KEY_ID: config.keyId,
      WORKLOAD_CALLER_PRIVATE_KEY_PKCS8: config.privateKeyPkcs8,
      WITNESS_GATEWAY: {
        async authenticate() {
          return { authenticated: false as const, reason: "unknown_key" as const };
        },
        async verifyEvidence() {
          return { verified: false as const, reason: "malformed_request" as const };
        },
        async checkpointReplay(proof: unknown, requestBody: Uint8Array) {
          receivedProof = proof;
          receivedBody = requestBody;
          return { checkpointed: false as const, reason: "provider_unavailable" as const };
        },
      },
    };

    const result = await checkpointReplayViaWitnessGateway(env, body);
    expect(result).toEqual({ checkpointed: false, reason: "provider_unavailable" });
    expect(receivedProof).toMatchObject({
      audience: "sky-high-witness-gateway",
      scope: "witness:checkpoint-replay",
      method: "POST",
      path: "/rpc/checkpoint-replay",
    });
    expect(receivedBody).toBe(body);
  });

});
