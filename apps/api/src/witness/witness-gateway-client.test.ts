import { describe, expect, it } from "vitest";
import { authenticateApiWorkerWithWitnessGateway } from "./witness-gateway-client";

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
});
