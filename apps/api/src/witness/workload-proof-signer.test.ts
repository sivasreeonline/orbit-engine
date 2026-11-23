import { describe, expect, it } from "vitest";
import {
  createApiWorkloadProof,
  type WorkloadSignerConfig,
} from "./workload-proof-signer";
import { workloadSigningBytes } from "./workload-identity";

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

async function fixture(): Promise<{
  config: WorkloadSignerConfig;
  publicKey: CryptoKey;
}> {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" } as AlgorithmIdentifier,
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(publicBytes)));
  const keyId = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return {
    config: {
      callerId: "api-worker-test",
      keyId,
      privateKeyPkcs8: encodeBase64Url(privateBytes),
    },
    publicKey: pair.publicKey,
  };
}

describe("API workload proof signer", () => {
  it("creates a short-lived Ed25519 proof bound to the exact body", async () => {
    const keys = await fixture();
    const body = new TextEncoder().encode('{"operation":"witness-authorize"}');
    const result = await createApiWorkloadProof(keys.config, body);
    expect(result.created).toBe(true);
    if (!result.created) return;

    const { proof } = result;
    expect(proof.callerId).toBe("api-worker-test");
    expect(proof.audience).toBe("sky-high-witness-gateway");
    expect(proof.scope).toBe("witness:authorize");
    expect(proof.method).toBe("POST");
    expect(proof.path).toBe("/rpc/authenticate");
    expect(proof.expiresAt - proof.issuedAt).toBe(45);
    expect(proof.nonce).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(proof.bodyDigest).toMatch(/^[0-9a-f]{64}$/);

    const signature = Uint8Array.from(
      atob(proof.signature.replace(/-/g, "+").replace(/_/g, "/") + "=="),
      (character) => character.charCodeAt(0),
    );
    expect(await crypto.subtle.verify(
      { name: "Ed25519" } as AlgorithmIdentifier,
      keys.publicKey,
      toArrayBuffer(signature),
      toArrayBuffer(workloadSigningBytes({
        callerId: proof.callerId,
        keyId: proof.keyId,
        audience: proof.audience,
        scope: proof.scope,
        method: proof.method,
        path: proof.path,
        bodyDigest: proof.bodyDigest,
        issuedAt: proof.issuedAt,
        expiresAt: proof.expiresAt,
        nonce: proof.nonce,
      })),
    )).toBe(true);
  });

  it("fails closed when caller identity configuration is missing", async () => {
    expect(await createApiWorkloadProof({}, new Uint8Array())).toEqual({
      created: false,
      reason: "caller_identity_unconfigured",
    });
  });

  it("fails closed when private key material cannot be imported", async () => {
    const result = await createApiWorkloadProof({
      callerId: "api-worker-test",
      keyId: "a".repeat(64),
      privateKeyPkcs8: "not-a-private-key",
    }, new Uint8Array());
    expect(result).toEqual({
      created: false,
      reason: "caller_proof_signing_failed",
    });
  });
  it("uses the dedicated evidence-verification audience scope and RPC path", async () => {
    const keys = await fixture();
    const result = await createApiWorkloadProof(
      keys.config,
      new TextEncoder().encode('{"evidence":"test"}'),
      "verify_evidence",
    );
    expect(result.created).toBe(true);
    if (!result.created) return;
    expect(result.proof).toMatchObject({
      audience: "sky-high-witness-gateway",
      scope: "witness:verify-evidence",
      method: "POST",
      path: "/rpc/verify-evidence",
    });
  });

});
