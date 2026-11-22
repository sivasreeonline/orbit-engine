import { describe, expect, it } from "vitest";
import {
  authenticateWorkloadCall,
  workloadSigningBytes,
  type TrustedWorkloadKey,
  type WorkloadNonceStore,
  type WorkloadProof,
} from "./workload-identity";

const REQUEST = {
  audience: "fence-witness-gateway",
  scope: "witness-01:authority-01:host-01",
  method: "POST",
  path: "/internal/witness/append",
  body: new TextEncoder().encode('{"operationId":"op-001","digest":"a"}'),
};
const NOW = 1_800_000_000;

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function makeFixture() {
  const pair = (await crypto.subtle.generateKey(
    { name: "Ed25519" } as AlgorithmIdentifier,
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const keyId = [...new Uint8Array(await crypto.subtle.digest("SHA-256", publicBytes))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  const base = {
    callerId: "api-worker-prod",
    keyId,
    audience: REQUEST.audience,
    scope: REQUEST.scope,
    method: REQUEST.method,
    path: REQUEST.path,
    bodyDigest: [...new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(REQUEST.body)))]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join(""),
    issuedAt: NOW - 1,
    expiresAt: NOW + 30,
    nonce: "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZg",
  };
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" } as AlgorithmIdentifier,
    pair.privateKey,
    toArrayBuffer(workloadSigningBytes(base)),
  ));
  const proof: WorkloadProof = {
    ...base,
    signature: btoa(String.fromCharCode(...signature))
      .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"),
  };
  const trustedKey: TrustedWorkloadKey = {
    callerId: base.callerId,
    keyId,
    publicKeyBase64Url: btoa(String.fromCharCode(...publicBytes))
      .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"),
    audiences: [REQUEST.audience],
    scopes: [REQUEST.scope],
    notBefore: NOW - 100,
    notAfter: NOW + 100,
  };
  const consumed = new Set<string>();
  const store: WorkloadNonceStore = {
    async consumeNonce(callerId, nonce) {
      const id = callerId + ":" + nonce;
      if (consumed.has(id)) return false;
      consumed.add(id);
      return true;
    },
  };
  return { pair, proof, trustedKey, store, consumed };
}

describe("FENCE-001 Worker workload identity", () => {
  it("authenticates a signed request bound to audience, scope, route and exact body bytes", async () => {
    const fixture = await makeFixture();
    const result = await authenticateWorkloadCall(
      fixture.proof, REQUEST, [fixture.trustedKey], NOW, fixture.store,
    );
    expect(result).toEqual({
      authenticated: true,
      callerId: "api-worker-prod",
      scope: REQUEST.scope,
      keyId: fixture.trustedKey.keyId,
    });
    expect(fixture.consumed.size).toBe(1);
  });

  it("rejects nonce replay after valid signature verification", async () => {
    const fixture = await makeFixture();
    const first = await authenticateWorkloadCall(
      fixture.proof, REQUEST, [fixture.trustedKey], NOW, fixture.store,
    );
    const second = await authenticateWorkloadCall(
      fixture.proof, REQUEST, [fixture.trustedKey], NOW, fixture.store,
    );
    expect(first.authenticated).toBe(true);
    expect(second).toEqual({ authenticated: false, reason: "replayed_nonce" });
  });

  it("rejects invalid signatures before consuming the nonce", async () => {
    const fixture = await makeFixture();
    const invalid = { ...fixture.proof, signature: "A".repeat(86) };
    const result = await authenticateWorkloadCall(
      invalid, REQUEST, [fixture.trustedKey], NOW, fixture.store,
    );
    expect(result).toEqual({ authenticated: false, reason: "invalid_signature" });
    expect(fixture.consumed.size).toBe(0);
  });

  it("rejects audience, scope, method, path and body substitution", async () => {
    const fixture = await makeFixture();
    const mismatches = [
      { ...REQUEST, audience: "another-service" },
      { ...REQUEST, scope: "another-scope" },
      { ...REQUEST, method: "GET" },
      { ...REQUEST, path: "/internal/other" },
      { ...REQUEST, body: new TextEncoder().encode("substituted") },
    ];
    for (const request of mismatches) {
      const result = await authenticateWorkloadCall(
        fixture.proof, request, [fixture.trustedKey], NOW, fixture.store,
      );
      expect(result).toEqual({
        authenticated: false,
        reason: "request_binding_mismatch",
      });
    }
    expect(fixture.consumed.size).toBe(0);
  });

  it("rejects unknown, revoked and out-of-validity keys", async () => {
    const fixture = await makeFixture();
    expect(await authenticateWorkloadCall(
      fixture.proof, REQUEST, [], NOW, fixture.store,
    )).toEqual({ authenticated: false, reason: "unknown_key" });

    expect(await authenticateWorkloadCall(
      fixture.proof, REQUEST,
      [{ ...fixture.trustedKey, revokedAt: NOW - 1 }], NOW, fixture.store,
    )).toEqual({ authenticated: false, reason: "key_not_valid" });

    expect(await authenticateWorkloadCall(
      fixture.proof, REQUEST,
      [{ ...fixture.trustedKey, notAfter: NOW - 1 }], NOW, fixture.store,
    )).toEqual({ authenticated: false, reason: "key_not_valid" });
  });

  it("rejects stale, future and overlong proofs", async () => {
    const fixture = await makeFixture();
    for (const proof of [
      { ...fixture.proof, expiresAt: NOW },
      { ...fixture.proof, issuedAt: NOW + 31 },
      { ...fixture.proof, expiresAt: NOW + 61 },
    ]) {
      const result = await authenticateWorkloadCall(
        proof, REQUEST, [fixture.trustedKey], NOW, fixture.store,
      );
      expect(result).toEqual({
        authenticated: false,
        reason: "proof_time_invalid",
      });
    }
  });

  it("fails closed when the durable replay store is unavailable", async () => {
    const fixture = await makeFixture();
    const unavailable: WorkloadNonceStore = {
      async consumeNonce() { throw new Error("storage unavailable"); },
    };
    expect(await authenticateWorkloadCall(
      fixture.proof, REQUEST, [fixture.trustedKey], NOW, unavailable,
    )).toEqual({ authenticated: false, reason: "replay_store_unavailable" });
  });
});
