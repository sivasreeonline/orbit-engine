import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { WitnessGatewayRpc } from "../src/witness/witness-gateway-contract";
import { createApiWorkloadProof } from "../src/witness/workload-proof-signer";
import { authenticateApiWorkerWithWitnessGateway } from "../src/witness/witness-gateway-client";

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
});
