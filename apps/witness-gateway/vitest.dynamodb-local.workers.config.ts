import { createHash, randomUUID, webcrypto } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export default defineConfig({
  plugins: [
    cloudflareTest(async () => {
      const endpoint = process.env.FENCE_DDB_LOCAL_ENDPOINT;
      if (!endpoint) {
        throw new Error("FENCE_DDB_LOCAL_ENDPOINT must point to the CI DynamoDB Local service");
      }

      const callerPair = await webcrypto.subtle.generateKey(
        { name: "Ed25519" } as AlgorithmIdentifier,
        true,
        ["sign", "verify"],
      ) as CryptoKeyPair;
      const callerPublic = new Uint8Array(await webcrypto.subtle.exportKey("raw", callerPair.publicKey));
      const callerPrivate = new Uint8Array(await webcrypto.subtle.exportKey("pkcs8", callerPair.privateKey));
      const callerId = "gateway-dynamodb-local-integration";
      const callerKeyId = createHash("sha256").update(callerPublic).digest("hex");

      const rootPair = await webcrypto.subtle.generateKey(
        { name: "Ed25519" } as AlgorithmIdentifier,
        true,
        ["sign", "verify"],
      ) as CryptoKeyPair;
      const rootPublic = new Uint8Array(await webcrypto.subtle.exportKey("raw", rootPair.publicKey));
      const rootPrivate = new Uint8Array(await webcrypto.subtle.exportKey("pkcs8", rootPair.privateKey));
      const rootKeyId = createHash("sha256").update(rootPublic).digest("hex");

      const tableName = `fence-workerd-${randomUUID().replace(/-/g, "").slice(0, 20)}`;
      const trustedKeys = JSON.stringify([{
        callerId,
        keyId: callerKeyId,
        publicKeyBase64Url: base64Url(callerPublic),
        audiences: ["sky-high-witness-gateway"],
        scopes: ["witness:checkpoint-replay", "witness:verify-evidence"],
        notBefore: 1_700_000_000,
        notAfter: 2_000_000_000,
      }]);

      return {
        wrangler: { configPath: "./test-support/gateway-integration-client.wrangler.jsonc" },
        miniflare: {
          bindings: {
            FENCE_TEST_CALLER_ID: callerId,
            FENCE_TEST_CALLER_KEY_ID: callerKeyId,
            FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8: base64Url(callerPrivate),
            FENCE_DDB_LOCAL_ENDPOINT: endpoint,
            FENCE_DDB_LOCAL_REGION: "us-east-1",
            FENCE_DDB_LOCAL_TABLE_NAME: tableName,
          },
          workers: [
            {
              name: "sky-high-dynamodb-local-witness-provider",
              scriptPath: ".test-dist/dynamodb-local-provider/dynamodb-local-provider-worker.js",
              modules: true,
              compatibilityDate: "2026-11-09",
              compatibilityFlags: ["nodejs_compat", "rpc"],
              bindings: {
                FENCE_DDB_LOCAL_ENDPOINT: endpoint,
                FENCE_DDB_LOCAL_REGION: "us-east-1",
                FENCE_DDB_LOCAL_TABLE_NAME: tableName,
              },
            },
            {
              name: "sky-high-synthetic-witness-services",
              scriptPath: ".test-dist/synthetic-witness-services/index.js",
              modules: true,
              compatibilityDate: "2026-11-09",
              compatibilityFlags: ["nodejs_compat", "rpc"],
              bindings: {
                FENCE_TEST_AUTHORITY_ROOT_PRIVATE_KEY_PKCS8: base64Url(rootPrivate),
                FENCE_TEST_AUTHORITY_ROOT_PUBLIC_KEY_BASE64URL: base64Url(rootPublic),
              },
            },
            {
              name: "sky-high-witness-gateway-dynamodb-local",
              scriptPath: ".test-dist/witness-gateway/index.js",
              modules: true,
              compatibilityDate: "2026-11-09",
              compatibilityFlags: ["nodejs_compat", "rpc"],
              bindings: {
                WORKLOAD_CALLER_KEYS: trustedKeys,
                WITNESS_ROOT_KEYS: JSON.stringify([{
                  keyId: rootKeyId,
                  publicKeyBase64Url: base64Url(rootPublic),
                }]),
                WITNESS_TRUST_SCOPES: JSON.stringify([{
                  trustDomainId: "workerd-dynamodb-domain",
                  witnessId: "workerd-dynamodb-witness",
                  authorityId: "workerd-dynamodb-authority",
                  hostId: "workerd-dynamodb-host",
                }]),
              },
              serviceBindings: {
                WITNESS_PROVIDER: {
                  name: "sky-high-dynamodb-local-witness-provider",
                  entrypoint: "DynamoDBLocalWitnessProvider",
                },
                WITNESS_EVIDENCE_AUTHORITY: {
                  name: "sky-high-synthetic-witness-services",
                  entrypoint: "SyntheticWitnessEvidenceAuthorityEntrypoint",
                },
              },
              durableObjects: {
                WORKLOAD_NONCE_REPLAY: "WorkloadNonceReplayDO",
                WITNESS_TRUST_STATE: "WitnessTrustStateDO",
              },
            },
          ],
        },
      };
    }),
  ],
  test: {
    include: ["workers-tests/dynamodb-local-gateway.test.ts"],
    clearMocks: true,
    restoreMocks: true,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
