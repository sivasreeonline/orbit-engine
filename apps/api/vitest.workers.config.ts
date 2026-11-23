import { createHash, webcrypto } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export default defineConfig({
  plugins: [
    cloudflareTest(async () => {
      // Generate an ephemeral caller identity for this test runtime. The API
      // test Worker receives the private key; the gateway receives only the
      // matching pinned public key. No key material is persisted.
      const pair = await webcrypto.subtle.generateKey(
        { name: "Ed25519" } as AlgorithmIdentifier,
        true,
        ["sign", "verify"],
      ) as CryptoKeyPair;
      const publicKey = new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey));
      const privateKeyPkcs8 = new Uint8Array(
        await webcrypto.subtle.exportKey("pkcs8", pair.privateKey),
      );
      const callerId = "api-worker-rpc-integration-test";
      const keyId = createHash("sha256").update(publicKey).digest("hex");
      const trustedKeys = JSON.stringify([{
        callerId,
        keyId,
        publicKeyBase64Url: base64Url(publicKey),
        audiences: ["sky-high-witness-gateway"],
        scopes: ["witness:authorize"],
        notBefore: 1_700_000_000,
        notAfter: 2_000_000_000,
      }]);

      return {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            FENCE_TEST_CALLER_ID: callerId,
            FENCE_TEST_CALLER_KEY_ID: keyId,
            FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8: base64Url(privateKeyPkcs8),
          },
          workers: [
            {
              name: "sky-high-witness-gateway",
              scriptPath: ".test-dist/witness-gateway/index.js",
              modules: true,
              compatibilityDate: "2026-11-09",
              compatibilityFlags: ["nodejs_compat", "rpc"],
              bindings: {
                WORKLOAD_CALLER_KEYS: trustedKeys,
              },
              durableObjects: {
                WORKLOAD_NONCE_REPLAY: "WorkloadNonceReplayDO",
              },
            },
          ],
        },
      };
    }),
  ],
  test: {
    include: ["workers-tests/**/*.test.ts"],
    clearMocks: true,
    restoreMocks: true,
  },
});
