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
        scopes: ["witness:authorize", "witness:verify-evidence", "witness:checkpoint-replay"],
        notBefore: 1_700_000_000,
        notAfter: 2_000_000_000,
      }]);

      // One independent ephemeral root is generated for the synthetic evidence
      // authority. Only its public half is pinned by the gateway Worker.
      const authorityRootPair = await webcrypto.subtle.generateKey(
        { name: "Ed25519" } as AlgorithmIdentifier,
        true,
        ["sign", "verify"],
      ) as CryptoKeyPair;
      const authorityRootPublicKey = new Uint8Array(
        await webcrypto.subtle.exportKey("raw", authorityRootPair.publicKey),
      );
      const authorityRootPrivateKeyPkcs8 = new Uint8Array(
        await webcrypto.subtle.exportKey("pkcs8", authorityRootPair.privateKey),
      );
      const authorityRootKeyId = createHash("sha256")
        .update(authorityRootPublicKey)
        .digest("hex");

      return {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            FENCE_TEST_CALLER_ID: callerId,
            FENCE_TEST_CALLER_KEY_ID: keyId,
            FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8: base64Url(privateKeyPkcs8),
            // Durable Objects use the production Env field names when signing
            // their recovery RPC; supply the same ephemeral test identity.
            WORKLOAD_CALLER_ID: callerId,
            WORKLOAD_CALLER_KEY_ID: keyId,
            WORKLOAD_CALLER_PRIVATE_KEY_PKCS8: base64Url(privateKeyPkcs8),
          },
          workers: [
            {
              name: "sky-high-synthetic-witness-provider",
              scriptPath: ".test-dist/synthetic-witness-provider/index.js",
              modules: true,
              compatibilityDate: "2026-11-09",
              compatibilityFlags: ["nodejs_compat", "rpc"],
              bindings: {
                // The provider receives only its one-shot lost-ack test flag.
                // It has no evidence-authority private key binding.
                FENCE_TEST_PROVIDER_LOSE_NEXT_ACK: "true",
              },
            },
            {
              name: "sky-high-synthetic-evidence-authority",
              scriptPath: ".test-dist/synthetic-evidence-authority/index.js",
              modules: true,
              compatibilityDate: "2026-11-09",
              compatibilityFlags: ["nodejs_compat", "rpc"],
              bindings: {
                FENCE_TEST_AUTHORITY_ROOT_PRIVATE_KEY_PKCS8: base64Url(authorityRootPrivateKeyPkcs8),
                FENCE_TEST_AUTHORITY_ROOT_PUBLIC_KEY_BASE64URL: base64Url(authorityRootPublicKey),
                // Provider commit succeeds, but independent evidence issuance is unavailable once.
                FENCE_TEST_AUTHORITY_FAIL_NEXT_ISSUANCE: "true",
                // Next return a shape-valid proof with a bad hash; API verification must reject it.
                FENCE_TEST_AUTHORITY_CORRUPT_NEXT_PROOF: "true",
              },
            },
            {
              name: "sky-high-witness-gateway",
              scriptPath: ".test-dist/witness-gateway/index.js",
              modules: true,
              compatibilityDate: "2026-11-09",
              compatibilityFlags: ["nodejs_compat", "rpc"],
              bindings: {
                WORKLOAD_CALLER_KEYS: trustedKeys,
                WITNESS_ROOT_KEYS: JSON.stringify([
                  {
                    keyId: authorityRootKeyId,
                    publicKeyBase64Url: base64Url(authorityRootPublicKey),
                  },
                  // Retain the independent fixed cryptographic vector used by
                  // the gateway's verifier integration test.
                  {
                    keyId: "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
                    publicKeyBase64Url: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
                  },
                ]),
                WITNESS_TRUST_SCOPES: JSON.stringify([
                  {
                    trustDomainId: "runtime-domain",
                    witnessId: "runtime-witness",
                    authorityId: "runtime-authority",
                    hostId: "runtime-host",
                  },
                  {
                    trustDomainId: "test-trust-domain-vector-01",
                    witnessId: "witness-vector-01",
                    authorityId: "authority-vector-01",
                    hostId: "host-vector-01",
                  },
                ]),
              },
              serviceBindings: {
                WITNESS_PROVIDER: {
                  name: "sky-high-synthetic-witness-provider",
                  entrypoint: "SyntheticWitnessProvider",
                },
                WITNESS_EVIDENCE_AUTHORITY: {
                  name: "sky-high-synthetic-evidence-authority",
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
    include: ["workers-tests/**/*.test.ts"],
    clearMocks: true,
    restoreMocks: true,
  },
});
