import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // API Worker tests do not exercise gateway RPC. Supply a closed,
        // deterministic local binding so unrelated API DO tests can start.
        serviceBindings: {
          WITNESS_GATEWAY: async () => new Response("Not Found", { status: 404 }),
        },
      },
    }),
  ],
  test: {
    include: ["workers-tests/**/*.test.ts"],
    clearMocks: true,
    restoreMocks: true,
  },
});
