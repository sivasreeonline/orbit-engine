import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // Node unit tests use a minimal base-class shim. Workers runtime tests
      // use the real cloudflare:workers module through vitest.workers.config.ts.
      "cloudflare:workers": fileURLToPath(
        new URL("./src/test/cloudflare-workers-mock.ts", import.meta.url),
      ),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    clearMocks: true,
    restoreMocks: true,
  },
});
