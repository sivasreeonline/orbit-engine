import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
        configure: (proxy) => {
          // The browser calls Vite same-origin; do not forward its Origin header
          // to the local Worker and accidentally invoke production CORS policy.
          proxy.on("proxyReq", (proxyRequest) => proxyRequest.removeHeader("origin"));
        },
      },
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    clearMocks: true,
    restoreMocks: true,
  },
});
