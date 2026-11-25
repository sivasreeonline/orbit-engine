import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

interface WranglerConfig {
  readonly workers_dev?: boolean;
  readonly vars?: Record<string, string>;
  readonly env?: Record<string, {
    readonly services?: readonly {
      readonly binding: string;
      readonly service: string;
      readonly entrypoint?: string;
    }[];
  }>;
}

function readConfig(relativePath: string): WranglerConfig {
  const path = fileURLToPath(new URL(relativePath, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as WranglerConfig;
}

describe("production witness deployment fail-closed configuration", () => {
  const gateway = readConfig("../wrangler.jsonc");
  const provider = readConfig("../provider.wrangler.jsonc");

  it("does not bind a production evidence authority before qualification", () => {
    const services = gateway.env?.production?.services ?? [];
    expect(services).toContainEqual({
      binding: "WITNESS_PROVIDER",
      service: "sky-high-witness-provider",
      entrypoint: "WitnessProvider",
    });
    expect(services.some((service) => service.binding === "WITNESS_EVIDENCE_AUTHORITY"))
      .toBe(false);
  });

  it("keeps the production provider write switch explicitly disabled", () => {
    expect(provider.vars?.WITNESS_DDB_WRITES_ENABLED).toBe("false");
  });

  it("keeps both private Workers off the public workers.dev surface", () => {
    expect(gateway.workers_dev).toBe(false);
    expect(provider.workers_dev).toBe(false);
  });
});
