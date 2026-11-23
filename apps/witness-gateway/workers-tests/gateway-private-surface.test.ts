import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("private witness gateway surface", () => {
  it("does not expose a public HTTP handler", async () => {
    const response = await SELF.fetch("https://gateway.invalid/");
    expect(response.status).toBe(404);
  });
});