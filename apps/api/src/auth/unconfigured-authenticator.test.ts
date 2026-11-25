import { describe, expect, it } from "vitest";
import { UnconfiguredAuthenticator } from "./unconfigured-authenticator";

describe("UnconfiguredAuthenticator", () => {
  it("fails closed even when a request supplies identity-looking headers", async () => {
    const authenticator = new UnconfiguredAuthenticator();
    const request = new Request("https://api.skyhigh.example/api/v1/problems", {
      headers: {
        Authorization: "Bearer fabricated-token",
        "X-Tenant-ID": "40000000-0000-4000-8000-000000000099",
        "X-User-ID": "50000000-0000-4000-8000-000000000099",
        "X-User-Role": "admin",
      },
    });

    await expect(authenticator.authenticate(request)).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
  });

  it("does not manufacture a principal when no credential is present", async () => {
    const authenticator = new UnconfiguredAuthenticator();
    const request = new Request("https://api.skyhigh.example/api/v1/problems");

    await expect(authenticator.authenticate(request)).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
  });
});
