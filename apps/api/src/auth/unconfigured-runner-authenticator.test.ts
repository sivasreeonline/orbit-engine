import { describe, expect, it } from "vitest";
import { UnconfiguredRunnerAuthenticator } from "./unconfigured-runner-authenticator";

describe("UnconfiguredRunnerAuthenticator", () => {
  it("fails closed when no machine identity provider is configured", async () => {
    const authenticator = new UnconfiguredRunnerAuthenticator();

    await expect(
      authenticator.authenticate(new Request("https://api.skyhigh.example/internal/v1/runner/dispatch-claims")),
    ).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
  });

  it("does not trust client-supplied runner identity or scope headers", async () => {
    const authenticator = new UnconfiguredRunnerAuthenticator();
    const request = new Request(
      "https://api.skyhigh.example/internal/v1/runner/dispatch-claims",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer attacker-controlled-token",
          "X-Runner-ID": "runner-admin",
          "X-Runner-Pool": "production",
          "X-Runner-Scopes": "dispatch:claim dispatch:receipt",
        },
      },
    );

    await expect(authenticator.authenticate(request)).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
  });
});
