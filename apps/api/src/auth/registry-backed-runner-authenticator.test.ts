import { describe, expect, it, vi } from "vitest";
import type { RunnerPrincipal } from "./runner-authenticator";
import {
  RegistryBackedRunnerAuthenticator,
  runnerHasScope,
  type RunnerCredentialVerifier,
  type RunnerIdentityResolver,
} from "./registry-backed-runner-authenticator";

const principal: RunnerPrincipal = {
  runnerId: "runner-java-01",
  poolId: "pool-java",
  subject: "service-subject-01",
  scopes: ["dispatch:claim", "dispatch:receipt"],
};

function setup(
  verification: Awaited<ReturnType<RunnerCredentialVerifier["verify"]>> =
    { verified: true, identity: { issuer: "https://identity.example.test", subject: "service-subject-01" } },
  resolved: RunnerPrincipal | null = principal,
) {
  const verify = vi.fn<RunnerCredentialVerifier["verify"]>().mockResolvedValue(verification);
  const findActivePrincipal = vi.fn<RunnerIdentityResolver["findActivePrincipal"]>()
    .mockResolvedValue(resolved);
  const authenticator = new RegistryBackedRunnerAuthenticator(
    { verify },
    { findActivePrincipal },
  );
  return { authenticator, verify, findActivePrincipal };
}

const request = () => new Request(
  "https://api.skyhigh.example/internal/v1/runner/dispatch-claims",
  {
    headers: {
      Authorization: "Bearer unverified-test-token",
      "X-Runner-ID": "attacker-runner",
      "X-Runner-Pool": "attacker-pool",
      "X-Runner-Scopes": "dispatch:admin",
    },
  },
);

describe("RegistryBackedRunnerAuthenticator", () => {
  it("returns only the principal resolved from a verified issuer and subject", async () => {
    const { authenticator, verify, findActivePrincipal } = setup();

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: true,
      principal,
    });
    expect(verify).toHaveBeenCalledOnce();
    expect(findActivePrincipal).toHaveBeenCalledWith(
      "https://identity.example.test",
      "service-subject-01",
    );
  });

  it("does not query the registry when credentials are missing", async () => {
    const { authenticator, findActivePrincipal } = setup({
      verified: false,
      reason: "missing",
    });

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "missing",
    });
    expect(findActivePrincipal).not.toHaveBeenCalled();
  });

  it("rejects invalid credentials without a registry lookup", async () => {
    const { authenticator, findActivePrincipal } = setup({
      verified: false,
      reason: "invalid",
    });

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "invalid",
    });
    expect(findActivePrincipal).not.toHaveBeenCalled();
  });

  it("fails closed when the identity provider is unavailable", async () => {
    const { authenticator, findActivePrincipal } = setup({
      verified: false,
      reason: "provider_unavailable",
    });

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
    expect(findActivePrincipal).not.toHaveBeenCalled();
  });

  it("fails closed when the verifier throws", async () => {
    const verify = vi.fn().mockRejectedValue(new Error("provider internals"));
    const findActivePrincipal = vi.fn();
    const authenticator = new RegistryBackedRunnerAuthenticator(
      { verify },
      { findActivePrincipal },
    );

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
    expect(findActivePrincipal).not.toHaveBeenCalled();
  });

  it("fails closed when a verifier returns a malformed result", async () => {
    const verify = vi.fn().mockResolvedValue(undefined);
    const findActivePrincipal = vi.fn();
    const authenticator = new RegistryBackedRunnerAuthenticator(
      { verify },
      { findActivePrincipal },
    );

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
    expect(findActivePrincipal).not.toHaveBeenCalled();
  });

  it("rejects unknown, suspended, revoked or disabled-pool identities", async () => {
    const { authenticator, findActivePrincipal } = setup(
      undefined,
      null,
    );

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "invalid",
    });
    expect(findActivePrincipal).toHaveBeenCalledOnce();
  });

  it("fails closed when the registry is unavailable or inconsistent", async () => {
    const { verify } = setup();
    const findActivePrincipal = vi.fn().mockRejectedValue(new Error("database details"));
    const authenticator = new RegistryBackedRunnerAuthenticator(
      { verify },
      { findActivePrincipal },
    );

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "provider_unavailable",
    });
  });

  it("rejects malformed verified identity claims before registry access", async () => {
    const { authenticator, findActivePrincipal } = setup({
      verified: true,
      identity: { issuer: " https://identity.example.test", subject: "subject" },
    });

    await expect(authenticator.authenticate(request())).resolves.toEqual({
      authenticated: false,
      reason: "invalid",
    });
    expect(findActivePrincipal).not.toHaveBeenCalled();
  });

  it("does not derive runner identity or scopes from caller-controlled headers", async () => {
    const { authenticator, findActivePrincipal } = setup();
    const result = await authenticator.authenticate(request());

    expect(result).toEqual({ authenticated: true, principal });
    expect(findActivePrincipal).toHaveBeenCalledWith(
      "https://identity.example.test",
      "service-subject-01",
    );
    expect(result.authenticated && result.principal.runnerId).toBe("runner-java-01");
    expect(result.authenticated && result.principal.scopes).not.toContain("dispatch:admin");
  });
});

describe("runnerHasScope", () => {
  it("allows only scopes explicitly present on the trusted principal", () => {
    expect(runnerHasScope(principal, "dispatch:claim")).toBe(true);
    expect(runnerHasScope(principal, "dispatch:receipt")).toBe(true);
    expect(runnerHasScope(principal, "dispatch:retry")).toBe(false);
  });
});
