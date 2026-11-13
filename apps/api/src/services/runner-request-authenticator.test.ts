import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
  authenticateRunnerRequest,
  RUNNER_AUTH_HEADERS,
  RUNNER_REQUEST_CLOCK_SKEW_SECONDS,
} from "./runner-request-authenticator";

interface Fixture {
  readonly keyId: string;
  readonly method: string;
  readonly path: string;
  readonly timestamp: string;
  readonly nonce: string;
  readonly bodyUtf8: string;
  readonly publicKeyBase64Url: string;
  readonly signatureBase64Url: string;
}

const fixture = JSON.parse(readFileSync(
  new URL("../../../../test-fixtures/runner-ed25519-v1.json", import.meta.url),
  "utf8",
)) as Fixture;

function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

const now = new Date(Number(fixture.timestamp) * 1000);
const rawBody = new TextEncoder().encode(fixture.bodyUtf8);
const runnerId = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";

function makeRequest(overrides: Partial<{
  keyId: string; timestamp: string; nonce: string; signature: string; path: string; method: string;
}> = {}) {
  return new Request(`https://control.example${overrides.path ?? fixture.path}`, {
    method: overrides.method ?? fixture.method,
    headers: {
      [RUNNER_AUTH_HEADERS.keyId]: overrides.keyId ?? fixture.keyId,
      [RUNNER_AUTH_HEADERS.timestamp]: overrides.timestamp ?? fixture.timestamp,
      [RUNNER_AUTH_HEADERS.nonce]: overrides.nonce ?? fixture.nonce,
      [RUNNER_AUTH_HEADERS.signature]: overrides.signature ?? fixture.signatureBase64Url,
    },
  });
}

function makeIdentityStore(overrides: {
  activeKey?: { keyId: string; runnerId: string; publicKey: Uint8Array } | null;
  consumeNonce?: boolean;
} = {}) {
  return {
    findActivePublicKey: vi.fn(async () => overrides.activeKey === undefined
      ? {
          keyId: fixture.keyId,
          runnerId,
          publicKey: decodeBase64Url(fixture.publicKeyBase64Url),
        }
      : overrides.activeKey),
    consumeNonce: vi.fn(async () => overrides.consumeNonce ?? true),
  };
}

describe("authenticateRunnerRequest", () => {
  it("authenticates a valid signed request and consumes its nonce once", async () => {
    const identities = makeIdentityStore();
    const authenticated = await authenticateRunnerRequest(
      makeRequest(), rawBody, identities, now,
    );

    expect(authenticated).toEqual({ runnerId, keyId: fixture.keyId });
    expect(identities.findActivePublicKey).toHaveBeenCalledWith(fixture.keyId, now);
    expect(identities.consumeNonce).toHaveBeenCalledWith(
      fixture.keyId,
      fixture.nonce,
      now,
      new Date(now.getTime() + 5 * 60 * 1000),
    );
  });

  it("rejects stale timestamps before looking up keys or consuming nonces", async () => {
    const identities = makeIdentityStore();
    const stale = String(Number(fixture.timestamp) + RUNNER_REQUEST_CLOCK_SKEW_SECONDS + 1);
    const authenticated = await authenticateRunnerRequest(
      makeRequest({ timestamp: stale }), rawBody, identities, now,
    );

    expect(authenticated).toBeNull();
    expect(identities.findActivePublicKey).not.toHaveBeenCalled();
    expect(identities.consumeNonce).not.toHaveBeenCalled();
  });

  it("rejects unknown or revoked keys without consuming a nonce", async () => {
    const identities = makeIdentityStore({ activeKey: null });
    const authenticated = await authenticateRunnerRequest(
      makeRequest(), rawBody, identities, now,
    );

    expect(authenticated).toBeNull();
    expect(identities.consumeNonce).not.toHaveBeenCalled();
  });

  it("rejects an invalid signature without consuming a nonce", async () => {
    const identities = makeIdentityStore();
    const authenticated = await authenticateRunnerRequest(
      makeRequest({ path: "/internal/v1/runner/other" }), rawBody, identities, now,
    );

    expect(authenticated).toBeNull();
    expect(identities.consumeNonce).not.toHaveBeenCalled();
  });

  it("rejects a nonce that has already been consumed", async () => {
    const identities = makeIdentityStore({ consumeNonce: false });
    const authenticated = await authenticateRunnerRequest(
      makeRequest(), rawBody, identities, now,
    );

    expect(authenticated).toBeNull();
    expect(identities.consumeNonce).toHaveBeenCalledOnce();
  });

  it("propagates identity-store outages instead of accepting or misclassifying the request", async () => {
    const identities = makeIdentityStore();
    identities.findActivePublicKey.mockRejectedValue(new Error("database unavailable"));

    await expect(authenticateRunnerRequest(
      makeRequest(), rawBody, identities, now,
    )).rejects.toThrow("database unavailable");
    expect(identities.consumeNonce).not.toHaveBeenCalled();
  });
});
