import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  canonicalRunnerRequestMessage,
  verifyRunnerRequestSignature,
} from "./runner-request-signature";

interface Fixture {
  readonly keyId: string;
  readonly method: string;
  readonly path: string;
  readonly timestamp: string;
  readonly nonce: string;
  readonly bodyUtf8: string;
  readonly canonicalUtf8: string;
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

function makeRequest(overrides: Partial<{
  keyId: string; method: string; path: string; timestamp: string; nonce: string; body: string;
}> = {}) {
  return {
    keyId: overrides.keyId ?? fixture.keyId,
    method: overrides.method ?? fixture.method,
    path: overrides.path ?? fixture.path,
    timestamp: overrides.timestamp ?? fixture.timestamp,
    nonce: overrides.nonce ?? fixture.nonce,
    body: new TextEncoder().encode(overrides.body ?? fixture.bodyUtf8),
  };
}

describe("runner Ed25519 request signature interoperability", () => {
  it("reproduces the canonical request bytes from the shared Go/Worker vector", async () => {
    const message = await canonicalRunnerRequestMessage(makeRequest());
    expect(new TextDecoder().decode(message)).toBe(fixture.canonicalUtf8);
  });

  it("verifies the Go-compatible Ed25519 signature with Web Crypto", async () => {
    const valid = await verifyRunnerRequestSignature(
      makeRequest(),
      decodeBase64Url(fixture.publicKeyBase64Url),
      fixture.signatureBase64Url,
    );
    expect(valid).toBe(true);
  });

  const mutations: Array<[string, Partial<{
    keyId: string; method: string; path: string; timestamp: string; nonce: string; body: string;
  }>]> = [
    ["path", { path: "/internal/v1/runner/other" }],
    ["timestamp", { timestamp: "1794535201" }],
    ["nonce", { nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
    ["non-canonical nonce", { nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" }],
    ["body", { body: "{\"requestedSlots\":2}" }],
    ["key ID", { keyId: "runner-other-key" }],
  ];

  it.each(mutations)("rejects a signature if the signed %s changes", async (_name, overrides) => {
    const valid = await verifyRunnerRequestSignature(
      makeRequest(overrides),
      decodeBase64Url(fixture.publicKeyBase64Url),
      fixture.signatureBase64Url,
    );
    expect(valid).toBe(false);
  });

  it("fails closed for malformed key and signature sizes", async () => {
    expect(await verifyRunnerRequestSignature(
      makeRequest(),
      new Uint8Array(31),
      fixture.signatureBase64Url,
    )).toBe(false);
    expect(await verifyRunnerRequestSignature(
      makeRequest(),
      decodeBase64Url(fixture.publicKeyBase64Url),
      "bad",
    )).toBe(false);
  });
});
