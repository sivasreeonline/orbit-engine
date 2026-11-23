import { describe, expect, it } from "vitest";
import { parseTrustedWorkloadKeys } from "./index";

describe("parseTrustedWorkloadKeys", () => {
  it("fails closed when the allowlist is missing or empty", () => {
    expect(parseTrustedWorkloadKeys(undefined)).toBeNull();
    expect(parseTrustedWorkloadKeys("")).toBeNull();
    expect(parseTrustedWorkloadKeys("[]")).toBeNull();
  });

  it("fails closed for malformed JSON and incomplete key records", () => {
    expect(parseTrustedWorkloadKeys("{")).toBeNull();
    expect(parseTrustedWorkloadKeys(JSON.stringify([{ callerId: "api" }]))).toBeNull();
  });

  it("accepts a structurally complete pinned public-key record", () => {
    const record = {
      callerId: "api-worker",
      keyId: "a".repeat(64),
      publicKeyBase64Url: "A".repeat(43),
      audiences: ["sky-high-witness-gateway"],
      scopes: ["witness:authorize"],
      notBefore: 1_700_000_000,
      notAfter: 1_900_000_000
    };
    expect(parseTrustedWorkloadKeys(JSON.stringify([record]))).toEqual([record]);
  });
});