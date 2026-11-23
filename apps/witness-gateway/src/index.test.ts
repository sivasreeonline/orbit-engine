import { describe, expect, it } from "vitest";
import {
  parseAllowedWitnessScopes,
  parsePinnedWitnessRoots,
  parseTrustedWorkloadKeys,
} from "./index";

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
describe("parsePinnedWitnessRoots", () => {
  it("fails closed for missing, empty and malformed root pin configuration", () => {
    expect(parsePinnedWitnessRoots(undefined)).toBeNull();
    expect(parsePinnedWitnessRoots("[]")).toBeNull();
    expect(parsePinnedWitnessRoots("{")).toBeNull();
    expect(parsePinnedWitnessRoots(JSON.stringify([{ keyId: "bad" }]))).toBeNull();
  });

  it("accepts unique pinned Ed25519 root fingerprints", () => {
    const roots = [{
      keyId: "a".repeat(64),
      publicKeyBase64Url: "A".repeat(43),
    }];
    expect(parsePinnedWitnessRoots(JSON.stringify(roots))).toEqual(roots);
  });
});

describe("parseAllowedWitnessScopes", () => {
  it("fails closed when no exact scope allowlist is configured", () => {
    expect(parseAllowedWitnessScopes(undefined)).toBeNull();
    expect(parseAllowedWitnessScopes("[]")).toBeNull();
    expect(parseAllowedWitnessScopes(JSON.stringify([{ witnessId: "w" }]))).toBeNull();
  });

  it("accepts exact trust-domain, witness, authority and host tuples", () => {
    const scopes = [{
      trustDomainId: "trust-domain",
      witnessId: "witness",
      authorityId: "authority",
      hostId: "host",
    }];
    expect(parseAllowedWitnessScopes(JSON.stringify(scopes))).toEqual(scopes);
  });

  it("rejects duplicate scope tuples", () => {
    const scope = {
      trustDomainId: "trust-domain",
      witnessId: "witness",
      authorityId: "authority",
      hostId: "host",
    };
    expect(parseAllowedWitnessScopes(JSON.stringify([scope, scope]))).toBeNull();
  });
});
