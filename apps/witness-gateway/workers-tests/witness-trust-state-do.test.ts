import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import canonicalize from "canonicalize";
import type {
  TreeHeadAdvanceInput,
  TrustBundleAdvanceInput,
  WitnessTrustScope,
  WitnessTrustSnapshot,
  WitnessTrustWriteResult,
} from "../src/witness-trust-state-do";

interface TrustStateStub {
  readSnapshot(scope: WitnessTrustScope): Promise<WitnessTrustSnapshot>;
  advanceTrustBundle(input: TrustBundleAdvanceInput): Promise<WitnessTrustWriteResult>;
  advanceTreeHead(input: TreeHeadAdvanceInput): Promise<WitnessTrustWriteResult>;
}

const ZERO_DIGEST = "0".repeat(64);
const signature = "A".repeat(86);

function stubFor(scope: WitnessTrustScope): TrustStateStub {
  const id = env.WITNESS_TRUST_STATE.idFromName(
    `${scope.trustDomainId}:${scope.witnessId}`,
  );
  return env.WITNESS_TRUST_STATE.get(id) as unknown as TrustStateStub;
}

async function digest(value: unknown): Promise<string> {
  const canonical = canonicalize(value);
  if (typeof canonical !== "string") throw new Error("test value not canonicalizable");
  const bytes = new TextEncoder().encode(canonical);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...hash].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function trustBundle(
  scope: WitnessTrustScope,
  generation: number,
  previousBundleDigest: string,
  marker: string,
) {
  const body = {
    profile: "sky-high-fence-witness-v1",
    schemaVersion: 1,
    trustDomainId: scope.trustDomainId,
    witnessId: scope.witnessId,
    generation,
    previousBundleDigest,
    keys: [],
    revocations: [],
    marker,
  };
  return {
    body,
    bundleDigest: await digest(body),
    rootKeyId: "1".repeat(64),
    rootSignature: signature,
  };
}

function treeHead(
  scope: WitnessTrustScope,
  treeSize: number,
  logId = "log-primary",
  rootHash = treeSize.toString(16).padStart(64, "0"),
) {
  return {
    body: {
      profile: "sky-high-fence-witness-merkle-v1",
      schemaVersion: 1,
      witnessId: scope.witnessId,
      authorityId: "authority-primary",
      hostId: "host-primary",
      logId,
      treeSize,
      rootHash,
      timestamp: "2026-11-23T08:00:00Z",
      keyId: "2".repeat(64),
    },
    signature,
  };
}

describe("WitnessTrustStateDO", () => {
  it("atomically advances trust-bundle generations and rejects stale forks", async () => {
    const scope = { trustDomainId: "trust-domain-do-test", witnessId: "witness-do-test" };
    const stub = stubFor(scope);
    const initial = await stub.readSnapshot(scope);
    expect(initial.trustBundle).toMatchObject({ generation: 0, digest: ZERO_DIGEST });
    expect(initial.treeHead).toBeNull();

    const first = await trustBundle(scope, 1, ZERO_DIGEST, "generation-one");
    const firstWrite = await stub.advanceTrustBundle({
      scope,
      expectedGeneration: 0,
      expectedDigest: ZERO_DIGEST,
      envelope: first,
    });
    expect(firstWrite.stored).toBe(true);
    expect(firstWrite.digest).toBe(first.bundleDigest);

    // An exact retry is idempotent even though the caller's expected state is now stale.
    expect(await stub.advanceTrustBundle({
      scope,
      expectedGeneration: 0,
      expectedDigest: ZERO_DIGEST,
      envelope: first,
    })).toMatchObject({ stored: true, digest: first.bundleDigest });

    const second = await trustBundle(scope, 2, first.bundleDigest, "generation-two");
    expect(await stub.advanceTrustBundle({
      scope,
      expectedGeneration: 1,
      expectedDigest: first.bundleDigest,
      envelope: second,
    })).toMatchObject({ stored: true, digest: second.bundleDigest });

    const fork = await trustBundle(scope, 2, first.bundleDigest, "forked-generation-two");
    expect(await stub.advanceTrustBundle({
      scope,
      expectedGeneration: 1,
      expectedDigest: first.bundleDigest,
      envelope: fork,
    })).toEqual({ stored: false, reason: "stale_state" });

    const snapshot = await stub.readSnapshot(scope);
    expect(snapshot.trustBundle).toMatchObject({
      generation: 2,
      digest: second.bundleDigest,
    });
  });

  it("allows only one concurrent compare-and-set trust update", async () => {
    const scope = { trustDomainId: "trust-domain-race-test", witnessId: "witness-race-test" };
    const stub = stubFor(scope);
    const [left, right] = await Promise.all([
      trustBundle(scope, 1, ZERO_DIGEST, "left"),
      trustBundle(scope, 1, ZERO_DIGEST, "right"),
    ]);
    const results = await Promise.all([
      stub.advanceTrustBundle({
        scope, expectedGeneration: 0, expectedDigest: ZERO_DIGEST, envelope: left,
      }),
      stub.advanceTrustBundle({
        scope, expectedGeneration: 0, expectedDigest: ZERO_DIGEST, envelope: right,
      }),
    ]);
    expect(results.filter((result) => result.stored)).toHaveLength(1);
    expect(results.filter((result) => !result.stored)).toHaveLength(1);
  });

  it("pins monotonic signed tree heads with compare-and-set and idempotent retry", async () => {
    const scope = { trustDomainId: "trust-domain-head-test", witnessId: "witness-head-test" };
    const stub = stubFor(scope);
    const bundle = await trustBundle(scope, 1, ZERO_DIGEST, "head-test");
    await expect(stub.advanceTrustBundle({
      scope, expectedGeneration: 0, expectedDigest: ZERO_DIGEST, envelope: bundle,
    })).resolves.toMatchObject({ stored: true });

    const first = treeHead(scope, 2);
    const firstDigest = await digest(first);
    expect(await stub.advanceTreeHead({
      scope,
      expectedPriorHeadDigest: null,
      envelope: first,
    })).toMatchObject({ stored: true, digest: firstDigest });

    const next = treeHead(scope, 3);
    const nextDigest = await digest(next);
    expect(await stub.advanceTreeHead({
      scope,
      expectedPriorHeadDigest: firstDigest,
      envelope: next,
    })).toMatchObject({ stored: true, digest: nextDigest });

    expect(await stub.advanceTreeHead({
      scope,
      expectedPriorHeadDigest: firstDigest,
      envelope: next,
    })).toMatchObject({ stored: true, digest: nextDigest });

    expect(await stub.advanceTreeHead({
      scope,
      expectedPriorHeadDigest: firstDigest,
      envelope: treeHead(scope, 4),
    })).toEqual({ stored: false, reason: "stale_state" });

    expect(await stub.advanceTreeHead({
      scope,
      expectedPriorHeadDigest: nextDigest,
      envelope: treeHead(scope, 2),
    })).toEqual({ stored: false, reason: "invalid_transition" });

    expect(await stub.advanceTreeHead({
      scope,
      expectedPriorHeadDigest: nextDigest,
      envelope: treeHead(scope, 4, "substituted-log"),
    })).toEqual({ stored: false, reason: "scope_mismatch" });

    const snapshot = await stub.readSnapshot(scope);
    expect(snapshot.treeHead).toMatchObject({
      digest: nextDigest,
      trustBundleDigest: bundle.bundleDigest,
      trustBundleEnvelope: bundle,
      envelope: next,
    });
  });

  it("isolates state by trust-domain and witness identity", async () => {
    const firstScope = { trustDomainId: "trust-domain-isolation", witnessId: "witness-a" };
    const secondScope = { trustDomainId: "trust-domain-isolation", witnessId: "witness-b" };
    const first = stubFor(firstScope);
    const second = stubFor(secondScope);
    const bundle = await trustBundle(firstScope, 1, ZERO_DIGEST, "only-a");
    await first.advanceTrustBundle({
      scope: firstScope,
      expectedGeneration: 0,
      expectedDigest: ZERO_DIGEST,
      envelope: bundle,
    });

    expect((await first.readSnapshot(firstScope)).trustBundle?.generation).toBe(1);
    expect((await second.readSnapshot(secondScope)).trustBundle?.generation).toBe(0);
  });
  it("uses collision-safe composite names for trust-domain and witness scopes", async () => {
    const firstScope = { trustDomainId: "domain:segment", witnessId: "witness" };
    const secondScope = { trustDomainId: "domain", witnessId: "segment:witness" };
    const first = stubFor(firstScope);
    const second = stubFor(secondScope);
    expect((await first.readSnapshot(firstScope)).scope).toEqual(firstScope);
    expect((await second.readSnapshot(secondScope)).scope).toEqual(secondScope);
  });

  it("retains the trust generation associated with each accepted tree head", async () => {
    const scope = { trustDomainId: "trust-domain-rotation", witnessId: "witness-rotation" };
    const stub = stubFor(scope);
    const firstBundle = await trustBundle(scope, 1, ZERO_DIGEST, "rotation-one");
    await stub.advanceTrustBundle({
      scope, expectedGeneration: 0, expectedDigest: ZERO_DIGEST, envelope: firstBundle,
    });
    const firstHead = treeHead(scope, 1);
    const firstHeadDigest = await digest(firstHead);
    await stub.advanceTreeHead({
      scope, expectedPriorHeadDigest: null, envelope: firstHead,
    });

    const secondBundle = await trustBundle(scope, 2, firstBundle.bundleDigest, "rotation-two");
    await stub.advanceTrustBundle({
      scope,
      expectedGeneration: 1,
      expectedDigest: firstBundle.bundleDigest,
      envelope: secondBundle,
    });
    const secondHead = treeHead(scope, 2);
    await stub.advanceTreeHead({
      scope,
      expectedPriorHeadDigest: firstHeadDigest,
      envelope: secondHead,
    });

    const snapshot = await stub.readSnapshot(scope);
    expect(snapshot.trustBundle?.digest).toBe(secondBundle.bundleDigest);
    expect(snapshot.treeHead?.trustBundleDigest).toBe(secondBundle.bundleDigest);
  });

});
