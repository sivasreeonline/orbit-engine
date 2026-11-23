import { DurableObject } from "cloudflare:workers";
import canonicalize from "canonicalize";

const STATE_KEY = "fence-witness-trust-state-v1";
const ZERO_DIGEST = "0".repeat(64);
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_IDENTIFIER_LENGTH = 256;

export interface WitnessTrustScope {
  readonly trustDomainId: string;
  readonly witnessId: string;
}

export interface StoredWitnessTrustBundle {
  readonly generation: number;
  readonly digest: string;
  readonly envelope: unknown;
}

export interface StoredWitnessTreeHead {
  readonly digest: string;
  readonly envelope: unknown;
}

export interface WitnessTrustSnapshot {
  readonly version: 1;
  readonly scope: WitnessTrustScope;
  readonly trustBundle: StoredWitnessTrustBundle | null;
  readonly treeHead: StoredWitnessTreeHead | null;
}

export interface TrustBundleAdvanceInput {
  readonly scope: WitnessTrustScope;
  readonly expectedGeneration: number;
  readonly expectedDigest: string;
  readonly envelope: {
    readonly body: {
      readonly profile: string;
      readonly schemaVersion: number;
      readonly trustDomainId: string;
      readonly witnessId: string;
      readonly generation: number;
      readonly previousBundleDigest: string;
    };
    readonly bundleDigest: string;
    readonly rootKeyId: string;
    readonly rootSignature: string;
  };
}

export interface TreeHeadAdvanceInput {
  readonly scope: WitnessTrustScope;
  readonly expectedPriorHeadDigest: string | null;
  readonly envelope: {
    readonly body: {
      readonly profile: string;
      readonly schemaVersion: number;
      readonly witnessId: string;
      readonly authorityId: string;
      readonly hostId: string;
      readonly logId: string;
      readonly treeSize: number;
      readonly rootHash: string;
      readonly timestamp: string;
      readonly keyId: string;
    };
    readonly signature: string;
  };
}

export type WitnessTrustWriteResult =
  | { readonly stored: true; readonly digest: string; readonly snapshot: WitnessTrustSnapshot }
  | {
      readonly stored: false;
      readonly reason:
        | "invalid_input"
        | "scope_mismatch"
        | "stale_state"
        | "invalid_transition"
        | "trust_bundle_required";
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validScope(scope: WitnessTrustScope): boolean {
  return (
    isRecord(scope) &&
    typeof scope.trustDomainId === "string" &&
    scope.trustDomainId.length > 0 &&
    scope.trustDomainId.length <= MAX_IDENTIFIER_LENGTH &&
    typeof scope.witnessId === "string" &&
    scope.witnessId.length > 0 &&
    scope.witnessId.length <= MAX_IDENTIFIER_LENGTH
  );
}

function validDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST.test(value);
}

function emptySnapshot(scope: WitnessTrustScope): WitnessTrustSnapshot {
  return {
    version: 1,
    scope,
    trustBundle: {
      generation: 0,
      digest: ZERO_DIGEST,
      envelope: null,
    },
    treeHead: null,
  };
}

function canonicalJson(value: unknown): string {
  const result = canonicalize(value);
  if (typeof result !== "string") throw new TypeError("value is not canonicalizable JSON");
  return result;
}

async function digestCanonical(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sameScope(left: WitnessTrustScope, right: WitnessTrustScope): boolean {
  return left.trustDomainId === right.trustDomainId && left.witnessId === right.witnessId;
}

/**
 * Durable compare-and-set state for root-verified trust-bundle generations and
 * accepted signed tree heads. Cryptographic verification occurs in the gateway
 * before these methods are called; this object enforces atomic state transitions.
 */
export class WitnessTrustStateDO extends DurableObject<unknown> {
  async readSnapshot(scope: WitnessTrustScope): Promise<WitnessTrustSnapshot> {
    if (!validScope(scope)) throw new TypeError("invalid trust scope");
    const stored = await this.ctx.storage.get<WitnessTrustSnapshot>(STATE_KEY);
    if (!stored) return emptySnapshot(scope);
    if (!sameScope(stored.scope, scope)) throw new TypeError("trust-state scope mismatch");
    return stored;
  }

  async advanceTrustBundle(input: TrustBundleAdvanceInput): Promise<WitnessTrustWriteResult> {
    if (
      !input ||
      !validScope(input.scope) ||
      !Number.isSafeInteger(input.expectedGeneration) ||
      input.expectedGeneration < 0 ||
      !validDigest(input.expectedDigest) ||
      !isRecord(input.envelope) ||
      !isRecord(input.envelope.body) ||
      input.envelope.body.profile !== "sky-high-fence-witness-v1" ||
      input.envelope.body.schemaVersion !== 1 ||
      input.envelope.body.trustDomainId !== input.scope.trustDomainId ||
      input.envelope.body.witnessId !== input.scope.witnessId ||
      !Number.isSafeInteger(input.envelope.body.generation) ||
      !validDigest(input.envelope.body.previousBundleDigest) ||
      !validDigest(input.envelope.bundleDigest) ||
      !validDigest(input.envelope.rootKeyId) ||
      typeof input.envelope.rootSignature !== "string" ||
      input.envelope.rootSignature.length !== 86
    ) return { stored: false, reason: "invalid_input" };

    let calculatedDigest: string;
    try {
      calculatedDigest = await digestCanonical(input.envelope.body);
    } catch {
      return { stored: false, reason: "invalid_input" };
    }
    if (calculatedDigest !== input.envelope.bundleDigest) {
      return { stored: false, reason: "invalid_input" };
    }

    return this.ctx.storage.transaction(async (txn) => {
      const stored = await txn.get<WitnessTrustSnapshot>(STATE_KEY);
      const current = stored ?? emptySnapshot(input.scope);
      if (!sameScope(current.scope, input.scope)) {
        return { stored: false, reason: "scope_mismatch" } as const;
      }
      const prior = current.trustBundle ?? emptySnapshot(input.scope).trustBundle;
      if (!prior) return { stored: false, reason: "invalid_transition" } as const;

      if (
        prior.generation === input.envelope.body.generation &&
        prior.digest === input.envelope.bundleDigest
      ) {
        return {
          stored: true,
          digest: prior.digest,
          snapshot: current,
        } as const;
      }

      if (
        prior.generation !== input.expectedGeneration ||
        prior.digest !== input.expectedDigest
      ) return { stored: false, reason: "stale_state" } as const;

      if (
        input.envelope.body.generation !== prior.generation + 1 ||
        input.envelope.body.previousBundleDigest !== prior.digest
      ) return { stored: false, reason: "invalid_transition" } as const;

      const next: WitnessTrustSnapshot = {
        ...current,
        trustBundle: {
          generation: input.envelope.body.generation,
          digest: input.envelope.bundleDigest,
          envelope: input.envelope,
        },
      };
      await txn.put(STATE_KEY, next);
      return { stored: true, digest: input.envelope.bundleDigest, snapshot: next } as const;
    });
  }

  async advanceTreeHead(input: TreeHeadAdvanceInput): Promise<WitnessTrustWriteResult> {
    if (
      !input ||
      !validScope(input.scope) ||
      (input.expectedPriorHeadDigest !== null && !validDigest(input.expectedPriorHeadDigest)) ||
      !isRecord(input.envelope) ||
      !isRecord(input.envelope.body) ||
      input.envelope.body.profile !== "sky-high-fence-witness-merkle-v1" ||
      input.envelope.body.schemaVersion !== 1 ||
      input.envelope.body.witnessId !== input.scope.witnessId ||
      !isRecord(input.envelope.body) ||
      typeof input.envelope.body.authorityId !== "string" ||
      typeof input.envelope.body.hostId !== "string" ||
      typeof input.envelope.body.logId !== "string" ||
      !Number.isSafeInteger(input.envelope.body.treeSize) ||
      input.envelope.body.treeSize < 1 ||
      !validDigest(input.envelope.body.rootHash) ||
      !validDigest(input.envelope.body.keyId) ||
      typeof input.envelope.body.timestamp !== "string" ||
      typeof input.envelope.signature !== "string" ||
      input.envelope.signature.length !== 86
    ) return { stored: false, reason: "invalid_input" };

    let nextDigest: string;
    try {
      nextDigest = await digestCanonical(input.envelope);
    } catch {
      return { stored: false, reason: "invalid_input" };
    }

    return this.ctx.storage.transaction(async (txn) => {
      const stored = await txn.get<WitnessTrustSnapshot>(STATE_KEY);
      if (!stored || !sameScope(stored.scope, input.scope)) {
        return { stored: false, reason: "scope_mismatch" } as const;
      }
      if (!stored.trustBundle) {
        return { stored: false, reason: "trust_bundle_required" } as const;
      }

      const prior = stored.treeHead;
      if (prior?.digest === nextDigest) {
        return { stored: true, digest: nextDigest, snapshot: stored } as const;
      }
      if ((prior?.digest ?? null) !== input.expectedPriorHeadDigest) {
        return { stored: false, reason: "stale_state" } as const;
      }

      if (prior) {
        const priorEnvelope = prior.envelope as TreeHeadAdvanceInput["envelope"];
        const priorBody = priorEnvelope.body;
        const nextBody = input.envelope.body;
        if (
          priorBody.witnessId !== nextBody.witnessId ||
          priorBody.authorityId !== nextBody.authorityId ||
          priorBody.hostId !== nextBody.hostId ||
          priorBody.logId !== nextBody.logId
        ) return { stored: false, reason: "scope_mismatch" } as const;
        if (nextBody.treeSize <= priorBody.treeSize) {
          return { stored: false, reason: "invalid_transition" } as const;
        }
      }

      const next: WitnessTrustSnapshot = {
        ...stored,
        treeHead: {
          digest: nextDigest,
          envelope: input.envelope,
        },
      };
      await txn.put(STATE_KEY, next);
      return { stored: true, digest: nextDigest, snapshot: next } as const;
    });
  }

  override async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }
}
