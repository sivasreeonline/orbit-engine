import {
  verifyRunnerRequestSignature,
  type RunnerSignedRequest,
} from "../security/runner-request-signature";
import type {
  ActiveRunnerPublicKey,
  PostgresRunnerIdentityRepository,
} from "../db/runner-identity-repository";

export const RUNNER_REQUEST_CLOCK_SKEW_SECONDS = 30;
export const RUNNER_REQUEST_NONCE_TTL_MS = 5 * 60 * 1000;

export const RUNNER_AUTH_HEADERS = {
  keyId: "X-SkyHigh-Runner-Key-Id",
  timestamp: "X-SkyHigh-Runner-Timestamp",
  nonce: "X-SkyHigh-Runner-Nonce",
  signature: "X-SkyHigh-Runner-Signature",
} as const;

type RunnerIdentityStore = Pick<
  PostgresRunnerIdentityRepository,
  "findActivePublicKey" | "consumeNonce"
>;

export interface AuthenticatedRunner {
  readonly runnerId: string;
  readonly keyId: string;
}

/**
 * Authenticates a runner request over the exact raw body bytes. Timestamp
 * freshness is checked before key lookup; the nonce is consumed only after
 * signature verification succeeds.
 *
 * Repository failures intentionally propagate so callers can return a
 * retryable infrastructure error instead of treating an outage as bad auth.
 */
export async function authenticateRunnerRequest(
  request: Request,
  rawBody: Uint8Array,
  identities: RunnerIdentityStore,
  now: Date = new Date(),
): Promise<AuthenticatedRunner | null> {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime()) ||
      !(rawBody instanceof Uint8Array) || rawBody.byteLength > 256 * 1024) {
    return null;
  }

  const keyId = request.headers.get(RUNNER_AUTH_HEADERS.keyId) ?? "";
  const timestamp = request.headers.get(RUNNER_AUTH_HEADERS.timestamp) ?? "";
  const nonce = request.headers.get(RUNNER_AUTH_HEADERS.nonce) ?? "";
  const signature = request.headers.get(RUNNER_AUTH_HEADERS.signature) ?? "";
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId) ||
      !/^[1-9][0-9]{9}$/.test(timestamp) ||
      !/^[A-Za-z0-9_-]{43}$/.test(nonce) ||
      signature.length !== 86) {
    return null;
  }

  const timestampSeconds = Number(timestamp);
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (!Number.isSafeInteger(timestampSeconds) ||
      Math.abs(nowSeconds - timestampSeconds) > RUNNER_REQUEST_CLOCK_SKEW_SECONDS) {
    return null;
  }

  const url = new URL(request.url);
  const signedRequest: RunnerSignedRequest = {
    keyId,
    method: request.method.toUpperCase(),
    path: `${url.pathname}${url.search}`,
    timestamp,
    nonce,
    body: rawBody,
  };

  const activeKey: ActiveRunnerPublicKey | null =
    await identities.findActivePublicKey(keyId, now);
  if (!activeKey || activeKey.keyId !== keyId) return null;

  const signatureValid = await verifyRunnerRequestSignature(
    signedRequest,
    activeKey.publicKey,
    signature,
  );
  if (!signatureValid) return null;

  const nonceExpiresAt = new Date(now.getTime() + RUNNER_REQUEST_NONCE_TTL_MS);
  const nonceConsumed = await identities.consumeNonce(keyId, nonce, now, nonceExpiresAt);
  if (!nonceConsumed) return null;

  return { runnerId: activeKey.runnerId, keyId };
}
