/**
 * FENCE-001 private Worker-to-Worker workload authentication.
 *
 * This module verifies an explicit Ed25519 proof. A Cloudflare Service Binding
 * is the private transport/capability boundary; it is not treated as proof of
 * the caller's workload identity. The caller's private key must remain in its
 * own Worker secret store. The verifier receives only pinned public keys.
 */
const DOMAIN = "SKYHIGH-FENCE-001-WORKER-WORKLOAD-V1\\n";
const MAX_TTL_SECONDS = 60;
const CLOCK_SKEW_SECONDS = 30;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SCOPE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const METHOD = /^[A-Z]{3,10}$/;
const PATH = /^\\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,1023}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const encoder = new TextEncoder();

export interface WorkloadProof {
  readonly callerId: string;
  readonly keyId: string;
  readonly audience: string;
  readonly scope: string;
  readonly method: string;
  readonly path: string;
  readonly bodyDigest: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string;
  readonly signature: string;
}

export interface TrustedWorkloadKey {
  readonly callerId: string;
  readonly keyId: string;
  readonly publicKeyBase64Url: string;
  readonly audiences: readonly string[];
  readonly scopes: readonly string[];
  /** Unix seconds, inclusive. */
  readonly notBefore: number;
  /** Unix seconds, exclusive. */
  readonly notAfter: number;
  /** A revoked key is rejected regardless of proof timestamp. */
  readonly revokedAt?: number;
}

export interface WorkloadRequestContext {
  readonly audience: string;
  readonly scope: string;
  readonly method: string;
  readonly path: string;
  readonly body: Uint8Array;
}

export interface WorkloadNonceStore {
  /** Must atomically insert callerId+nonce if absent and reject duplicates. */
  consumeNonce(
    callerId: string,
    nonce: string,
    expiresAt: number,
    trustedNow: number,
  ): Promise<boolean>;
}

export type WorkloadAuthenticationResult =
  | { readonly authenticated: true; readonly callerId: string; readonly scope: string; readonly keyId: string }
  | {
      readonly authenticated: false;
      readonly reason:
        | "malformed_proof"
        | "unknown_key"
        | "key_scope_denied"
        | "key_not_valid"
        | "proof_time_invalid"
        | "request_binding_mismatch"
        | "invalid_signature"
        | "replayed_nonce"
        | "replay_store_unavailable";
    };

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isCanonicalBase64Url(value: string): boolean {
  return value.length > 0 && !value.includes("=") && BASE64URL.test(value);
}

function decodeBase64Url(value: string): Uint8Array {
  if (!isCanonicalBase64Url(value)) throw new TypeError("non-canonical base64url");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) throw new TypeError("non-canonical base64url");
  return bytes;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\\+/g, "-").replace(/\\//g, "_");
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * The signed representation is a domain-separated, newline-delimited ASCII
 * tuple. All fields are constrained to ASCII grammars that exclude newlines,
 * so there is one unambiguous byte representation without JSON re-serialization.
 */
export function workloadSigningBytes(proof: Omit<WorkloadProof, "signature">): Uint8Array {
  const fields = [
    proof.callerId,
    proof.keyId,
    proof.audience,
    proof.scope,
    proof.method,
    proof.path,
    proof.bodyDigest,
    String(proof.issuedAt),
    String(proof.expiresAt),
    proof.nonce,
  ];
  return encoder.encode(DOMAIN + fields.join("\\n"));
}

function isWellFormedProof(proof: WorkloadProof): boolean {
  return Boolean(
    proof &&
      IDENTIFIER.test(proof.callerId) &&
      DIGEST.test(proof.keyId) &&
      IDENTIFIER.test(proof.audience) &&
      SCOPE.test(proof.scope) &&
      METHOD.test(proof.method) &&
      PATH.test(proof.path) &&
      DIGEST.test(proof.bodyDigest) &&
      isSafeInteger(proof.issuedAt) &&
      isSafeInteger(proof.expiresAt) &&
      proof.nonce.length >= 22 &&
      proof.nonce.length <= 86 &&
      isCanonicalBase64Url(proof.nonce) &&
      proof.signature.length === 86 &&
      isCanonicalBase64Url(proof.signature),
  );
}

export async function authenticateWorkloadCall(
  proof: WorkloadProof,
  request: WorkloadRequestContext,
  trustedKeys: readonly TrustedWorkloadKey[],
  trustedNow: number,
  nonceStore: WorkloadNonceStore,
): Promise<WorkloadAuthenticationResult> {
  if (!isWellFormedProof(proof) || !isSafeInteger(trustedNow)) {
    return { authenticated: false, reason: "malformed_proof" };
  }

  const matches = trustedKeys.filter(
    (key) => key.callerId === proof.callerId && key.keyId === proof.keyId,
  );
  if (matches.length !== 1) {
    return { authenticated: false, reason: "unknown_key" };
  }
  const key = matches[0];
  if (
    !key ||
    !Array.isArray(key.audiences) ||
    !Array.isArray(key.scopes) ||
    !key.audiences.includes(proof.audience) ||
    !key.scopes.includes(proof.scope)
  ) {
    return { authenticated: false, reason: "key_scope_denied" };
  }
  if (
    !isSafeInteger(key.notBefore) ||
    !isSafeInteger(key.notAfter) ||
    key.notBefore >= key.notAfter ||
    (key.revokedAt !== undefined && isSafeInteger(key.revokedAt))
  ) {
    if (key.revokedAt !== undefined) {
      return { authenticated: false, reason: "key_not_valid" };
    }
    return { authenticated: false, reason: "key_not_valid" };
  }
  if (
    trustedNow < key.notBefore ||
    trustedNow >= key.notAfter ||
    proof.issuedAt < key.notBefore ||
    proof.issuedAt >= key.notAfter
  ) {
    return { authenticated: false, reason: "key_not_valid" };
  }
  if (
    proof.issuedAt > trustedNow + CLOCK_SKEW_SECONDS ||
    proof.expiresAt <= trustedNow ||
    proof.expiresAt <= proof.issuedAt ||
    proof.expiresAt - proof.issuedAt > MAX_TTL_SECONDS
  ) {
    return { authenticated: false, reason: "proof_time_invalid" };
  }

  const actualBodyDigest = await sha256Hex(request.body);
  if (
    proof.audience !== request.audience ||
    proof.scope !== request.scope ||
    proof.method !== request.method ||
    proof.path !== request.path ||
    proof.bodyDigest !== actualBodyDigest
  ) {
    return { authenticated: false, reason: "request_binding_mismatch" };
  }

  try {
    const publicKeyBytes = decodeBase64Url(key.publicKeyBase64Url);
    if (
      publicKeyBytes.length !== 32 ||
      (await sha256Hex(publicKeyBytes)) !== key.keyId
    ) {
      return { authenticated: false, reason: "unknown_key" };
    }
    const signature = decodeBase64Url(proof.signature);
    if (signature.length !== 64) {
      return { authenticated: false, reason: "malformed_proof" };
    }
    const publicKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" } as AlgorithmIdentifier,
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" } as AlgorithmIdentifier,
      publicKey,
      signature,
      workloadSigningBytes(proof),
    );
    if (!valid) return { authenticated: false, reason: "invalid_signature" };
  } catch {
    return { authenticated: false, reason: "invalid_signature" };
  }

  try {
    const consumed = await nonceStore.consumeNonce(
      proof.callerId,
      proof.nonce,
      proof.expiresAt,
      trustedNow,
    );
    if (!consumed) return { authenticated: false, reason: "replayed_nonce" };
  } catch {
    return { authenticated: false, reason: "replay_store_unavailable" };
  }

  return {
    authenticated: true,
    callerId: proof.callerId,
    scope: proof.scope,
    keyId: proof.keyId,
  };
}
