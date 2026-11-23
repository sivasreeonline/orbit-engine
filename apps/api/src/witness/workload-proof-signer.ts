import type { WorkloadProof } from "./workload-identity";
import { workloadSigningBytes } from "./workload-identity";

const AUDIENCE = "sky-high-witness-gateway";
const PROOF_TTL_SECONDS = 45;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const KEY_ID = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export type WorkloadProofOperation = "authorize" | "verify_evidence";

const OPERATION_CONTEXT: Record<WorkloadProofOperation, { scope: string; method: string; path: string }> = {
  authorize: {
    scope: "witness:authorize",
    method: "POST",
    path: "/rpc/authenticate",
  },
  verify_evidence: {
    scope: "witness:verify-evidence",
    method: "POST",
    path: "/rpc/verify-evidence",
  },
};
export interface WorkloadSignerConfig {
  readonly callerId?: string;
  readonly keyId?: string;
  /** Base64url-encoded PKCS#8 Ed25519 private key. Keep this in Worker secrets. */
  readonly privateKeyPkcs8?: string;
}

export type WorkloadProofCreationResult =
  | { readonly created: true; readonly proof: WorkloadProof }
  | {
      readonly created: false;
      readonly reason: "caller_identity_unconfigured" | "caller_proof_signing_failed";
    };

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function decodeBase64Url(value: string): Uint8Array {
  if (!value || value.includes("=") || !BASE64URL.test(value)) {
    throw new TypeError("private key must be canonical base64url");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...bytes))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  if (canonical !== value) throw new TypeError("non-canonical private key encoding");
  return bytes;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Create a short-lived proof for the one gateway operation. The audience,
 * scope, method and path are constants, not caller-controlled parameters.
 */
export async function createApiWorkloadProof(
  config: WorkloadSignerConfig,
  body: Uint8Array,
  operation: WorkloadProofOperation = "authorize",
): Promise<WorkloadProofCreationResult> {
  const callerId = config?.callerId;
  const keyId = config?.keyId;
  const privateKeyPkcs8 = config?.privateKeyPkcs8;
  if (
    typeof callerId !== "string" ||
    !IDENTIFIER.test(callerId) ||
    typeof keyId !== "string" ||
    !KEY_ID.test(keyId) ||
    typeof privateKeyPkcs8 !== "string" ||
    privateKeyPkcs8.length === 0 ||
    !(body instanceof Uint8Array)
  ) {
    return { created: false, reason: "caller_identity_unconfigured" };
  }

  try {
    const privateKeyBytes = decodeBase64Url(privateKeyPkcs8);
    if (privateKeyBytes.length < 32 || privateKeyBytes.length > 128) {
      return { created: false, reason: "caller_proof_signing_failed" };
    }
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      toArrayBuffer(privateKeyBytes),
      { name: "Ed25519" } as AlgorithmIdentifier,
      false,
      ["sign"],
    );

    const context = OPERATION_CONTEXT[operation];
    const issuedAt = Math.floor(Date.now() / 1_000);
    const nonceBytes = new Uint8Array(24);
    crypto.getRandomValues(nonceBytes);
    const unsigned = {
      callerId,
      keyId,
      audience: AUDIENCE,
      scope: context.scope,
      method: context.method,
      path: context.path,
      bodyDigest: await sha256Hex(body),
      issuedAt,
      expiresAt: issuedAt + PROOF_TTL_SECONDS,
      nonce: encodeBase64Url(nonceBytes),
    };
    const signature = new Uint8Array(await crypto.subtle.sign(
      { name: "Ed25519" } as AlgorithmIdentifier,
      privateKey,
      toArrayBuffer(workloadSigningBytes(unsigned)),
    ));
    if (signature.length !== 64) {
      return { created: false, reason: "caller_proof_signing_failed" };
    }
    return {
      created: true,
      proof: { ...unsigned, signature: encodeBase64Url(signature) },
    };
  } catch {
    return { created: false, reason: "caller_proof_signing_failed" };
  }
}
