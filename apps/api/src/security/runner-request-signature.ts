export interface RunnerSignedRequest {
  readonly keyId: string;
  readonly method: string;
  readonly path: string;
  readonly timestamp: string;
  readonly nonce: string;
  readonly body: Uint8Array;
}

function isValidRequest(request: RunnerSignedRequest): boolean {
  let nonceBytes: Uint8Array;
  try {
    nonceBytes = decodeBase64Url(request.nonce);
  } catch {
    return false;
  }
  return /^[A-Za-z0-9._:-]{1,128}$/.test(request.keyId) &&
    /^[A-Z]{3,10}$/.test(request.method) &&
    request.path.startsWith("/") &&
    !/[\r\n\s]/.test(request.path) &&
    /^[1-9][0-9]{9}$/.test(request.timestamp) &&
    nonceBytes.byteLength === 32 &&
    request.body instanceof Uint8Array &&
    request.body.byteLength <= 256 * 1024;
}
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("invalid_base64url");
  }
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(base64);
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(decoded) !== value) throw new Error("non_canonical_base64url");
  return decoded;
}

/** Canonical bytes shared with the Go runner's internal/runnerauth package. */
export async function canonicalRunnerRequestMessage(
  request: RunnerSignedRequest,
): Promise<Uint8Array> {
  if (!isValidRequest(request)) throw new Error("invalid_runner_signed_request");
  const bodyBytes = new Uint8Array(request.body);
  const digest = await crypto.subtle.digest("SHA-256", bodyBytes);
  const canonical = [
    "SKYHIGH-RUNNER-REQUEST-V1",
    request.keyId,
    request.method,
    request.path,
    request.timestamp,
    request.nonce,
    toHex(new Uint8Array(digest)),
  ].join("\n");
  return new TextEncoder().encode(canonical);
}

/**
 * Verifies an Ed25519 signature using the runner's registered raw 32-byte
 * public key. Invalid inputs and unsupported runtime crypto fail closed.
 */
export async function verifyRunnerRequestSignature(
  request: RunnerSignedRequest,
  rawPublicKey: Uint8Array,
  signatureBase64Url: string,
): Promise<boolean> {
  try {
    if (rawPublicKey.byteLength !== 32) return false;
    const signature = decodeBase64Url(signatureBase64Url);
    if (signature.byteLength !== 64) return false;
    const message = await canonicalRunnerRequestMessage(request);
    const publicKeyBytes = new Uint8Array(rawPublicKey);
    const signatureBytes = new Uint8Array(signature);
    const messageBytes = new Uint8Array(message);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      "Ed25519",
      false,
      ["verify"],
    );
    return await crypto.subtle.verify("Ed25519", publicKey, signatureBytes, messageBytes);
  } catch {
    return false;
  }
}
