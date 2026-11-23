import canonicalize from "canonicalize";

const RECEIPT_PREFIX = "SKYHIGH-FENCE-001-WITNESS-RECEIPT-V1\0";
const TRUST_BUNDLE_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TRUST-BUNDLE-V1\0";
const TREE_HEAD_PREFIX = "SKYHIGH-FENCE-001-WITNESS-TREE-HEAD-V1\0";
const PROFILE = "sky-high-fence-witness-v1";
const MERKLE_PROFILE = "sky-high-fence-witness-merkle-v1";
const ZERO_DIGEST = "0".repeat(64);
const DIGEST = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const encoder = new TextEncoder();

export type WitnessSigningPurpose = "WITNESS_RECEIPT_SIGNING" | "WITNESS_LOG_SIGNING";

export interface WitnessSigningKey {
  readonly keyId: string;
  readonly publicKeyBase64Url: string;
  readonly purpose: WitnessSigningPurpose;
  readonly witnessId: string;
  readonly authorityIds: readonly string[];
  readonly notBefore: string;
  readonly notAfter: string;
  readonly retiredAt?: string;
}

export interface WitnessTrustBundleBody {
  readonly profile: typeof PROFILE;
  readonly schemaVersion: 1;
  readonly trustDomainId: string;
  readonly witnessId: string;
  readonly generation: number;
  readonly previousBundleDigest: string;
  readonly keys: readonly WitnessSigningKey[];
  readonly revocations: readonly {
    readonly keyId: string;
    readonly revokedAt: string;
    readonly reason: string;
  }[];
}

export interface WitnessTrustBundleEnvelope {
  readonly body: WitnessTrustBundleBody;
  readonly bundleDigest: string;
  readonly rootKeyId: string;
  readonly rootSignature: string;
}

export interface WitnessCheckpointBody {
  readonly profile: typeof PROFILE;
  readonly schemaVersion: 1;
  readonly authorityId: string;
  readonly hostId: string;
  readonly generation: number;
  readonly phase: "ISSUED" | "ACCEPTED" | "REVOKED";
  readonly operationId: string;
  readonly previousCheckpointDigest: string;
  readonly authorityStateDigest: string;
  readonly responseDigest: string;
  readonly epoch: number;
  readonly recordVersion: number;
}

export interface WitnessReceiptBody {
  readonly profile: typeof PROFILE;
  readonly schemaVersion: 1;
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
  readonly generation: number;
  readonly operationId: string;
  readonly checkpointDigest: string;
  readonly previousCheckpointDigest: string;
  readonly keyId: string;
  readonly committedAt: string;
  readonly consistencyToken: string;
}

export interface WitnessReceiptEnvelope {
  readonly body: WitnessReceiptBody;
  readonly signature: string;
}

export interface WitnessTreeHeadBody {
  readonly profile: typeof MERKLE_PROFILE;
  readonly schemaVersion: 1;
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
  readonly logId: string;
  readonly treeSize: number;
  readonly rootHash: string;
  readonly timestamp: string;
  readonly keyId: string;
}

export interface WitnessTreeHeadEnvelope {
  readonly body: WitnessTreeHeadBody;
  readonly signature: string;
}

export interface PinnedRootKey {
  readonly keyId: string;
  readonly publicKeyBase64Url: string;
}

export interface ExpectedTrustBundleState {
  readonly generation: number;
  readonly digest: string;
  readonly trustDomainId: string;
  readonly witnessId: string;
}

export interface ExpectedWitnessScope {
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
}

export interface VerifiedTrustBundle {
  readonly body: WitnessTrustBundleBody;
  readonly digest: string;
  readonly rootKeyId: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const actual = Object.keys(value).sort();
  const allowed = [...required, ...optional].sort();
  return required.every((key) => Object.hasOwn(value, key))
    && actual.every((key) => allowed.includes(key))
    && actual.length >= required.length;
}

function isSafeInteger(value: unknown, minimum = 0): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST.test(value);
}

function parseUtc(value: unknown): number {
  if (typeof value !== "string" || !UTC_TIMESTAMP.test(value)) {
    throw new TypeError("timestamp must be UTC RFC 3339");
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError("timestamp is invalid");
  return Math.floor(parsed / 1_000);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function canonicalBytes(value: unknown): Uint8Array {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") {
    throw new TypeError("value cannot be represented as RFC 8785 JSON");
  }
  return encoder.encode(serialized);
}

function decodeBase64Url(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("=") ||
    !BASE64URL.test(value)
  ) {
    throw new TypeError("base64url value is malformed");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  let encoded = "";
  for (const byte of bytes) encoded += String.fromCharCode(byte);
  const canonical = btoa(encoded).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  if (canonical !== value) throw new TypeError("base64url encoding is not canonical");
  return bytes;
}

function decodeHex(value: unknown): Uint8Array {
  if (typeof value !== "string" || !DIGEST.test(value)) {
    throw new TypeError("SHA-256 hex value is malformed");
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)));
}

async function verifyEd25519(
  publicKeyBytes: Uint8Array,
  signatureBytes: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (publicKeyBytes.length !== 32 || signatureBytes.length !== 64) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(publicKeyBytes),
    { name: "Ed25519" } as AlgorithmIdentifier,
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "Ed25519" } as AlgorithmIdentifier,
    key,
    toArrayBuffer(signatureBytes),
    toArrayBuffer(message),
  );
}

function validateTrustBundleShape(envelope: unknown): asserts envelope is WitnessTrustBundleEnvelope {
  if (!isRecord(envelope) || !exactKeys(envelope, ["body", "bundleDigest", "rootKeyId", "rootSignature"])) {
    throw new TypeError("trust-bundle envelope shape is invalid");
  }
  if (!isRecord(envelope.body) || !exactKeys(envelope.body, [
    "profile", "schemaVersion", "trustDomainId", "witnessId", "generation",
    "previousBundleDigest", "keys", "revocations",
  ])) throw new TypeError("trust-bundle body shape is invalid");
  const body = envelope.body;
  if (
    body.profile !== PROFILE ||
    body.schemaVersion !== 1 ||
    !isIdentifier(body.trustDomainId) ||
    !isIdentifier(body.witnessId) ||
    !isSafeInteger(body.generation, 1) ||
    !isDigest(body.previousBundleDigest) ||
    !Array.isArray(body.keys) ||
    body.keys.length === 0 ||
    !Array.isArray(body.revocations) ||
    !isDigest(envelope.bundleDigest) ||
    !isDigest(envelope.rootKeyId) ||
    typeof envelope.rootSignature !== "string"
  ) throw new TypeError("trust-bundle fields are invalid");

  for (const value of body.keys) {
    if (!isRecord(value) || !exactKeys(value, [
      "keyId", "publicKeyBase64Url", "purpose", "witnessId",
      "authorityIds", "notBefore", "notAfter",
    ], ["retiredAt"])) throw new TypeError("trust-bundle signing key shape is invalid");
    if (
      !isDigest(value.keyId) ||
      typeof value.publicKeyBase64Url !== "string" ||
      (value.purpose !== "WITNESS_RECEIPT_SIGNING" && value.purpose !== "WITNESS_LOG_SIGNING") ||
      !isIdentifier(value.witnessId) ||
      !Array.isArray(value.authorityIds) ||
      value.authorityIds.length === 0 ||
      !value.authorityIds.every(isIdentifier) ||
      new Set(value.authorityIds).size !== value.authorityIds.length
    ) throw new TypeError("trust-bundle signing key fields are invalid");
    parseUtc(value.notBefore);
    parseUtc(value.notAfter);
    if (value.retiredAt !== undefined) parseUtc(value.retiredAt);
  }
  for (const value of body.revocations) {
    if (!isRecord(value) || !exactKeys(value, ["keyId", "revokedAt", "reason"])) {
      throw new TypeError("trust-bundle revocation shape is invalid");
    }
    if (!isDigest(value.keyId) || typeof value.reason !== "string" || value.reason.length === 0) {
      throw new TypeError("trust-bundle revocation fields are invalid");
    }
    parseUtc(value.revokedAt);
  }
}

function validateTrustBundleSemantics(body: WitnessTrustBundleBody): void {
  const keyIds = body.keys.map((key) => key.keyId);
  if (new Set(keyIds).size !== keyIds.length) throw new TypeError("duplicate trust-bundle key ID");
  for (const key of body.keys) {
    const publicKey = decodeBase64Url(key.publicKeyBase64Url);
    if (publicKey.length !== 32 || hex(new Uint8Array(publicKey)) !== key.keyId && hex(new Uint8Array([])) === "") {
      // Fingerprint is checked asynchronously by verifyTrustBundleEnvelope.
      if (publicKey.length !== 32) throw new TypeError("Ed25519 public key must be 32 bytes");
    }
    if (key.witnessId !== body.witnessId) throw new TypeError("trust-bundle key witness scope mismatch");
    const notBefore = parseUtc(key.notBefore);
    const notAfter = parseUtc(key.notAfter);
    if (notBefore >= notAfter) throw new TypeError("trust-bundle key validity interval is reversed");
    if (key.retiredAt !== undefined) {
      const retiredAt = parseUtc(key.retiredAt);
      if (retiredAt < notBefore || retiredAt > notAfter) {
        throw new TypeError("trust-bundle key retirement is outside its validity interval");
      }
    }
  }
  const revocationIds = body.revocations.map((item) => item.keyId);
  if (new Set(revocationIds).size !== revocationIds.length) {
    throw new TypeError("duplicate trust-bundle revocation key ID");
  }
}

export async function verifyTrustBundleEnvelope(
  envelope: unknown,
  pinnedRoots: readonly PinnedRootKey[],
  expected: ExpectedTrustBundleState,
): Promise<VerifiedTrustBundle> {
  validateTrustBundleShape(envelope);
  const body = envelope.body;
  if (
    body.trustDomainId !== expected.trustDomainId ||
    body.witnessId !== expected.witnessId ||
    body.generation !== expected.generation + 1 ||
    body.previousBundleDigest !== expected.digest
  ) throw new TypeError("trust-bundle scope, generation, or predecessor mismatch");

  const canonical = canonicalBytes(body);
  const digest = hex(await sha256(canonical));
  if (digest !== envelope.bundleDigest) throw new TypeError("trust-bundle digest mismatch");

  const roots = pinnedRoots.filter((root) => root.keyId === envelope.rootKeyId);
  if (roots.length !== 1) throw new TypeError("trust-bundle root key is missing or ambiguous");
  const rootBytes = decodeBase64Url(roots[0].publicKeyBase64Url);
  if (rootBytes.length !== 32 || hex(await sha256(rootBytes)) !== roots[0].keyId) {
    throw new TypeError("pinned root key fingerprint mismatch");
  }
  const signature = decodeBase64Url(envelope.rootSignature);
  if (signature.length !== 64) throw new TypeError("root signature must be 64 bytes");
  if (!(await verifyEd25519(rootBytes, signature, new Uint8Array([
    ...encoder.encode(TRUST_BUNDLE_PREFIX), ...canonical,
  ])))) throw new TypeError("root trust-bundle signature is invalid");

  validateTrustBundleSemantics(body);
  for (const key of body.keys) {
    const publicKey = decodeBase64Url(key.publicKeyBase64Url);
    if (hex(await sha256(publicKey)) !== key.keyId) {
      throw new TypeError("trust-bundle key fingerprint mismatch");
    }
  }
  return { body, digest, rootKeyId: envelope.rootKeyId };
}

function validateCheckpointBody(value: unknown): asserts value is WitnessCheckpointBody {
  if (!isRecord(value) || !exactKeys(value, [
    "profile", "schemaVersion", "authorityId", "hostId", "generation",
    "phase", "operationId", "previousCheckpointDigest", "authorityStateDigest",
    "responseDigest", "epoch", "recordVersion",
  ])) throw new TypeError("checkpoint body shape is invalid");
  if (
    value.profile !== PROFILE ||
    value.schemaVersion !== 1 ||
    !isIdentifier(value.authorityId) ||
    !isIdentifier(value.hostId) ||
    !isSafeInteger(value.generation, 1) ||
    !["ISSUED", "ACCEPTED", "REVOKED"].includes(String(value.phase)) ||
    !isIdentifier(value.operationId) ||
    !isDigest(value.previousCheckpointDigest) ||
    !isDigest(value.authorityStateDigest) ||
    !isDigest(value.responseDigest) ||
    !isSafeInteger(value.epoch) ||
    !isSafeInteger(value.recordVersion, 1)
  ) throw new TypeError("checkpoint body fields are invalid");
}

function validateReceiptEnvelope(value: unknown): asserts value is WitnessReceiptEnvelope {
  if (!isRecord(value) || !exactKeys(value, ["body", "signature"]) || !isRecord(value.body)) {
    throw new TypeError("receipt envelope shape is invalid");
  }
  const body = value.body;
  if (!exactKeys(body, [
    "profile", "schemaVersion", "witnessId", "authorityId", "hostId",
    "generation", "operationId", "checkpointDigest", "previousCheckpointDigest",
    "keyId", "committedAt", "consistencyToken",
  ])) throw new TypeError("receipt body shape is invalid");
  if (
    body.profile !== PROFILE ||
    body.schemaVersion !== 1 ||
    !isIdentifier(body.witnessId) ||
    !isIdentifier(body.authorityId) ||
    !isIdentifier(body.hostId) ||
    !isSafeInteger(body.generation, 1) ||
    !isIdentifier(body.operationId) ||
    !isDigest(body.checkpointDigest) ||
    !isDigest(body.previousCheckpointDigest) ||
    !isDigest(body.keyId) ||
    typeof body.consistencyToken !== "string" ||
    body.consistencyToken.length === 0 ||
    body.consistencyToken.length > 8192 ||
    typeof value.signature !== "string"
  ) throw new TypeError("receipt fields are invalid");
  parseUtc(body.committedAt);
  const signature = decodeBase64Url(value.signature);
  if (signature.length !== 64) throw new TypeError("receipt signature must be 64 bytes");
}

export async function verifyReceiptAgainstTrustedBundle(
  checkpointBody: unknown,
  checkpointDigest: unknown,
  receiptEnvelope: unknown,
  trustBundle: WitnessTrustBundleBody,
  trustedNow: number,
): Promise<WitnessReceiptEnvelope> {
  validateCheckpointBody(checkpointBody);
  validateReceiptEnvelope(receiptEnvelope);
  if (!isDigest(checkpointDigest)) throw new TypeError("checkpoint digest is malformed");
  if (!isSafeInteger(trustedNow)) throw new TypeError("trusted time is malformed");

  const actualCheckpointDigest = hex(await sha256(canonicalBytes(checkpointBody)));
  if (actualCheckpointDigest !== checkpointDigest) throw new TypeError("checkpoint digest mismatch");
  const receipt = receiptEnvelope.body;
  const checkpoint = checkpointBody;
  if (
    receipt.profile !== checkpoint.profile ||
    receipt.schemaVersion !== checkpoint.schemaVersion ||
    receipt.authorityId !== checkpoint.authorityId ||
    receipt.hostId !== checkpoint.hostId ||
    receipt.generation !== checkpoint.generation ||
    receipt.operationId !== checkpoint.operationId ||
    receipt.previousCheckpointDigest !== checkpoint.previousCheckpointDigest ||
    receipt.checkpointDigest !== checkpointDigest ||
    trustBundle.profile !== receipt.profile ||
    trustBundle.witnessId !== receipt.witnessId
  ) throw new TypeError("receipt/checkpoint/trust scope binding mismatch");

  const matches = trustBundle.keys.filter((key) => key.keyId === receipt.keyId);
  if (matches.length !== 1) throw new TypeError("receipt signing key is missing or ambiguous");
  const key = matches[0];
  if (
    key.purpose !== "WITNESS_RECEIPT_SIGNING" ||
    key.witnessId !== receipt.witnessId ||
    !key.authorityIds.includes(receipt.authorityId)
  ) throw new TypeError("receipt signing key purpose or scope mismatch");
  const notBefore = parseUtc(key.notBefore);
  const notAfter = parseUtc(key.notAfter);
  if (trustedNow < notBefore || trustedNow >= notAfter) {
    throw new TypeError("trusted receipt time is outside key validity");
  }
  if (key.retiredAt !== undefined && trustedNow >= parseUtc(key.retiredAt)) {
    throw new TypeError("receipt signing key is retired");
  }
  if (trustBundle.revocations.some((item) => item.keyId === receipt.keyId)) {
    throw new TypeError("receipt signing key is revoked");
  }
  const publicKey = decodeBase64Url(key.publicKeyBase64Url);
  if (publicKey.length !== 32 || hex(await sha256(publicKey)) !== key.keyId) {
    throw new TypeError("receipt signing key fingerprint mismatch");
  }
  const signature = decodeBase64Url(receiptEnvelope.signature);
  const signedBytes = new Uint8Array([
    ...encoder.encode(RECEIPT_PREFIX),
    ...canonicalBytes(receipt),
  ]);
  if (!(await verifyEd25519(publicKey, signature, signedBytes))) {
    throw new TypeError("receipt signature is invalid");
  }
  return receiptEnvelope;
}

function validateTreeHeadEnvelope(value: unknown): asserts value is WitnessTreeHeadEnvelope {
  if (!isRecord(value) || !exactKeys(value, ["body", "signature"]) || !isRecord(value.body)) {
    throw new TypeError("tree-head envelope shape is invalid");
  }
  const body = value.body;
  if (!exactKeys(body, [
    "profile", "schemaVersion", "witnessId", "authorityId", "hostId",
    "logId", "treeSize", "rootHash", "timestamp", "keyId",
  ])) throw new TypeError("tree-head body shape is invalid");
  if (
    body.profile !== MERKLE_PROFILE ||
    body.schemaVersion !== 1 ||
    !isIdentifier(body.witnessId) ||
    !isIdentifier(body.authorityId) ||
    !isIdentifier(body.hostId) ||
    !isIdentifier(body.logId) ||
    !isSafeInteger(body.treeSize, 1) ||
    !isDigest(body.rootHash) ||
    !isDigest(body.keyId) ||
    typeof value.signature !== "string"
  ) throw new TypeError("tree-head fields are invalid");
  parseUtc(body.timestamp);
  const signature = decodeBase64Url(value.signature);
  if (signature.length !== 64) throw new TypeError("tree-head signature must be 64 bytes");
}

export async function verifySignedTreeHead(
  envelope: unknown,
  trustBundle: WitnessTrustBundleBody,
  trustedNow: number,
  expectedScope: ExpectedWitnessScope,
): Promise<WitnessTreeHeadBody> {
  validateTreeHeadEnvelope(envelope);
  if (!isSafeInteger(trustedNow)) throw new TypeError("trusted time is malformed");
  const body = envelope.body;
  if (
    body.witnessId !== expectedScope.witnessId ||
    body.authorityId !== expectedScope.authorityId ||
    body.hostId !== expectedScope.hostId
  ) throw new TypeError("tree-head scope substitution");

  const matches = trustBundle.keys.filter((key) => key.keyId === body.keyId);
  if (matches.length !== 1) throw new TypeError("tree-head signing key is missing or ambiguous");
  const key = matches[0];
  if (
    key.purpose !== "WITNESS_LOG_SIGNING" ||
    key.witnessId !== body.witnessId ||
    !key.authorityIds.includes(body.authorityId)
  ) throw new TypeError("tree-head key purpose or scope mismatch");

  const headTime = parseUtc(body.timestamp);
  const notBefore = parseUtc(key.notBefore);
  const notAfter = parseUtc(key.notAfter);
  if (headTime < notBefore || headTime >= notAfter || trustedNow < notBefore || trustedNow >= notAfter) {
    throw new TypeError("tree-head timestamp or trusted time is outside key validity");
  }
  if (headTime > trustedNow) throw new TypeError("tree-head timestamp is in the future");
  if (key.retiredAt !== undefined && trustedNow >= parseUtc(key.retiredAt)) {
    throw new TypeError("tree-head signing key is retired");
  }
  if (trustBundle.revocations.some((item) => item.keyId === body.keyId)) {
    throw new TypeError("tree-head signing key is revoked");
  }
  const publicKey = decodeBase64Url(key.publicKeyBase64Url);
  if (publicKey.length !== 32 || hex(await sha256(publicKey)) !== key.keyId) {
    throw new TypeError("tree-head signing key fingerprint mismatch");
  }
  const signature = decodeBase64Url(envelope.signature);
  const signedBytes = new Uint8Array([
    ...encoder.encode(TREE_HEAD_PREFIX),
    ...canonicalBytes(body),
  ]);
  if (!(await verifyEd25519(publicKey, signature, signedBytes))) {
    throw new TypeError("tree-head signature is invalid");
  }
  return body;
}

function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(new Uint8Array([1, ...left, ...right]));
}

async function leafHash(data: Uint8Array): Promise<Uint8Array> {
  return sha256(new Uint8Array([0, ...data]));
}

function largestPowerOfTwoLessThan(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 1) throw new TypeError("tree size must exceed one");
  return 2 ** (Math.floor(Math.log2(value - 1)));
}

export async function merkleTreeHash(entries: readonly Uint8Array[]): Promise<Uint8Array> {
  if (entries.length === 0) return sha256(new Uint8Array());
  if (entries.length === 1) return leafHash(entries[0]);
  const split = largestPowerOfTwoLessThan(entries.length);
  return nodeHash(
    await merkleTreeHash(entries.slice(0, split)),
    await merkleTreeHash(entries.slice(split)),
  );
}

export async function inclusionProof(
  leafIndex: number,
  entries: readonly Uint8Array[],
): Promise<Uint8Array[]> {
  const size = entries.length;
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= size) {
    throw new TypeError("leaf index is outside the tree");
  }
  if (size === 1) return [];
  const split = largestPowerOfTwoLessThan(size);
  if (leafIndex < split) {
    return [
      ...await inclusionProof(leafIndex, entries.slice(0, split)),
      await merkleTreeHash(entries.slice(split)),
    ];
  }
  return [
    ...await inclusionProof(leafIndex - split, entries.slice(split)),
    await merkleTreeHash(entries.slice(0, split)),
  ];
}

export async function verifyInclusionProof(
  leafIndex: number,
  treeSize: number,
  leafDigest: Uint8Array,
  rootDigest: Uint8Array,
  proof: readonly Uint8Array[],
): Promise<boolean> {
  if (
    !Number.isSafeInteger(leafIndex) ||
    !Number.isSafeInteger(treeSize) ||
    treeSize <= 0 ||
    leafIndex < 0 ||
    leafIndex >= treeSize ||
    leafDigest.length !== 32 ||
    rootDigest.length !== 32 ||
    proof.some((item) => item.length !== 32)
  ) return false;

  let fn = leafIndex;
  let sn = treeSize - 1;
  let calculated = leafDigest;
  for (const sibling of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      calculated = await nodeHash(sibling, calculated);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      calculated = await nodeHash(calculated, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && hex(calculated) === hex(rootDigest);
}

async function consistencySubproof(
  firstSize: number,
  entries: readonly Uint8Array[],
  completeSubtreeKnown: boolean,
): Promise<Uint8Array[]> {
  const secondSize = entries.length;
  if (firstSize === secondSize) {
    return completeSubtreeKnown ? [] : [await merkleTreeHash(entries)];
  }
  const split = largestPowerOfTwoLessThan(secondSize);
  if (firstSize <= split) {
    return [
      ...await consistencySubproof(firstSize, entries.slice(0, split), completeSubtreeKnown),
      await merkleTreeHash(entries.slice(split)),
    ];
  }
  return [
    ...await consistencySubproof(firstSize - split, entries.slice(split), false),
    await merkleTreeHash(entries.slice(0, split)),
  ];
}

export async function consistencyProof(
  firstSize: number,
  entries: readonly Uint8Array[],
): Promise<Uint8Array[]> {
  if (!Number.isSafeInteger(firstSize) || firstSize <= 0 || firstSize >= entries.length) {
    throw new TypeError("consistency proof requires 0 < first size < second size");
  }
  return consistencySubproof(firstSize, entries, true);
}

export async function verifyConsistencyProof(
  firstSize: number,
  secondSize: number,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
  proof: readonly Uint8Array[],
): Promise<boolean> {
  if (
    !Number.isSafeInteger(firstSize) ||
    !Number.isSafeInteger(secondSize) ||
    firstSize <= 0 ||
    secondSize < firstSize ||
    firstRoot.length !== 32 ||
    secondRoot.length !== 32 ||
    proof.some((item) => item.length !== 32)
  ) return false;
  if (firstSize === secondSize) return proof.length === 0 && hex(firstRoot) === hex(secondRoot);
  if (proof.length === 0) return false;

  const path = [...proof];
  if ((firstSize & (firstSize - 1)) === 0) path.unshift(firstRoot);
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  if (fn & 1) {
    while (fn & 1) {
      fn >>= 1;
      sn >>= 1;
    }
  }
  let firstCalculated = path[0];
  let secondCalculated = path[0];
  if (!firstCalculated) return false;
  for (const sibling of path.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      firstCalculated = await nodeHash(sibling, firstCalculated);
      secondCalculated = await nodeHash(sibling, secondCalculated);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      secondCalculated = await nodeHash(secondCalculated, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return (
    sn === 0 &&
    hex(firstCalculated) === hex(firstRoot) &&
    hex(secondCalculated) === hex(secondRoot)
  );
}

export async function verifyReceiptInclusion(
  receiptEnvelope: WitnessReceiptEnvelope,
  leafIndex: number,
  treeHead: WitnessTreeHeadBody,
  proofHex: readonly string[],
): Promise<string> {
  if (
    receiptEnvelope.body.witnessId !== treeHead.witnessId ||
    receiptEnvelope.body.authorityId !== treeHead.authorityId ||
    receiptEnvelope.body.hostId !== treeHead.hostId
  ) throw new TypeError("receipt/tree-head scope mismatch");
  const proof = proofHex.map(decodeHex);
  const leaf = await leafHash(canonicalBytes(receiptEnvelope));
  const root = decodeHex(treeHead.rootHash);
  if (!(await verifyInclusionProof(leafIndex, treeHead.treeSize, leaf, root, proof))) {
    throw new TypeError("receipt inclusion proof is invalid");
  }
  return hex(leaf);
}

export async function verifyTreeHeadExtension(
  prior: WitnessTreeHeadBody,
  current: WitnessTreeHeadBody,
  proofHex: readonly string[],
): Promise<void> {
  if (
    prior.witnessId !== current.witnessId ||
    prior.authorityId !== current.authorityId ||
    prior.hostId !== current.hostId ||
    prior.logId !== current.logId
  ) throw new TypeError("tree-head log or scope substitution");
  if (current.treeSize < prior.treeSize) throw new TypeError("tree-size rollback");
  const valid = await verifyConsistencyProof(
    prior.treeSize,
    current.treeSize,
    decodeHex(prior.rootHash),
    decodeHex(current.rootHash),
    proofHex.map(decodeHex),
  );
  if (!valid) throw new TypeError("tree-head consistency proof is invalid");
}

export async function verifyWitnessEvidence(input: {
  readonly checkpointBody: WitnessCheckpointBody;
  readonly checkpointDigest: string;
  readonly receiptEnvelope: WitnessReceiptEnvelope;
  readonly trustBundle: WitnessTrustBundleEnvelope;
  readonly pinnedRoots: readonly PinnedRootKey[];
  readonly expectedTrustState: ExpectedTrustBundleState;
  readonly trustedNow: number;
  readonly treeHeadEnvelope: WitnessTreeHeadEnvelope;
  readonly expectedScope: ExpectedWitnessScope;
  readonly leafIndex: number;
  readonly inclusionProofHex: readonly string[];
  readonly priorTreeHead: WitnessTreeHeadBody;
  readonly consistencyProofHex: readonly string[];
}): Promise<{
  readonly trustBundle: VerifiedTrustBundle;
  readonly receipt: WitnessReceiptEnvelope;
  readonly treeHead: WitnessTreeHeadBody;
  readonly receiptLeafHash: string;
}> {
  const trust = await verifyTrustBundleEnvelope(
    input.trustBundle,
    input.pinnedRoots,
    input.expectedTrustState,
  );
  const receipt = await verifyReceiptAgainstTrustedBundle(
    input.checkpointBody,
    input.checkpointDigest,
    input.receiptEnvelope,
    trust.body,
    input.trustedNow,
  );
  const treeHead = await verifySignedTreeHead(
    input.treeHeadEnvelope,
    trust.body,
    input.trustedNow,
    input.expectedScope,
  );
  const receiptLeafHash = await verifyReceiptInclusion(
    receipt,
    input.leafIndex,
    treeHead,
    input.inclusionProofHex,
  );
  await verifyTreeHeadExtension(
    input.priorTreeHead,
    treeHead,
    input.consistencyProofHex,
  );
  return { trustBundle: trust, receipt, treeHead, receiptLeafHash };
}
