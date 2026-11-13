# Runner Ed25519 request-signature format

**Status:** Interoperability spike; transport protocol remains proposed.

## Canonical message

The Go runner signer and Cloudflare Worker verifier construct the same UTF-8 message, with fields separated by a single LF byte and no trailing LF:

```text
SKYHIGH-RUNNER-REQUEST-V1
{keyId}
{HTTP_METHOD}
{canonical_path_and_query}
{unix_timestamp_seconds}
{nonce_base64url}
{lowercase_sha256_hex_of_exact_body_bytes}
```

Rules:
- `keyId`: 1–128 ASCII characters from letters, digits, dot, underscore, colon and hyphen.
- HTTP method: uppercase ASCII token, 3–10 characters.
- Path: absolute path beginning with `/`; whitespace and line breaks are rejected. Query string is included exactly as sent.
- Timestamp: 10-digit Unix seconds. The request handler must separately enforce the allowed clock-skew window.
- Nonce: 32 cryptographically random bytes, unpadded canonical base64url (43 characters). The request handler must separately consume each nonce once in durable storage.
- Body digest: SHA-256 over the exact transmitted body bytes, before JSON parsing or normalization.
- Signature: Ed25519 over the canonical message, encoded as unpadded canonical base64url (64 signature bytes).
- Public key: raw Ed25519 public key (32 bytes), encoded as unpadded base64url when transported/stored in text form.

## Shared interoperability vector

`test-fixtures/runner-ed25519-v1.json` is a deterministic, test-only vector consumed by both Go and TypeScript tests. Its private seed is used only in test code to prove that Go signing matches the same signature that Cloudflare-compatible Web Crypto verifies. It must never be reused for runner identity or deployment.

## What this spike proves

- Identical canonical request bytes in Go and TypeScript.
- Go Ed25519 signature output matches the shared vector.
- Web Crypto verifies the Go-compatible signature.
- Changes to key ID, method, path, timestamp, nonce or body invalidate the signature.
- Malformed and non-canonical base64url values fail closed.

## What it does not prove

This is not a complete authentication system. It does not implement runner registration, public-key storage, revocation, timestamp freshness enforcement, nonce replay storage, signed HTTP middleware, claim endpoints, lease acceptance receipts, artifact access or execution. Those require separate implementation and security tests. Do not enable runner network access based on this spike alone.
