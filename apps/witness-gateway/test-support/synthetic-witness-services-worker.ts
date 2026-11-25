import { WorkerEntrypoint } from "cloudflare:workers";
import { SyntheticWitnessEvidenceAuthority } from "./synthetic-witness-evidence-authority";
import { SyntheticWitnessProviderAdapter } from "./synthetic-witness-provider-adapter";
import type { WitnessEvidenceAuthority } from "../src/evidence/witness-evidence-authority";
import type {
  WitnessCheckpointScope,
  WitnessProviderAdapter,
  WitnessCheckpoint,
  WitnessCheckpointReceipt,
  StoredWitnessCheckpoint,
} from "../src/provider/witness-provider-adapter";
import type {
  WitnessEvidenceAuthorityRequest,
  WitnessEvidenceAuthorityBundle,
} from "../src/evidence/witness-evidence-authority";

interface Env {
  readonly FENCE_TEST_AUTHORITY_ROOT_PRIVATE_KEY_PKCS8: string;
  readonly FENCE_TEST_AUTHORITY_ROOT_PUBLIC_KEY_BASE64URL: string;
  /** One-shot fault injection; available only in the synthetic test Worker. */
  readonly FENCE_TEST_PROVIDER_LOSE_NEXT_ACK?: string;
  /** Fail evidence issuance once after provider commit to exercise durable retry. */
  readonly FENCE_TEST_AUTHORITY_FAIL_NEXT_ISSUANCE?: string;
  /** Return one structurally valid but cryptographically invalid inclusion proof. */
  readonly FENCE_TEST_AUTHORITY_CORRUPT_NEXT_PROOF?: string;
}

const provider = new SyntheticWitnessProviderAdapter();
let authority: SyntheticWitnessEvidenceAuthority | undefined;
let lostAckFaultConsumed = false;
let authorityFailureConsumed = false;
let authorityProofCorruptionConsumed = false;

function getAuthority(env: Env): SyntheticWitnessEvidenceAuthority {
  if (!authority) {
    if (!env.FENCE_TEST_AUTHORITY_ROOT_PRIVATE_KEY_PKCS8 ||
        !env.FENCE_TEST_AUTHORITY_ROOT_PUBLIC_KEY_BASE64URL) {
      throw new Error("synthetic evidence authority root is not configured");
    }
    authority = SyntheticWitnessEvidenceAuthority.withRootKeyMaterial(
      env.FENCE_TEST_AUTHORITY_ROOT_PRIVATE_KEY_PKCS8,
      env.FENCE_TEST_AUTHORITY_ROOT_PUBLIC_KEY_BASE64URL,
    );
  }
  return authority;
}

/** Test-only provider RPC. Its in-memory state is isolated to this Worker instance. */
export class SyntheticWitnessProvider extends WorkerEntrypoint<Env> implements WitnessProviderAdapter {
  appendIfCurrent(
    checkpoint: WitnessCheckpoint,
    expected: { readonly generation: number; readonly digest: string },
    idempotencyKey: string,
  ): Promise<WitnessCheckpointReceipt> {
    if (this.env.FENCE_TEST_PROVIDER_LOSE_NEXT_ACK === "true" && !lostAckFaultConsumed) {
      // Simulate a provider commit whose acknowledgement is lost in transit.
      // The coordinator must recover the immutable operation by its exact ID.
      provider.loseNextAck = true;
      lostAckFaultConsumed = true;
    }
    return provider.appendIfCurrent(checkpoint, expected, idempotencyKey);
  }

  readLatest(scope: WitnessCheckpointScope): Promise<StoredWitnessCheckpoint | null> {
    return provider.readLatest(scope);
  }

  readByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<StoredWitnessCheckpoint | null> {
    return provider.readByOperation(scope, operationId);
  }
}

/** Test-only evidence RPC. The root private key is never exposed as an RPC method. */
export class SyntheticWitnessEvidenceAuthorityEntrypoint
  extends WorkerEntrypoint<Env> implements WitnessEvidenceAuthority {
  issueOrRecoverEvidence(
    request: WitnessEvidenceAuthorityRequest,
  ): Promise<WitnessEvidenceAuthorityBundle> {
    if (this.env.FENCE_TEST_AUTHORITY_FAIL_NEXT_ISSUANCE === "true" && !authorityFailureConsumed) {
      // The provider may already have committed. The API must retain its exact
      // pending intent and recover the same operation/evidence on a later retry.
      authorityFailureConsumed = true;
      throw new Error("simulated evidence-authority outage after provider commit");
    }
    return getAuthority(this.env).issueOrRecoverEvidence(request).then((bundle) => {
      if (this.env.FENCE_TEST_AUTHORITY_CORRUPT_NEXT_PROOF === "true" && !authorityProofCorruptionConsumed) {
        // Keep the proof's shape valid so only independent cryptographic
        // verification detects the corruption; the authority's stored bundle
        // remains immutable and a later exact retry returns the original proof.
        authorityProofCorruptionConsumed = true;
        return {
          ...bundle,
          inclusionProofHex: [...bundle.inclusionProofHex, "f".repeat(64)],
        };
      }
      return bundle;
    });
  }

  readEvidenceByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<WitnessEvidenceAuthorityBundle | null> {
    return getAuthority(this.env).readEvidenceByOperation(scope, operationId);
  }
}

export default {
  async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  },
};
