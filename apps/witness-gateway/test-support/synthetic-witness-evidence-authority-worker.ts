import { WorkerEntrypoint } from "cloudflare:workers";
import { SyntheticWitnessEvidenceAuthority } from "./synthetic-witness-evidence-authority";
import type { WitnessEvidenceAuthority } from "../src/evidence/witness-evidence-authority";
import type {
  WitnessCheckpointScope,
} from "../src/provider/witness-provider-adapter";
import type {
  WitnessEvidenceAuthorityRequest,
  WitnessEvidenceAuthorityBundle,
} from "../src/evidence/witness-evidence-authority";

interface Env {
  readonly FENCE_TEST_AUTHORITY_ROOT_PRIVATE_KEY_PKCS8: string;
  readonly FENCE_TEST_AUTHORITY_ROOT_PUBLIC_KEY_BASE64URL: string;
  /** Fail evidence issuance once after provider commit to exercise durable retry. */
  readonly FENCE_TEST_AUTHORITY_FAIL_NEXT_ISSUANCE?: string;
  /** Return one shape-valid but cryptographically invalid inclusion proof. */
  readonly FENCE_TEST_AUTHORITY_CORRUPT_NEXT_PROOF?: string;
}

let authority: SyntheticWitnessEvidenceAuthority | undefined;
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

/**
 * Test-only authority Worker. It owns the ephemeral root private key and has
 * no provider adapter or provider RPC entrypoint in this Worker deployment.
 */
export class SyntheticWitnessEvidenceAuthorityEntrypoint
  extends WorkerEntrypoint<Env> implements WitnessEvidenceAuthority {
  issueOrRecoverEvidence(
    request: WitnessEvidenceAuthorityRequest,
  ): Promise<WitnessEvidenceAuthorityBundle> {
    if (this.env.FENCE_TEST_AUTHORITY_FAIL_NEXT_ISSUANCE === "true" && !authorityFailureConsumed) {
      authorityFailureConsumed = true;
      throw new Error("simulated evidence-authority outage after provider commit");
    }
    return getAuthority(this.env).issueOrRecoverEvidence(request).then((bundle) => {
      if (
        this.env.FENCE_TEST_AUTHORITY_CORRUPT_NEXT_PROOF === "true" &&
        !authorityProofCorruptionConsumed
      ) {
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
