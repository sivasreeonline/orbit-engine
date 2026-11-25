import type { Env } from "../env";

const POLICY_ENV_KEYS = [
  "PROTOCOL_V2_POLICY_REVISION",
  "JAVA_RUNTIME_IMAGE_DIGEST",
  "PYTHON_RUNTIME_IMAGE_DIGEST",
  "EXECUTION_CPU_QUOTA_MILLIS",
  "EXECUTION_MEMORY_BYTES",
  "EXECUTION_WALL_TIME_MILLIS",
  "EXECUTION_PROCESS_LIMIT",
  "EXECUTION_OUTPUT_BYTES",
  "EXECUTION_SCRATCH_BYTES",
  "EXECUTION_SCRATCH_INODES",
] as const;

type PolicyEnv = Pick<Env, (typeof POLICY_ENV_KEYS)[number]>;

export interface ExecutionProtocolV2Limits {
  readonly cpuQuotaMillis: number;
  readonly memoryBytes: number;
  readonly wallTimeMillis: number;
  readonly processLimit: number;
  readonly outputBytes: number;
  readonly scratchBytes: number;
  readonly scratchInodes: number;
}

export interface ExecutionProtocolV2Policy {
  readonly policyRevision: string;
  readonly runtimeImageDigests: {
    readonly java: string;
    readonly python: string;
  };
  readonly limits: ExecutionProtocolV2Limits;
}

export class ExecutionProtocolV2PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExecutionProtocolV2PolicyError";
  }
}

function requiredValue(env: PolicyEnv, key: (typeof POLICY_ENV_KEYS)[number]): string {
  const value = env[key];
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new ExecutionProtocolV2PolicyError(`protocol_v2_policy_${key.toLowerCase()}_invalid`);
  }
  return value;
}

function positiveInteger(env: PolicyEnv, key: (typeof POLICY_ENV_KEYS)[number]): number {
  const raw = requiredValue(env, key);
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new ExecutionProtocolV2PolicyError(`protocol_v2_policy_${key.toLowerCase()}_invalid`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ExecutionProtocolV2PolicyError(`protocol_v2_policy_${key.toLowerCase()}_out_of_range`);
  }
  return value;
}

/**
 * Returns null only when v2 policy is entirely absent. Partial or malformed
 * configuration is an error; no resource limits or image digests are guessed.
 * This parser does not enable v2 dispatch or student execution.
 */
export function loadExecutionProtocolV2Policy(
  env: PolicyEnv,
): ExecutionProtocolV2Policy | null {
  const configured = POLICY_ENV_KEYS.filter((key) => env[key] !== undefined);
  if (configured.length === 0) return null;
  if (configured.length !== POLICY_ENV_KEYS.length) {
    const missing = POLICY_ENV_KEYS.filter((key) => env[key] === undefined);
    throw new ExecutionProtocolV2PolicyError(
      `protocol_v2_policy_incomplete:${missing.map((key) => key.toLowerCase()).join(",")}`,
    );
  }

  const policyRevision = requiredValue(env, "PROTOCOL_V2_POLICY_REVISION");
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(policyRevision)) {
    throw new ExecutionProtocolV2PolicyError("protocol_v2_policy_revision_invalid");
  }

  const javaImage = requiredValue(env, "JAVA_RUNTIME_IMAGE_DIGEST");
  const pythonImage = requiredValue(env, "PYTHON_RUNTIME_IMAGE_DIGEST");
  const imageDigestPattern = /^sha256:[0-9a-f]{64}$/;
  if (!imageDigestPattern.test(javaImage) || !imageDigestPattern.test(pythonImage)) {
    throw new ExecutionProtocolV2PolicyError("protocol_v2_policy_runtime_image_digest_invalid");
  }

  const scratchBytes = positiveInteger(env, "EXECUTION_SCRATCH_BYTES");
  const scratchInodes = positiveInteger(env, "EXECUTION_SCRATCH_INODES");
  if (scratchBytes > 536870912 || scratchInodes > 8192) {
    throw new ExecutionProtocolV2PolicyError("protocol_v2_policy_scratch_limit_out_of_range");
  }

  return {
    policyRevision,
    runtimeImageDigests: { java: javaImage, python: pythonImage },
    limits: {
      cpuQuotaMillis: positiveInteger(env, "EXECUTION_CPU_QUOTA_MILLIS"),
      memoryBytes: positiveInteger(env, "EXECUTION_MEMORY_BYTES"),
      wallTimeMillis: positiveInteger(env, "EXECUTION_WALL_TIME_MILLIS"),
      processLimit: positiveInteger(env, "EXECUTION_PROCESS_LIMIT"),
      outputBytes: positiveInteger(env, "EXECUTION_OUTPUT_BYTES"),
      scratchBytes,
      scratchInodes,
    },
  };
}
