import { describe, expect, it } from "vitest";
import {
  ExecutionProtocolV2PolicyError,
  loadExecutionProtocolV2Policy,
} from "./execution-protocol-v2-policy";

const validPolicyEnv = {
  PROTOCOL_V2_POLICY_REVISION: "skyhigh-v2-policy-1",
  JAVA_RUNTIME_IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
  PYTHON_RUNTIME_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`,
  EXECUTION_CPU_QUOTA_MILLIS: "2000",
  EXECUTION_MEMORY_BYTES: "536870912",
  EXECUTION_WALL_TIME_MILLIS: "10000",
  EXECUTION_PROCESS_LIMIT: "32",
  EXECUTION_OUTPUT_BYTES: "1048576",
  EXECUTION_SCRATCH_BYTES: "268435456",
  EXECUTION_SCRATCH_INODES: "4096",
};

describe("loadExecutionProtocolV2Policy", () => {
  it("keeps v2 policy disabled when no v2 settings are configured", () => {
    expect(loadExecutionProtocolV2Policy({})).toBeNull();
  });

  it("loads immutable runtime digests and all seven positive resource limits", () => {
    expect(loadExecutionProtocolV2Policy(validPolicyEnv)).toEqual({
      policyRevision: "skyhigh-v2-policy-1",
      runtimeImageDigests: {
        java: `sha256:${"a".repeat(64)}`,
        python: `sha256:${"b".repeat(64)}`,
      },
      limits: {
        cpuQuotaMillis: 2000,
        memoryBytes: 536870912,
        wallTimeMillis: 10000,
        processLimit: 32,
        outputBytes: 1048576,
        scratchBytes: 268435456,
        scratchInodes: 4096,
      },
    });
  });

  it("rejects partial policy instead of filling missing values with defaults", () => {
    expect(() => loadExecutionProtocolV2Policy({
      PROTOCOL_V2_POLICY_REVISION: "skyhigh-v2-policy-1",
    })).toThrow(ExecutionProtocolV2PolicyError);
    expect(() => loadExecutionProtocolV2Policy({
      PROTOCOL_V2_POLICY_REVISION: "skyhigh-v2-policy-1",
    })).toThrow(/protocol_v2_policy_incomplete/);
  });

  it("rejects mutable tags and malformed runtime image digests", () => {
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      JAVA_RUNTIME_IMAGE_DIGEST: "ghcr.io/skyhigh/java:25",
    })).toThrow("protocol_v2_policy_runtime_image_digest_invalid");
  });

  it("rejects zero, non-decimal and unsafe resource values", () => {
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      EXECUTION_MEMORY_BYTES: "0",
    })).toThrow(ExecutionProtocolV2PolicyError);
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      EXECUTION_CPU_QUOTA_MILLIS: "2e3",
    })).toThrow(ExecutionProtocolV2PolicyError);
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      EXECUTION_OUTPUT_BYTES: "9007199254740992",
    })).toThrow(ExecutionProtocolV2PolicyError);
  });

  it("rejects wall times that cannot fit the database deadline window", () => {
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      EXECUTION_WALL_TIME_MILLIS: "600001",
    })).toThrow("protocol_v2_policy_wall_time_out_of_range");
  });

  it("enforces the database's scratch byte and inode ceilings", () => {
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      EXECUTION_SCRATCH_BYTES: "536870913",
    })).toThrow("protocol_v2_policy_scratch_limit_out_of_range");
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      EXECUTION_SCRATCH_INODES: "8193",
    })).toThrow("protocol_v2_policy_scratch_limit_out_of_range");
  });

  it("rejects blank or whitespace-padded policy values", () => {
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      PROTOCOL_V2_POLICY_REVISION: " ",
    })).toThrow(ExecutionProtocolV2PolicyError);
    expect(() => loadExecutionProtocolV2Policy({
      ...validPolicyEnv,
      EXECUTION_MEMORY_BYTES: " 1024 ",
    })).toThrow(ExecutionProtocolV2PolicyError);
  });
});
