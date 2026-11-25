export interface HyperdriveBinding {
  readonly connectionString: string;
}

export interface ExecutionQueueBinding {
  send(message: Readonly<Record<string, unknown>>): Promise<void>;
}

export interface Env {
  readonly HYPERDRIVE?: HyperdriveBinding;
  readonly EXECUTION_QUEUE?: ExecutionQueueBinding;
  readonly OUTBOX_BATCH_SIZE?: string;
  readonly OUTBOX_LEASE_SECONDS?: string;
  readonly OUTBOX_RETRY_BASE_MS?: string;
  readonly OUTBOX_RETRY_MAX_MS?: string;
  readonly RUNNER_RECOVERY_BATCH_SIZE?: string;
  readonly RUNNER_RECOVERY_MAX_RETRIES?: string;
  readonly RUNNER_RECOVERY_BASE_DELAY_SECONDS?: string;
  readonly RUNNER_RECOVERY_MAX_DELAY_SECONDS?: string;
  readonly CORS_ALLOWED_ORIGINS?: string;
  readonly APP_ENV?: string;
  readonly JAVA_RUNTIME_VERSION?: string;
  readonly PYTHON_RUNTIME_VERSION?: string;
  readonly PROTOCOL_V2_POLICY_REVISION?: string;
  readonly JAVA_RUNTIME_IMAGE_DIGEST?: string;
  readonly PYTHON_RUNTIME_IMAGE_DIGEST?: string;
  readonly EXECUTION_CPU_QUOTA_MILLIS?: string;
  readonly EXECUTION_MEMORY_BYTES?: string;
  readonly EXECUTION_WALL_TIME_MILLIS?: string;
  readonly EXECUTION_PROCESS_LIMIT?: string;
  readonly EXECUTION_OUTPUT_BYTES?: string;
  readonly EXECUTION_SCRATCH_BYTES?: string;
  readonly EXECUTION_SCRATCH_INODES?: string;
}
