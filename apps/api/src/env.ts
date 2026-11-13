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
}
