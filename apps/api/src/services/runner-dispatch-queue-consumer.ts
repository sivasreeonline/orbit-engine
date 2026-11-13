import type {
  ExecutionRequestedEnvelope,
  PostgresRunnerDispatchHandoffRepository,
} from "../db/runner-dispatch-handoff-repository";

export interface RunnerDispatchQueueMessage {
  readonly body: unknown;
  ack(): void;
  retry(): void;
}

export interface RunnerDispatchQueueBatch {
  readonly messages: readonly RunnerDispatchQueueMessage[];
}

export interface RunnerDispatchQueueConsumerSummary {
  readonly received: number;
  readonly acknowledged: number;
  readonly retried: number;
}

type RunnerDispatchHandoffStore = Pick<PostgresRunnerDispatchHandoffRepository, "record">;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseEnvelope(value: unknown): ExecutionRequestedEnvelope {
  if (!isRecord(value)) throw new Error("invalid_runner_dispatch_queue_envelope");
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "attemptId,executionId,protocolVersion") {
    throw new Error("invalid_runner_dispatch_queue_envelope");
  }
  const { executionId, attemptId, protocolVersion } = value;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (typeof executionId !== "string" || !uuid.test(executionId) ||
      typeof attemptId !== "string" || !uuid.test(attemptId) ||
      protocolVersion !== "v1") {
    throw new Error("invalid_runner_dispatch_queue_envelope");
  }
  return { executionId, attemptId, protocolVersion: "v1" };
}

/**
 * Acknowledges a queue delivery only after the PostgreSQL handoff repository
 * commits the durable runner-dispatch intent. Duplicate durable intents are
 * safe to acknowledge. Invalid messages and transient failures are retried so
 * the configured queue dead-letter policy can retain poison deliveries.
 */
export async function consumeRunnerDispatchBatch(
  batch: RunnerDispatchQueueBatch,
  handoff: RunnerDispatchHandoffStore,
): Promise<RunnerDispatchQueueConsumerSummary> {
  let acknowledged = 0;
  let retried = 0;

  for (const message of batch.messages) {
    try {
      const envelope = parseEnvelope(message.body);
      await handoff.record(envelope);
      message.ack();
      acknowledged += 1;
    } catch {
      message.retry();
      retried += 1;
    }
  }

  return {
    received: batch.messages.length,
    acknowledged,
    retried,
  };
}
