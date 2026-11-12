import { buildApiHandler } from "./app";
import { UnconfiguredAuthenticator } from "./auth/unconfigured-authenticator";
import { PostgresOutboxLeaseRepository } from "./db/outbox-lease-repository";
import { publishOutboxBatch } from "./db/outbox-publisher";
import { PostgresProblemRepository } from "./db/problem-repository";
import { PostgresExecutionEvidenceRepository } from "./db/execution-evidence-repository";
import { PostgresExecutionSourceSnapshotRepository } from "./db/execution-source-snapshot-repository";
import type { Env } from "./env";

const authenticator = new UnconfiguredAuthenticator();
const publisherWorkerId = "sky-high-api-outbox-publisher";

function positiveInteger(value: string | undefined, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error("invalid_outbox_publisher_configuration");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new Error("invalid_outbox_publisher_configuration");
  }
  return parsed;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const repository = new PostgresProblemRepository(env);
    const evidenceRepository = new PostgresExecutionEvidenceRepository(
      env.HYPERDRIVE?.connectionString,
    );
    const sourceSnapshotRepository = new PostgresExecutionSourceSnapshotRepository(
      env.HYPERDRIVE?.connectionString,
    );
    const handler = buildApiHandler(env, {
      authenticator,
      repository,
      evidenceRepository,
      sourceSnapshotRepository,
    });
    return handler(request);
  },

  async scheduled(
    _controller: ScheduledController,
    env: Env,
    context: ExecutionContext,
  ): Promise<void> {
    const connectionString = env.HYPERDRIVE?.connectionString;
    const queue = env.EXECUTION_QUEUE;
    if (!connectionString || !queue) {
      console.error("outbox_publisher_not_configured");
      return;
    }

    const batchSize = positiveInteger(env.OUTBOX_BATCH_SIZE, 10, 100);
    const leaseSeconds = positiveInteger(env.OUTBOX_LEASE_SECONDS, 120, 3600);
    const retryBaseMs = positiveInteger(env.OUTBOX_RETRY_BASE_MS, 5_000, 300_000);
    const retryMaxMs = positiveInteger(env.OUTBOX_RETRY_MAX_MS, 300_000, 3_600_000);
    if (retryBaseMs > retryMaxMs) {
      throw new Error("invalid_outbox_publisher_configuration");
    }

    const repository = new PostgresOutboxLeaseRepository(connectionString);
    const task = publishOutboxBatch(repository, queue, {
      workerId: publisherWorkerId,
      batchSize,
      leaseDurationSeconds: leaseSeconds,
      retryAt: (attempts, now) => {
        const exponent = Math.min(Math.max(attempts - 1, 0), 16);
        const delay = Math.min(retryMaxMs, retryBaseMs * (2 ** exponent));
        return new Date(now.getTime() + delay);
      },
    }).catch(() => {
      // Do not log database errors, queue payloads or student source.
      console.error("outbox_publish_cycle_failed");
    });

    context.waitUntil(task);
  },
};
