import { buildApiHandler } from "./app";
import { UnconfiguredAuthenticator } from "./auth/unconfigured-authenticator";
import { PostgresOutboxLeaseRepository } from "./db/outbox-lease-repository";
import { publishOutboxBatch } from "./db/outbox-publisher";
import { PostgresProblemRepository } from "./db/problem-repository";
import { PostgresExecutionEvidenceRepository } from "./db/execution-evidence-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./db/runner-dispatch-handoff-repository";
import { PostgresRunnerIdentityRepository } from "./db/runner-identity-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./db/runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./db/runner-acceptance-repository";
import { PostgresRunnerStartRepository } from "./db/runner-start-repository";
import { PostgresRunnerHeartbeatRepository } from "./db/runner-heartbeat-repository";
import { PostgresRunnerArtifactRepository } from "./db/runner-artifact-repository";
import { PostgresRunnerRecoveryRepository } from "./db/runner-recovery-repository";
import { consumeRunnerDispatchBatch } from "./services/runner-dispatch-queue-consumer";
import { PostgresExecutionIntakeRepository } from "./db/execution-intake-repository";
import type { Env } from "./env";

const authenticator = new UnconfiguredAuthenticator();
const publisherWorkerId = "sky-high-api-outbox-publisher";
const runnerRecoveryWorkerId = "sky-high-api-runner-expiry-recovery";

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
    const connectionString = env.HYPERDRIVE?.connectionString;
    const evidenceRepository = new PostgresExecutionEvidenceRepository(connectionString);
    const executionIntakeRepository = new PostgresExecutionIntakeRepository(connectionString);
    const runnerIdentityRepository = new PostgresRunnerIdentityRepository(connectionString);
    const runnerDispatchLeaseRepository = new PostgresRunnerDispatchLeaseRepository(connectionString);
    const runnerAcceptanceRepository = new PostgresRunnerAcceptanceRepository(connectionString);
    const runnerStartRepository = new PostgresRunnerStartRepository(connectionString);
    const runnerHeartbeatRepository = new PostgresRunnerHeartbeatRepository(connectionString);
    const runnerArtifactRepository = new PostgresRunnerArtifactRepository(connectionString);
    const handler = buildApiHandler(env, {
      authenticator,
      repository,
      evidenceRepository,
      executionIntakeRepository,
      runnerIdentityRepository,
      runnerDispatchLeaseRepository,
      runnerAcceptanceRepository,
      runnerStartRepository,
      runnerHeartbeatRepository,
      runnerArtifactRepository,
      runnerCompletionRepository: evidenceRepository,
      runtimeVersions: {
        java: env.JAVA_RUNTIME_VERSION ?? "",
        python: env.PYTHON_RUNTIME_VERSION ?? "",
      },
    });
    return handler(request);
  },

  async queue(batch: MessageBatch<unknown>, env: Env, _context: ExecutionContext): Promise<void> {
    const connectionString = env.HYPERDRIVE?.connectionString;
    if (!connectionString) {
      for (const message of batch.messages) message.retry();
      console.error("runner_dispatch_consumer_database_not_configured", {
        received: batch.messages.length,
      });
      return;
    }

    const handoff = new PostgresRunnerDispatchHandoffRepository(connectionString);
    const summary = await consumeRunnerDispatchBatch(batch, handoff);
    console.info("runner_dispatch_handoff_batch_completed", summary);
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
    const recoveryRepository = new PostgresRunnerRecoveryRepository(connectionString);
    const recoveryBatchSize = positiveInteger(env.RUNNER_RECOVERY_BATCH_SIZE, 25, 100);
    const recoveryMaxRetries = positiveInteger(env.RUNNER_RECOVERY_MAX_RETRIES, 2, 10);
    const recoveryBaseDelaySeconds = positiveInteger(env.RUNNER_RECOVERY_BASE_DELAY_SECONDS, 5, 300);
    const recoveryMaxDelaySeconds = positiveInteger(env.RUNNER_RECOVERY_MAX_DELAY_SECONDS, 60, 3600);
    if (recoveryBaseDelaySeconds > recoveryMaxDelaySeconds) {
      throw new Error("invalid_runner_recovery_configuration");
    }
    const task = (async () => {
      try {
        const recoveries = await recoveryRepository.recoverExpiredRunning({
          workerId: runnerRecoveryWorkerId,
          batchSize: recoveryBatchSize,
          maxRetries: recoveryMaxRetries,
          baseDelaySeconds: recoveryBaseDelaySeconds,
          maxDelaySeconds: recoveryMaxDelaySeconds,
        });
        if (recoveries.length > 0) {
          console.info("runner_lease_recovery_batch_completed", {
            recovered: recoveries.length,
            requeued: recoveries.filter((item) => item.action === "REQUEUED").length,
            failedInfrastructure: recoveries.filter((item) => item.action === "FAILED_INFRASTRUCTURE").length,
          });
        }
      } catch {
        // Never log lease tokens, runner keys, student source or database errors.
        console.error("runner_lease_recovery_cycle_failed");
      }

      await publishOutboxBatch(repository, queue, {
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
    })();

    context.waitUntil(task);
  },
};
