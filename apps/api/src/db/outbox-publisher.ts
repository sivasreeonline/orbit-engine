import type { OutboxLease } from "./outbox-lease-repository";

export interface OutboxLeaseStore {
  claimBatch(
    workerId: string,
    batchSize: number,
    leaseDurationSeconds: number,
  ): Promise<OutboxLease[]>;
  markPublished(outboxId: string, workerId: string, leaseToken: string): Promise<boolean>;
  releaseForRetry(
    outboxId: string,
    workerId: string,
    leaseToken: string,
    availableAt: Date,
  ): Promise<boolean>;
}

export interface ExecutionQueue {
  send(message: Readonly<Record<string, unknown>>): Promise<void>;
}

export type OutboxPublishOutcome =
  | { readonly outboxId: string; readonly status: "PUBLISHED" }
  | { readonly outboxId: string; readonly status: "ACKNOWLEDGEMENT_LOST" }
  | { readonly outboxId: string; readonly status: "SEND_FAILED_RELEASED" }
  | { readonly outboxId: string; readonly status: "SEND_FAILED_LEASE_EXPIRED" };

export interface OutboxPublisherOptions {
  readonly workerId: string;
  readonly batchSize: number;
  readonly leaseDurationSeconds: number;
  /** Retry timing is a caller-owned operational policy, not hard-coded here. */
  readonly retryAt: (deliveryAttempts: number, now: Date) => Date;
}

/**
 * Publishes metadata-only outbox messages to an at-least-once queue.
 * A queue send followed by a lost DB acknowledgement can produce a duplicate;
 * consumers must therefore be idempotent by execution ID.
 */
export async function publishOutboxBatch(
  store: OutboxLeaseStore,
  queue: ExecutionQueue,
  options: OutboxPublisherOptions,
): Promise<OutboxPublishOutcome[]> {
  const leases = await store.claimBatch(
    options.workerId,
    options.batchSize,
    options.leaseDurationSeconds,
  );
  const outcomes: OutboxPublishOutcome[] = [];

  for (const lease of leases) {
    try {
      await queue.send(lease.payload);
    } catch {
      const released = await store.releaseForRetry(
        lease.id,
        options.workerId,
        lease.leaseToken,
        options.retryAt(lease.deliveryAttempts, new Date()),
      );
      outcomes.push({
        outboxId: lease.id,
        status: released ? "SEND_FAILED_RELEASED" : "SEND_FAILED_LEASE_EXPIRED",
      });
      continue;
    }

    const acknowledged = await store.markPublished(
      lease.id,
      options.workerId,
      lease.leaseToken,
    );
    outcomes.push({
      outboxId: lease.id,
      status: acknowledged ? "PUBLISHED" : "ACKNOWLEDGEMENT_LOST",
    });
  }

  return outcomes;
}
