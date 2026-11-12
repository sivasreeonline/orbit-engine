import type { OutboxLease } from "../db/outbox-lease-repository";

export interface LocalExecutionDispatchEnvelope {
  readonly executionId: string;
  readonly attemptId: string;
  readonly protocolVersion: "v1";
}

/**
 * A sink must resolve only after the execution request has been durably
 * accepted by the next local handoff boundary. Merely putting work in memory
 * is not a valid acknowledgement.
 */
export interface DurableLocalDispatchSink {
  accept(envelope: LocalExecutionDispatchEnvelope): Promise<void>;
}

export interface LocalOutboxLeaseRepository {
  claimBatch(
    workerId: string,
    batchSize: number,
    leaseDurationSeconds: number,
  ): Promise<OutboxLease[]>;
  markPublished(
    outboxId: string,
    workerId: string,
    leaseToken: string,
  ): Promise<boolean>;
}

export interface LocalDispatchConfiguration {
  readonly workerId: string;
  readonly batchSize: number;
  readonly leaseDurationSeconds: number;
}

export interface LocalDispatchSummary {
  readonly claimed: number;
  readonly acknowledged: number;
  readonly rejected: number;
  readonly fenced: number;
}

/**
 * Development-only outbox pump. It deliberately does not execute student
 * code and does not replace Cloudflare Queues in production.
 *
 * The outbox row is acknowledged only after the injected sink confirms
 * durable acceptance. If the sink fails, the lease is left to expire so the
 * same outbox identity can be retried. A stale lease cannot acknowledge work.
 */
export class LocalExecutionOutboxDispatcher {
  constructor(
    private readonly outbox: LocalOutboxLeaseRepository,
    private readonly sink: DurableLocalDispatchSink,
    private readonly configuration: LocalDispatchConfiguration,
  ) {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(configuration.workerId)) {
      throw new Error("invalid_local_dispatch_worker_id");
    }
    if (!Number.isSafeInteger(configuration.batchSize) ||
        configuration.batchSize < 1 || configuration.batchSize > 100) {
      throw new Error("invalid_local_dispatch_batch_size");
    }
    if (!Number.isSafeInteger(configuration.leaseDurationSeconds) ||
        configuration.leaseDurationSeconds < 1 ||
        configuration.leaseDurationSeconds > 3600) {
      throw new Error("invalid_local_dispatch_lease_duration");
    }
  }

  async dispatchOnce(): Promise<LocalDispatchSummary> {
    const leases = await this.outbox.claimBatch(
      this.configuration.workerId,
      this.configuration.batchSize,
      this.configuration.leaseDurationSeconds,
    );

    let acknowledged = 0;
    let rejected = 0;
    let fenced = 0;

    for (const lease of leases) {
      let envelope: LocalExecutionDispatchEnvelope;
      try {
        envelope = this.toEnvelope(lease);
        await this.sink.accept(envelope);
      } catch {
        // Do not acknowledge. The lease will expire and the exact same
        // durable outbox identity can be retried by this or another worker.
        rejected += 1;
        continue;
      }

      const marked = await this.outbox.markPublished(
        lease.id,
        this.configuration.workerId,
        lease.leaseToken,
      );
      if (marked) acknowledged += 1;
      else fenced += 1;
    }

    return {
      claimed: leases.length,
      acknowledged,
      rejected,
      fenced,
    };
  }

  private toEnvelope(lease: OutboxLease): LocalExecutionDispatchEnvelope {
    if (lease.eventType !== "EXECUTION_REQUESTED" ||
        lease.protocolVersion !== "v1") {
      throw new Error("unsupported_local_dispatch_event");
    }

    const keys = Object.keys(lease.payload).sort();
    if (keys.join(",") !== "attemptId,executionId,protocolVersion") {
      throw new Error("invalid_local_dispatch_payload_shape");
    }

    const executionId = lease.payload.executionId;
    const attemptId = lease.payload.attemptId;
    const protocolVersion = lease.payload.protocolVersion;
    if (typeof executionId !== "string" ||
        !/^[0-9a-f-]{36}$/i.test(executionId) ||
        executionId !== lease.executionId ||
        typeof attemptId !== "string" ||
        !/^[0-9a-f-]{36}$/i.test(attemptId) ||
        protocolVersion !== "v1") {
      throw new Error("invalid_local_dispatch_payload_identity");
    }

    return { executionId, attemptId, protocolVersion: "v1" };
  }
}
