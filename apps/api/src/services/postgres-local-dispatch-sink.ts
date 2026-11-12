import type { PostgresRunnerDispatchHandoffRepository } from "../db/runner-dispatch-handoff-repository";
import type {
  DurableLocalDispatchSink,
  LocalExecutionDispatchEnvelope,
} from "./local-execution-outbox-dispatcher";

/**
 * Adapts the local intake-outbox pump to the durable runner-dispatch outbox.
 * The repository commits the handoff intent before this method resolves.
 */
export class PostgresLocalDispatchSink implements DurableLocalDispatchSink {
  constructor(
    private readonly handoff: Pick<PostgresRunnerDispatchHandoffRepository, "record">,
  ) {}

  async accept(envelope: LocalExecutionDispatchEnvelope): Promise<void> {
    // RECORDED and exact DUPLICATE both mean the durable handoff already exists.
    // Any validation/storage failure propagates so the intake lease is not acked.
    await this.handoff.record(envelope);
  }
}
