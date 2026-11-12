import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface ExecutionRequestedEnvelope {
  readonly executionId: string;
  readonly attemptId: string;
  readonly protocolVersion: string;
}

export type RunnerDispatchHandoffResult =
  | { readonly status: "RECORDED"; readonly dispatchId: string }
  | { readonly status: "DUPLICATE"; readonly dispatchId: string };

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgHandoffClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgHandoffClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-handoff-consumer",
  }) as unknown as PgHandoffClient;

interface AuthoritativeExecutionRow extends Record<string, unknown> {
  readonly attempt_id: string;
  readonly job_state: string;
  readonly outbox_attempt_id: string;
  readonly outbox_protocol_version: string;
  readonly correlation_id: string;
}

interface DispatchRow extends Record<string, unknown> {
  readonly id: string;
  readonly attempt_id: string;
  readonly protocol_version: string;
  readonly correlation_id: string;
}

/**
 * Persists the durable queue-to-runner handoff record.
 *
 * This repository does not acknowledge a Cloudflare Queue message, claim a
 * runner lease, contact the Linux runner, retrieve artifacts or execute code.
 * Its caller may acknowledge only after this method resolves successfully.
 */
export class PostgresRunnerDispatchHandoffRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async record(envelope: ExecutionRequestedEnvelope): Promise<RunnerDispatchHandoffResult> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateEnvelope(envelope);

    const client = this.clientFactory(this.connectionString);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      await client.query("BEGIN");

      try {
        // The job row lock serializes first-time handoff creation for this job.
        // Queue fields are only hints; the joined PostgreSQL records are authoritative.
        const authoritative = await client.query<AuthoritativeExecutionRow>(
          [
            "SELECT ej.attempt_id, ej.state AS job_state,",
            "  eo.payload->>'attemptId' AS outbox_attempt_id,",
            "  eo.protocol_version AS outbox_protocol_version,",
            "  eo.correlation_id",
            "FROM execution_jobs AS ej",
            "INNER JOIN execution_outbox AS eo ON eo.execution_id = ej.id",
            "WHERE ej.id = $1::uuid",
            "  AND eo.event_type = 'EXECUTION_REQUESTED'",
            "  AND eo.payload->>'executionId' = ej.id::text",
            "FOR UPDATE OF ej",
          ].join("\n"),
          [envelope.executionId],
        );
        const current = authoritative.rows[0];
        if (!current ||
            current.attempt_id !== envelope.attemptId ||
            current.outbox_attempt_id !== envelope.attemptId ||
            current.outbox_protocol_version !== envelope.protocolVersion) {
          throw new InvalidRunnerDispatchEnvelopeError();
        }

        // A redelivery after the job has advanced is still safe to acknowledge
        // when its exact durable handoff already exists.
        const existing = await client.query<DispatchRow>(
          [
            "SELECT id, attempt_id, protocol_version, correlation_id",
            "FROM runner_dispatch_outbox",
            "WHERE execution_id = $1::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [envelope.executionId],
        );
        const prior = existing.rows[0];
        if (prior) {
          if (prior.attempt_id !== envelope.attemptId ||
              prior.protocol_version !== envelope.protocolVersion ||
              prior.correlation_id !== current.correlation_id) {
            throw new InvalidRunnerDispatchEnvelopeError();
          }
          await client.query("COMMIT");
          return { status: "DUPLICATE", dispatchId: prior.id };
        }

        // First-time handoff is accepted only for a job still waiting in intake.
        if (current.job_state !== "QUEUED") {
          throw new InvalidRunnerDispatchEnvelopeError();
        }

        const inserted = await client.query<DispatchRow>(
          [
            "INSERT INTO runner_dispatch_outbox",
            "  (execution_id, attempt_id, protocol_version, correlation_id)",
            "VALUES ($1::uuid, $2::uuid, $3, $4)",
            "RETURNING id, attempt_id, protocol_version, correlation_id",
          ].join("\n"),
          [
            envelope.executionId,
            envelope.attemptId,
            envelope.protocolVersion,
            current.correlation_id,
          ],
        );

        const created = inserted.rows[0];
        if (!created) throw new Error("runner_dispatch_insert_returned_no_id");
        await client.query("COMMIT");
        return { status: "RECORDED", dispatchId: created.id };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    } catch (error) {
      if (error instanceof InvalidRunnerDispatchEnvelopeError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }

  private validateEnvelope(envelope: ExecutionRequestedEnvelope): void {
    if (!envelope || typeof envelope !== "object" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(envelope.executionId) ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(envelope.attemptId) ||
        envelope.protocolVersion !== "v1" ||
        Object.keys(envelope).some((key) =>
          !["executionId", "attemptId", "protocolVersion"].includes(key))) {
      throw new InvalidRunnerDispatchEnvelopeError();
    }
  }
}

export class InvalidRunnerDispatchEnvelopeError extends Error {
  constructor() {
    super("invalid_runner_dispatch_envelope");
    this.name = "InvalidRunnerDispatchEnvelopeError";
  }
}
