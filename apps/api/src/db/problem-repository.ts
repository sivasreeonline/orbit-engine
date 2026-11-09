import { Client } from "pg";
import type {
  Difficulty,
  ProblemDetails,
  ProblemExample,
  ProblemRepository,
  ProblemSummary,
} from "../contracts";
import type { Env } from "../env";
import { DatabaseUnavailableError } from "./database-errors";

interface SummaryRow extends Record<string, unknown> {
  slug: string;
  problem_version_id: string;
  version_number: number;
  title: string;
  difficulty: Difficulty;
  category: string;
  tags: string[] | null;
  summary: string;
}

interface DetailsRow extends SummaryRow {
  statement: string;
  input_format: string[];
  output_format: string;
  constraints: string[];
}

interface ExampleRow extends Record<string, unknown> {
  sequence: number;
  input: string;
  output: string;
  explanation: string | null;
}

interface PgClientLike {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: T[] }>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgClientLike;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-coding-judge-api",
  }) as unknown as PgClientLike;

const listPublishedSql = [
  "SELECT",
  "  p.slug,",
  "  pv.id AS problem_version_id,",
  "  pv.version_number,",
  "  pv.title,",
  "  pv.difficulty,",
  "  pv.category,",
  "  pv.tags,",
  "  pv.summary",
  "FROM problems AS p",
  "INNER JOIN problem_versions AS pv ON pv.id = p.current_version_id",
  "WHERE p.lifecycle_status = 'PUBLISHED'",
  "  AND (p.tenant_id IS NULL OR p.tenant_id = $1::uuid)",
  "  AND pv.published_at IS NOT NULL",
  "ORDER BY p.sort_order ASC, p.slug ASC",
  "LIMIT $2",
].join("\n");

const getPublishedBySlugSql = [
  "SELECT",
  "  p.slug,",
  "  pv.id AS problem_version_id,",
  "  pv.version_number,",
  "  pv.title,",
  "  pv.difficulty,",
  "  pv.category,",
  "  pv.tags,",
  "  pv.summary,",
  "  pv.statement,",
  "  pv.input_format,",
  "  pv.output_format,",
  "  pv.constraints",
  "FROM problems AS p",
  "INNER JOIN problem_versions AS pv ON pv.id = p.current_version_id",
  "WHERE p.slug = $1",
  "  AND p.lifecycle_status = 'PUBLISHED'",
  "  AND (p.tenant_id IS NULL OR p.tenant_id = $2::uuid)",
  "  AND pv.published_at IS NOT NULL",
  "LIMIT 1",
].join("\n");

const publicExamplesSql = [
  "SELECT",
  "  sequence,",
  "  convert_from(input_data, 'UTF8') AS input,",
  "  convert_from(expected_output, 'UTF8') AS output,",
  "  explanation",
  "FROM public_problem_test_cases",
  "WHERE problem_version_id = $1::uuid",
  "ORDER BY sequence ASC",
  "LIMIT 10",
].join("\n");

function mapSummary(row: SummaryRow): ProblemSummary {
  return {
    id: row.slug,
    problemVersionId: row.problem_version_id,
    version: row.version_number,
    title: row.title,
    difficulty: row.difficulty,
    category: row.category,
    tags: row.tags ?? [],
    summary: row.summary,
  };
}

export class PostgresProblemRepository implements ProblemRepository {
  constructor(
    private readonly env: Env,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async ping(): Promise<void> {
    await this.withClient(async (client) => {
      await client.query("SELECT 1");
    });
  }

  async listPublished(tenantId: string, limit: number): Promise<readonly ProblemSummary[]> {
    return this.withClient(async (client) => {
      const result = await client.query<SummaryRow>(
        listPublishedSql,
        [tenantId, limit],
      );
      return result.rows.map(mapSummary);
    });
  }

  async getPublishedBySlug(
    tenantId: string,
    slug: string,
  ): Promise<ProblemDetails | null> {
    return this.withClient(async (client) => {
      const problemResult = await client.query<DetailsRow>(
        getPublishedBySlugSql,
        [slug, tenantId],
      );
      const problem = problemResult.rows[0];
      if (!problem) return null;

      // Public examples only. Hidden test input/expected output is never selected.
      const exampleResult = await client.query<ExampleRow>(
        publicExamplesSql,
        [problem.problem_version_id],
      );

      const examples: ProblemExample[] = exampleResult.rows.map((row) => ({
        id: row.sequence,
        input: row.input,
        output: row.output,
        explanation: row.explanation,
      }));

      return {
        ...mapSummary(problem),
        statement: problem.statement,
        inputFormat: problem.input_format,
        outputFormat: problem.output_format,
        constraints: problem.constraints,
        examples,
      };
    });
  }

  private async withClient<T>(operation: (client: PgClientLike) => Promise<T>): Promise<T> {
    const connectionString = this.env.HYPERDRIVE?.connectionString;
    if (!connectionString) throw new DatabaseUnavailableError();

    const client = this.clientFactory(connectionString);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      return await operation(client);
    } catch {
      // Do not expose connection strings, SQL, driver diagnostics or row data.
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
