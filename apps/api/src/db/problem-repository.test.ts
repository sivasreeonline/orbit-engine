import { describe, expect, it } from "vitest";
import { DatabaseUnavailableError } from "./database-errors";
import { PostgresProblemRepository } from "./problem-repository";

interface QueryCall {
  readonly text: string;
  readonly values: unknown[] | undefined;
}

interface FakeClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: T[] }>;
  end(): Promise<void>;
}

function makeFakeClient(resultSets: Record<string, unknown>[][] = []) {
  const calls: QueryCall[] = [];
  let connected = false;
  let ended = false;
  let failOnQuery = false;

  const client: FakeClient = {
    async connect() {
      connected = true;
    },
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      if (failOnQuery && text !== "SET statement_timeout = '5s'") {
        throw new Error("sensitive PostgreSQL driver detail");
      }
      const rows = resultSets.shift() ?? [];
      return { rows: rows as T[] };
    },
    async end() {
      ended = true;
    },
  };

  return {
    client,
    calls,
    isConnected: () => connected,
    isEnded: () => ended,
    failQueries() {
      failOnQuery = true;
    },
  };
}

const tenantId = "30000000-0000-4000-8000-000000000001";
const connection = "postgres://test-user:test-password@localhost/test";

const summaryRow = {
  slug: "two-sum",
  problem_version_id: "10000000-0000-4000-8000-000000000001",
  version_number: 1,
  title: "Two Sum",
  difficulty: "Easy" as const,
  category: "Arrays & Hashing",
  tags: ["Array", "Hash Map"],
  summary: "Find two indices.",
};

describe("PostgresProblemRepository", () => {
  it("uses parameterized tenant-scoped SQL and maps published problem summaries", async () => {
    const fake = makeFakeClient([[], [summaryRow]]);
    const repository = new PostgresProblemRepository(
      { HYPERDRIVE: { connectionString: connection } },
      () => fake.client,
    );

    const problems = await repository.listPublished(tenantId, 15);

    expect(problems).toEqual([{
      id: "two-sum",
      problemVersionId: summaryRow.problem_version_id,
      version: 1,
      title: "Two Sum",
      difficulty: "Easy",
      category: "Arrays & Hashing",
      tags: ["Array", "Hash Map"],
      summary: "Find two indices.",
    }]);
    const listQuery = fake.calls[1];
    expect(listQuery?.text).toContain("FROM problems AS p");
    expect(listQuery?.text).toContain("\nWHERE p.lifecycle_status = 'PUBLISHED'");
    expect(listQuery?.text).toContain("AND (p.tenant_id IS NULL OR p.tenant_id = $1::uuid)");
    expect(listQuery?.text).not.toContain("\\n");
    expect(listQuery?.values).toEqual([tenantId, 15]);
    expect(fake.isConnected()).toBe(true);
    expect(fake.isEnded()).toBe(true);
  });

  it("loads public examples only and never selects hidden test contents", async () => {
    const problemRow = {
      ...summaryRow,
      statement: "Find two indices.",
      input_format: ["n target", "array values"],
      output_format: "Two indices.",
      constraints: ["2 <= n <= 100000"],
    };
    const publicExample = {
      sequence: 1,
      input: "4 9\n2 7 11 15",
      output: "0 1",
      explanation: "2 + 7 = 9.",
    };
    const fake = makeFakeClient([[], [problemRow], [publicExample]]);
    const repository = new PostgresProblemRepository(
      { HYPERDRIVE: { connectionString: connection } },
      () => fake.client,
    );

    const problem = await repository.getPublishedBySlug(tenantId, "two-sum");

    expect(problem?.examples).toEqual([{
      id: 1,
      input: publicExample.input,
      output: publicExample.output,
      explanation: publicExample.explanation,
    }]);
    const testCaseQuery = fake.calls[2]?.text ?? "";
    expect(testCaseQuery).toContain("FROM public_problem_test_cases");
    expect(testCaseQuery).toContain("LIMIT 10");
    expect(testCaseQuery).not.toContain("FROM problem_test_cases");
    expect(testCaseQuery).not.toContain("hidden_test_cases");
    const detailQuery = fake.calls[1]?.text ?? "";
    expect(detailQuery).toContain("p.slug = $1");
    expect(detailQuery).toContain("AND (p.tenant_id IS NULL OR p.tenant_id = $2::uuid)");
    expect(detailQuery).not.toContain("two-sum");
    expect(fake.calls[1]?.values).toEqual(["two-sum", tenantId]);
  });

  it("fails closed when Hyperdrive is not configured", async () => {
    const repository = new PostgresProblemRepository({});

    await expect(repository.ping()).rejects.toBeInstanceOf(DatabaseUnavailableError);
  });

  it("maps query failures to a generic database error and always closes the client", async () => {
    const fake = makeFakeClient([[]]);
    fake.failQueries();
    const repository = new PostgresProblemRepository(
      { HYPERDRIVE: { connectionString: connection } },
      () => fake.client,
    );

    await expect(repository.ping()).rejects.toBeInstanceOf(DatabaseUnavailableError);
    expect(fake.isEnded()).toBe(true);
  });
});
