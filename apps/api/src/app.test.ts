import { describe, expect, it, vi } from "vitest";
import { createApiHandler } from "./app";
import type {
  AuthenticationResult,
  Authenticator,
  ProblemDetails,
  ProblemRepository,
  ProblemSummary,
} from "./contracts";
import { DatabaseUnavailableError } from "./db/database-errors";

const allowedOrigin = "https://app.skyhigh.example";

const summary: ProblemSummary = {
  id: "two-sum",
  problemVersionId: "10000000-0000-4000-8000-000000000001",
  version: 1,
  title: "Two Sum",
  difficulty: "Easy",
  category: "Arrays & Hashing",
  tags: ["Array", "Hash Map"],
  summary: "Find two indices whose values add up to the target.",
};

const details: ProblemDetails = {
  ...summary,
  statement: "Given an integer array and a target, return the matching indices.",
  inputFormat: ["The first line contains n and target.", "The second line contains n integers."],
  outputFormat: "Print the two indices.",
  constraints: ["2 <= n <= 100000"],
  examples: [
    {
      id: 1,
      input: "4 9\n2 7 11 15",
      output: "0 1",
      explanation: "2 + 7 = 9.",
    },
  ],
};

const authenticated: AuthenticationResult = {
  authenticated: true,
  principal: {
    userId: "20000000-0000-4000-8000-000000000001",
    tenantId: "30000000-0000-4000-8000-000000000001",
    roles: ["student"],
  },
};

interface HarnessOptions {
  auth?: AuthenticationResult;
  repository?: Partial<ProblemRepository>;
}

function makeHarness(options: HarnessOptions = {}) {
  const auth = options.auth ?? authenticated;
  const authenticator: Authenticator = {
    authenticate: vi.fn(async (_request: Request) => auth),
  };

  const repository: ProblemRepository = {
    ping: vi.fn(async () => undefined),
    listPublished: vi.fn(async (_tenantId: string, _limit: number) => [summary]),
    getPublishedBySlug: vi.fn(async (_tenantId: string, _slug: string) => details),
    ...options.repository,
  };

  const handler = createApiHandler({
    authenticator,
    repository,
    allowedOrigins: allowedOrigin,
  });

  return { handler, authenticator, repository };
}

function makeRequest(path: string, init: RequestInit = {}): Request {
  return new Request(`https://api.skyhigh.example${path}`, init);
}

async function readJson<T>(response: Response): Promise<T> {
  return await response.json() as T;
}

describe("M1 API control plane", () => {
  it("serves liveness without requiring authentication or database access", async () => {
    const { handler, authenticator, repository } = makeHarness();

    const response = await handler(makeRequest("/healthz"));

    expect(response.status).toBe(200);
    expect(await readJson(response)).toEqual({
      status: "ok",
      service: "sky-high-coding-judge-api",
    });
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(authenticator.authenticate).not.toHaveBeenCalled();
    expect(repository.ping).not.toHaveBeenCalled();
  });

  it("reports readiness only after the database ping succeeds", async () => {
    const ping = vi.fn(async () => undefined);
    const { handler, authenticator } = makeHarness({ repository: { ping } });

    const response = await handler(makeRequest("/readyz"));

    expect(response.status).toBe(200);
    expect(await readJson(response)).toEqual({ status: "ready" });
    expect(ping).toHaveBeenCalledOnce();
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });

  it("returns a non-disclosing retryable readiness failure when the database is unavailable", async () => {
    const ping = vi.fn(async () => {
      throw new Error("postgres://secret-user:secret-password@db.internal");
    });
    const { handler, authenticator } = makeHarness({ repository: { ping } });

    const response = await handler(makeRequest("/readyz", {
      headers: { "X-Correlation-ID": "readiness-probe-17" },
    }));
    const body = await readJson<{
      error: { code: string; message: string; retryable: boolean };
      correlationId: string;
    }>(response);

    expect(response.status).toBe(503);
    expect(body).toEqual({
      error: {
        code: "DATABASE_NOT_READY",
        message: "The API database connection is not ready.",
        retryable: true,
      },
      correlationId: "readiness-probe-17",
    });
    expect(JSON.stringify(body)).not.toContain("secret-password");
    expect(response.headers.get("X-Correlation-ID")).toBe("readiness-probe-17");
    expect(ping).toHaveBeenCalledOnce();
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });

  it("reflects only an explicitly allowed origin and preserves a valid correlation ID", async () => {
    const { handler } = makeHarness();

    const response = await handler(makeRequest("/healthz", {
      headers: {
        Origin: allowedOrigin,
        "X-Correlation-ID": "student-session:request-42",
      },
    }));

    expect(response.status).toBe(200);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(allowedOrigin);
    expect(response.headers.get("Vary")).toContain("Origin");
    expect(response.headers.get("X-Correlation-ID")).toBe("student-session:request-42");
  });

  it("rejects an untrusted origin before route handling", async () => {
    const { handler, authenticator } = makeHarness();

    const response = await handler(makeRequest("/healthz", {
      headers: { Origin: "https://unexpected.example" },
    }));

    expect(response.status).toBe(403);
    expect(await readJson(response)).toMatchObject({
      error: { code: "ORIGIN_NOT_ALLOWED", retryable: false },
    });
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });

  it("answers an allowed CORS preflight without authenticating", async () => {
    const { handler, authenticator } = makeHarness();

    const response = await handler(makeRequest("/api/v1/problems", {
      method: "OPTIONS",
      headers: { Origin: allowedOrigin },
    }));

    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Methods")).toBe("GET, OPTIONS");
    expect(response.headers.get("Access-Control-Allow-Headers")).toContain("Authorization");
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });

  it("fails closed while the Sky High identity provider is not configured", async () => {
    const { handler, repository } = makeHarness({
      auth: { authenticated: false, reason: "provider_unavailable" },
    });

    const response = await handler(makeRequest("/api/v1/problems"));

    expect(response.status).toBe(503);
    expect(await readJson(response)).toMatchObject({
      error: { code: "AUTH_PROVIDER_NOT_CONFIGURED", retryable: false },
    });
    expect(repository.listPublished).not.toHaveBeenCalled();
  });

  it("rejects a request with no valid session", async () => {
    const { handler, repository } = makeHarness({
      auth: { authenticated: false, reason: "missing" },
    });

    const response = await handler(makeRequest("/api/v1/problems"));

    expect(response.status).toBe(401);
    expect(await readJson(response)).toMatchObject({
      error: { code: "UNAUTHENTICATED", retryable: false },
    });
    expect(repository.listPublished).not.toHaveBeenCalled();
  });

  it("lists published problems using the authenticated tenant and bounded limit", async () => {
    const listPublished = vi.fn(async (_tenantId: string, _limit: number) => [summary]);
    const { handler } = makeHarness({ repository: { listPublished } });

    const response = await handler(makeRequest("/api/v1/problems?limit=12"));

    expect(response.status).toBe(200);
    expect(await readJson(response)).toEqual({
      data: [summary],
      meta: { count: 1, limit: 12 },
    });
    expect(listPublished).toHaveBeenCalledWith(authenticated.principal.tenantId, 12);
  });

  it.each(["0", "-1", "51", "2.5", "many"])(
    "rejects an invalid problem-list limit: %s",
    async (limit) => {
      const listPublished = vi.fn(async (_tenantId: string, _limit: number) => [summary]);
      const { handler } = makeHarness({ repository: { listPublished } });

      const response = await handler(makeRequest(`/api/v1/problems?limit=${limit}`));

      expect(response.status).toBe(400);
      expect(await readJson(response)).toMatchObject({
        error: { code: "INVALID_LIMIT", retryable: false },
      });
      expect(listPublished).not.toHaveBeenCalled();
    },
  );

  it("returns published problem details by validated slug", async () => {
    const getPublishedBySlug = vi.fn(async (_tenantId: string, _slug: string) => details);
    const { handler } = makeHarness({ repository: { getPublishedBySlug } });

    const response = await handler(makeRequest("/api/v1/problems/two-sum"));

    expect(response.status).toBe(200);
    expect(await readJson(response)).toEqual({ data: details });
    expect(getPublishedBySlug).toHaveBeenCalledWith(authenticated.principal.tenantId, "two-sum");
  });

  it("rejects an invalid problem slug before repository access", async () => {
    const getPublishedBySlug = vi.fn(async (_tenantId: string, _slug: string) => details);
    const { handler } = makeHarness({ repository: { getPublishedBySlug } });

    const response = await handler(makeRequest("/api/v1/problems/Two%20Sum"));

    expect(response.status).toBe(400);
    expect(await readJson(response)).toMatchObject({
      error: { code: "INVALID_PROBLEM_ID", retryable: false },
    });
    expect(getPublishedBySlug).not.toHaveBeenCalled();
  });

  it("returns a non-disclosing 404 for an unpublished or missing problem", async () => {
    const getPublishedBySlug = vi.fn(async (_tenantId: string, _slug: string) => null);
    const { handler } = makeHarness({ repository: { getPublishedBySlug } });

    const response = await handler(makeRequest("/api/v1/problems/not-published"));

    expect(response.status).toBe(404);
    expect(await readJson(response)).toMatchObject({
      error: { code: "PROBLEM_NOT_FOUND", retryable: false },
    });
  });

  it("maps database outages to a retryable 503 without exposing driver details", async () => {
    const listPublished = vi.fn(async (_tenantId: string, _limit: number) => {
      throw new DatabaseUnavailableError();
    });
    const { handler } = makeHarness({ repository: { listPublished } });

    const response = await handler(makeRequest("/api/v1/problems"));

    const body = await readJson<{
      error: { code: string; message: string; retryable: boolean };
    }>(response);
    expect(response.status).toBe(503);
    expect(body.error).toEqual({
      code: "DATABASE_UNAVAILABLE",
      message: "The problem catalog is temporarily unavailable.",
      retryable: true,
    });
    expect(JSON.stringify(body)).not.toContain("postgres://");
  });

  it("does not expose unexpected repository error details", async () => {
    const listPublished = vi.fn(async (_tenantId: string, _limit: number) => {
      throw new Error("postgres://secret-user:secret-password@db.internal");
    });
    const { handler } = makeHarness({ repository: { listPublished } });

    const response = await handler(makeRequest("/api/v1/problems"));

    const body = await readJson(response);
    expect(response.status).toBe(500);
    expect(JSON.stringify(body)).not.toContain("secret-password");
    expect(body).toMatchObject({
      error: { code: "INTERNAL_ERROR", retryable: true },
    });
  });

  it("returns 404 for unknown routes", async () => {
    const { handler, authenticator } = makeHarness();

    const response = await handler(makeRequest("/api/v1/unknown"));

    expect(response.status).toBe(404);
    expect(await readJson(response)).toMatchObject({
      error: { code: "NOT_FOUND", retryable: false },
    });
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });
});
