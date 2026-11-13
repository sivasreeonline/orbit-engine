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
import type { ActiveRunnerPublicKey } from "./db/runner-identity-repository";
import type { RunnerDispatchLease } from "./db/runner-dispatch-lease-repository";
import type {
  RecordRunnerAcceptanceInput,
  RecordedRunnerAcceptance,
} from "./db/runner-acceptance-repository";
import {
  RunnerStartNotAcceptedError,
} from "./db/runner-start-repository";
import type {
  RecordRunnerStartInput,
  RecordedRunnerStart,
} from "./db/runner-start-repository";
import {
  RunnerHeartbeatNotStartedError,
} from "./db/runner-heartbeat-repository";
import type {
  RecordRunnerHeartbeatInput,
  RecordedRunnerHeartbeat,
} from "./db/runner-heartbeat-repository";
import {
  RunnerArtifactNotStartedError,
} from "./db/runner-artifact-repository";
import type {
  FetchRunnerArtifactInput,
  RunnerExecutionArtifact,
} from "./db/runner-artifact-repository";
import { canonicalRunnerRequestMessage } from "./security/runner-request-signature";
import { RUNNER_AUTH_HEADERS } from "./services/runner-request-authenticator";
import type { PostgresExecutionEvidenceRepository } from "./db/execution-evidence-repository";
import type { CreateExecutionInput } from "./db/execution-intake-repository";

type ExecutionEvidenceReadRepository = Pick<
  PostgresExecutionEvidenceRepository,
  "listProblemAttemptHistory" | "listExecutionEvents"
> & Partial<Pick<PostgresExecutionEvidenceRepository, "getExecutionQueueStatus">>;

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
  evidenceRepository?: ExecutionEvidenceReadRepository;
  executionIntakeRepository?: {
    create(input: CreateExecutionInput, idempotencyKey: string): Promise<{
      executionId: string; attemptId: string; replayed: boolean;
    }>;
  };
  runtimeVersions?: { readonly java: string; readonly python: string };
  runnerIdentityRepository?: {
    findActivePublicKey(keyId: string, now: Date): Promise<ActiveRunnerPublicKey | null>;
    consumeNonce(keyId: string, nonce: string, now: Date, expiresAt: Date): Promise<boolean>;
  };
  runnerDispatchLeaseRepository?: {
    claimFairBatchForRunner(
      runnerId: string, requestedSlots: number, maxActiveLeases: number, leaseSeconds: number,
    ): Promise<RunnerDispatchLease[]>;
  };
  runnerAcceptanceRepository?: {
    record(input: RecordRunnerAcceptanceInput): Promise<RecordedRunnerAcceptance>;
  };
  runnerStartRepository?: {
    start(input: RecordRunnerStartInput): Promise<RecordedRunnerStart>;
  };
  runnerHeartbeatRepository?: {
    renew(input: RecordRunnerHeartbeatInput): Promise<RecordedRunnerHeartbeat>;
  };
  runnerArtifactRepository?: {
    fetch(input: FetchRunnerArtifactInput): Promise<RunnerExecutionArtifact>;
  };
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
    ...(options.evidenceRepository
      ? { evidenceRepository: options.evidenceRepository }
      : {}),
    ...(options.executionIntakeRepository
      ? { executionIntakeRepository: options.executionIntakeRepository }
      : {}),
    ...(options.runtimeVersions ? { runtimeVersions: options.runtimeVersions } : {}),
    ...(options.runnerIdentityRepository
      ? { runnerIdentityRepository: options.runnerIdentityRepository }
      : {}),
    ...(options.runnerDispatchLeaseRepository
      ? { runnerDispatchLeaseRepository: options.runnerDispatchLeaseRepository }
      : {}),
    ...(options.runnerAcceptanceRepository
      ? { runnerAcceptanceRepository: options.runnerAcceptanceRepository }
      : {}),
    ...(options.runnerStartRepository
      ? { runnerStartRepository: options.runnerStartRepository }
      : {}),
    ...(options.runnerHeartbeatRepository
      ? { runnerHeartbeatRepository: options.runnerHeartbeatRepository }
      : {}),
    ...(options.runnerArtifactRepository
      ? { runnerArtifactRepository: options.runnerArtifactRepository }
      : {}),
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
    expect(response.headers.get("Access-Control-Allow-Methods")).toBe("GET, POST, OPTIONS");
    expect(response.headers.get("Access-Control-Allow-Headers")).toContain("Authorization");
    expect(response.headers.get("Access-Control-Allow-Headers")).toContain("Idempotency-Key");
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

  it("accepts an authenticated Run request with server-selected runtime and durable idempotency", async () => {
    const create = vi.fn(async (_input: CreateExecutionInput, _key: string) => ({
      executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
      attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      replayed: false,
    }));
    const { handler } = makeHarness({
      executionIntakeRepository: { create },
      runtimeVersions: { java: "25", python: "3.14" },
    });

    const response = await handler(makeRequest("/api/v1/executions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "student-run-001",
        "X-Correlation-ID": "run-request-001",
      },
      body: JSON.stringify({
        action: "RUN",
        problemSlug: "two-sum",
        language: "java",
        sourceCode: "public class Main {}",
      }),
    }));

    expect(response.status).toBe(202);
    expect(await readJson(response)).toEqual({
      data: {
        executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
        attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
        action: "RUN",
        accepted: true,
        replayed: false,
        statusUrl: "/api/v1/executions/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1/status",
      },
    });
    expect(create).toHaveBeenCalledWith({
      principal: authenticated.principal,
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main {}",
      correlationId: "run-request-001",
    }, "student-run-001");
  });

  it("rejects client-supplied identity or runtime fields instead of trusting them", async () => {
    const create = vi.fn(async () => ({
      executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
      attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      replayed: false,
    }));
    const { handler } = makeHarness({
      executionIntakeRepository: { create },
      runtimeVersions: { java: "25", python: "3.14" },
    });

    const response = await handler(makeRequest("/api/v1/executions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "student-run-002",
      },
      body: JSON.stringify({
        action: "RUN",
        problemSlug: "two-sum",
        language: "java",
        runtimeVersion: "attacker-selected",
        tenantId: "ffffffff-ffff-4fff-8fff-ffffffffffff",
        sourceCode: "public class Main {}",
      }),
    }));

    expect(response.status).toBe(400);
    expect(await readJson(response)).toMatchObject({
      error: { code: "INVALID_EXECUTION_REQUEST", retryable: false },
    });
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects non-JSON media types before reading the request body", async () => {
    const create = vi.fn(async () => ({
      executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
      attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      replayed: false,
    }));
    const { handler } = makeHarness({
      executionIntakeRepository: { create },
      runtimeVersions: { java: "25", python: "3.14" },
    });

    const response = await handler(makeRequest("/api/v1/executions", {
      method: "POST",
      headers: {
        "Content-Type": "application/jsonp",
        "Idempotency-Key": "student-run-004",
      },
      body: "{}",
    }));

    expect(response.status).toBe(415);
    expect(await readJson(response)).toMatchObject({
      error: { code: "UNSUPPORTED_MEDIA_TYPE", retryable: false },
    });
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects source larger than 200 KiB before writing an execution attempt", async () => {
    const create = vi.fn(async () => ({
      executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
      attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      replayed: false,
    }));
    const { handler } = makeHarness({
      executionIntakeRepository: { create },
      runtimeVersions: { java: "25", python: "3.14" },
    });

    const response = await handler(makeRequest("/api/v1/executions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "student-run-003",
      },
      body: JSON.stringify({
        action: "RUN",
        problemSlug: "two-sum",
        language: "java",
        sourceCode: "x".repeat(200 * 1024 + 1),
      }),
    }));

    expect(response.status).toBe(413);
    expect(await readJson(response)).toMatchObject({
      error: { code: "SOURCE_TOO_LARGE", retryable: false },
    });
    expect(create).not.toHaveBeenCalled();
  });

  it("returns attempt history only for the authenticated tenant and student", async () => {
    const listProblemAttemptHistory = vi.fn(async (
      _tenantId: string,
      _actorUserId: string,
      _problemSlug: string,
      _limit?: number,
    ) => []);
    const listExecutionEvents = vi.fn(async (
      _tenantId: string,
      _actorUserId: string,
      _executionId: string,
    ) => []);
    const { handler } = makeHarness({
      evidenceRepository: { listProblemAttemptHistory, listExecutionEvents },
    });

    const response = await handler(makeRequest(
      "/api/v1/problems/two-sum/attempts?limit=7",
    ));

    expect(response.status).toBe(200);
    expect(await readJson(response)).toEqual({ data: [], meta: { count: 0, limit: 7 } });
    expect(listProblemAttemptHistory).toHaveBeenCalledWith(
      authenticated.principal.tenantId,
      authenticated.principal.userId,
      "two-sum",
      7,
    );
  });

  it("rejects invalid attempt-history limits before querying evidence", async () => {
    const listProblemAttemptHistory = vi.fn(async (
      _tenantId: string,
      _actorUserId: string,
      _problemSlug: string,
      _limit?: number,
    ) => []);
    const listExecutionEvents = vi.fn(async (
      _tenantId: string,
      _actorUserId: string,
      _executionId: string,
    ) => []);
    const { handler } = makeHarness({
      evidenceRepository: { listProblemAttemptHistory, listExecutionEvents },
    });

    const response = await handler(makeRequest(
      "/api/v1/problems/two-sum/attempts?limit=101",
    ));

    expect(response.status).toBe(400);
    expect(await readJson(response)).toMatchObject({
      error: { code: "INVALID_LIMIT", retryable: false },
    });
    expect(listProblemAttemptHistory).not.toHaveBeenCalled();
  });

  it("returns safe execution queue status only for the authenticated student", async () => {
    const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
    const getExecutionQueueStatus = vi.fn(async (
      _tenantId: string,
      _actorUserId: string,
      _executionId: string,
    ) => ({
      executionId,
      attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      action: "RUN" as const,
      executionState: "QUEUED",
      dispatchState: "PENDING" as const,
      submittedAt: "2026-11-13T01:00:00.000Z",
      updatedAt: "2026-11-13T01:00:00.000Z",
    }));
    const listProblemAttemptHistory = vi.fn(async (
      _tenantId: string, _actorUserId: string, _problemSlug: string, _limit?: number,
    ) => []);
    const listExecutionEvents = vi.fn(async (
      _tenantId: string, _actorUserId: string, _executionId: string,
    ) => []);
    const { handler } = makeHarness({
      evidenceRepository: {
        listProblemAttemptHistory, listExecutionEvents, getExecutionQueueStatus,
      },
    });

    const response = await handler(makeRequest(
      `/api/v1/executions/${executionId}/status`,
    ));

    expect(response.status).toBe(200);
    expect(await readJson(response)).toEqual({
      data: {
        executionId,
        attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
        action: "RUN",
        executionState: "QUEUED",
        dispatchState: "PENDING",
        submittedAt: "2026-11-13T01:00:00.000Z",
        updatedAt: "2026-11-13T01:00:00.000Z",
      },
    });
    expect(getExecutionQueueStatus).toHaveBeenCalledWith(
      authenticated.principal.tenantId,
      authenticated.principal.userId,
      executionId,
    );
  });

  it("does not reveal whether an execution belongs to another student", async () => {
    const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
    const getExecutionQueueStatus = vi.fn(async () => null);
    const listProblemAttemptHistory = vi.fn(async (
      _tenantId: string, _actorUserId: string, _problemSlug: string, _limit?: number,
    ) => []);
    const listExecutionEvents = vi.fn(async (
      _tenantId: string, _actorUserId: string, _executionId: string,
    ) => []);
    const { handler } = makeHarness({
      evidenceRepository: {
        listProblemAttemptHistory, listExecutionEvents, getExecutionQueueStatus,
      },
    });

    const response = await handler(makeRequest(
      `/api/v1/executions/${executionId}/status`,
    ));

    expect(response.status).toBe(404);
    expect(await readJson(response)).toMatchObject({
      error: { code: "EXECUTION_NOT_FOUND", retryable: false },
    });
  });

  it("returns timeline events scoped to the authenticated student", async () => {
    const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
    const listProblemAttemptHistory = vi.fn(async (
      _tenantId: string,
      _actorUserId: string,
      _problemSlug: string,
      _limit?: number,
    ) => []);
    const listExecutionEvents = vi.fn(async (
      _tenantId: string,
      _actorUserId: string,
      _executionId: string,
    ) => []);
    const { handler } = makeHarness({
      evidenceRepository: { listProblemAttemptHistory, listExecutionEvents },
    });

    const response = await handler(makeRequest(
      `/api/v1/executions/${executionId}/events`,
    ));

    expect(response.status).toBe(200);
    expect(await readJson(response)).toEqual({ data: [], meta: { count: 0 } });
    expect(listExecutionEvents).toHaveBeenCalledWith(
      authenticated.principal.tenantId,
      authenticated.principal.userId,
      executionId,
    );
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


describe("authenticated runner claim endpoint", () => {
  const runnerId = "40000000-0000-4000-8000-000000000001";
  const dispatch: RunnerDispatchLease = {
    id: "50000000-0000-4000-8000-000000000001",
    executionId: "60000000-0000-4000-8000-000000000001",
    attemptId: "70000000-0000-4000-8000-000000000001",
    protocolVersion: "v1",
    correlationId: "test-runner-claim",
    deliveryAttempts: 1,
    leaseToken: "80000000-0000-4000-8000-000000000001",
    leaseExpiresAt: "2026-11-13T08:16:00.000Z",
  };

  function encodeBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/g, "");
  }

  async function signedClaimRequest(requestedSlots: number): Promise<{
    request: Request;
    publicKey: Uint8Array;
    nonce: string;
    now: Date;
  }> {
    const now = new Date();
    const timestamp = String(Math.floor(now.getTime() / 1000));
    const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
    const nonce = encodeBase64Url(nonceBytes);
    const bodyText = JSON.stringify({ requestedSlots });
    const body = new TextEncoder().encode(bodyText);
    const keyPair = await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    ) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const signedMessage = await canonicalRunnerRequestMessage({
      keyId: "runner-test-key",
      method: "POST",
      path: "/internal/v1/runner/claim",
      timestamp,
      nonce,
      body,
    });
    const signingBytes = new Uint8Array(signedMessage);
    const signature = new Uint8Array(await crypto.subtle.sign(
      "Ed25519", keyPair.privateKey, signingBytes,
    ));
    return {
      request: new Request("https://api.skyhigh.example/internal/v1/runner/claim", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [RUNNER_AUTH_HEADERS.keyId]: "runner-test-key",
          [RUNNER_AUTH_HEADERS.timestamp]: timestamp,
          [RUNNER_AUTH_HEADERS.nonce]: nonce,
          [RUNNER_AUTH_HEADERS.signature]: encodeBase64Url(signature),
        },
        body: bodyText,
      }),
      publicKey,
      nonce,
      now,
    };
  }

  it("authenticates the machine and claims only within the configured active lease cap", async () => {
    const signed = await signedClaimRequest(4);
    const findActivePublicKey = vi.fn(async () => ({
      keyId: "runner-test-key",
      runnerId,
      publicKey: signed.publicKey,
    }));
    const consumeNonce = vi.fn(async () => true);
    const claimFairBatchForRunner = vi.fn(async () => [dispatch]);
    const { handler, authenticator } = makeHarness({
      runnerIdentityRepository: { findActivePublicKey, consumeNonce },
      runnerDispatchLeaseRepository: { claimFairBatchForRunner },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(200);
    expect(await readJson(response)).toMatchObject({
      data: [{
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
      }],
      meta: {
        claimed: 1,
        maxActiveLeasesPerRunner: 2,
        leaseDurationSeconds: 120,
      },
    });
    expect(authenticator.authenticate).not.toHaveBeenCalled();
    expect(findActivePublicKey).toHaveBeenCalledWith("runner-test-key", expect.any(Date));
    expect(consumeNonce).toHaveBeenCalledOnce();
    expect(claimFairBatchForRunner).toHaveBeenCalledWith(runnerId, 2, 2, 120);
  });

  it("rejects a replayed nonce before dispatch claim", async () => {
    const signed = await signedClaimRequest(1);
    const claimFairBatchForRunner = vi.fn(async () => [dispatch]);
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey: vi.fn(async () => ({
          keyId: "runner-test-key", runnerId, publicKey: signed.publicKey,
        })),
        consumeNonce: vi.fn(async () => false),
      },
      runnerDispatchLeaseRepository: { claimFairBatchForRunner },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(401);
    expect(await readJson(response)).toMatchObject({
      error: { code: "RUNNER_AUTHENTICATION_FAILED" },
    });
    expect(claimFairBatchForRunner).not.toHaveBeenCalled();
  });

  it("rejects malformed claim capacity before key lookup", async () => {
    const findActivePublicKey = vi.fn(async () => null);
    const claimFairBatchForRunner = vi.fn(async () => []);
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey,
        consumeNonce: vi.fn(async () => true),
      },
      runnerDispatchLeaseRepository: { claimFairBatchForRunner },
    });

    const response = await handler(makeRequest("/internal/v1/runner/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ requestedSlots: 99 }),
    }));

    expect(response.status).toBe(400);
    expect(findActivePublicKey).not.toHaveBeenCalled();
    expect(claimFairBatchForRunner).not.toHaveBeenCalled();
  });
});

describe("authenticated runner acceptance endpoint", () => {
  const runnerId = "40000000-0000-4000-8000-000000000001";
  const receipt = {
    acceptanceId: "90000000-0000-4000-8000-000000000001",
    dispatchId: "50000000-0000-4000-8000-000000000001",
    executionId: "60000000-0000-4000-8000-000000000001",
    attemptId: "70000000-0000-4000-8000-000000000001",
    leaseToken: "80000000-0000-4000-8000-000000000001",
  };

  function encodeBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/g, "");
  }

  async function signedAcceptanceRequest(bodyValue: Record<string, string>) {
    const now = new Date();
    const timestamp = String(Math.floor(now.getTime() / 1000));
    const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const bodyText = JSON.stringify(bodyValue);
    const body = new TextEncoder().encode(bodyText);
    const keyPair = await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    ) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const message = await canonicalRunnerRequestMessage({
      keyId: "runner-accept-key",
      method: "POST",
      path: "/internal/v1/runner/accept",
      timestamp,
      nonce,
      body,
    });
    const signature = new Uint8Array(await crypto.subtle.sign(
      "Ed25519", keyPair.privateKey, new Uint8Array(message),
    ));
    return {
      request: new Request("https://api.skyhigh.example/internal/v1/runner/accept", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [RUNNER_AUTH_HEADERS.keyId]: "runner-accept-key",
          [RUNNER_AUTH_HEADERS.timestamp]: timestamp,
          [RUNNER_AUTH_HEADERS.nonce]: nonce,
          [RUNNER_AUTH_HEADERS.signature]: encodeBase64Url(signature),
        },
        body: bodyText,
      }),
      publicKey,
    };
  }

  it("persists a signed acceptance receipt and returns its durable event", async () => {
    const signed = await signedAcceptanceRequest(receipt);
    const record = vi.fn(async (input: RecordRunnerAcceptanceInput) => ({
      dispatchId: input.dispatchId,
      acceptanceId: input.acceptanceId,
      eventId: "a0000000-0000-4000-8000-000000000001",
      acceptedAt: "2026-11-13T08:00:00.000Z",
      replayed: false,
    }));
    const { handler, authenticator } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey: vi.fn(async () => ({
          keyId: "runner-accept-key", runnerId, publicKey: signed.publicKey,
        })),
        consumeNonce: vi.fn(async () => true),
      },
      runnerAcceptanceRepository: { record },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(200);
    expect(await readJson(response)).toMatchObject({
      data: {
        accepted: true,
        replayed: false,
        dispatchId: receipt.dispatchId,
        acceptanceId: receipt.acceptanceId,
        eventId: "a0000000-0000-4000-8000-000000000001",
      },
    });
    expect(authenticator.authenticate).not.toHaveBeenCalled();
    expect(record).toHaveBeenCalledWith(expect.objectContaining({
      ...receipt,
      runnerId,
      keyId: "runner-accept-key",
      receiptSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
    }));
  });

  it("rejects additional acceptance fields before key lookup", async () => {
    const findActivePublicKey = vi.fn(async () => null);
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey,
        consumeNonce: vi.fn(async () => true),
      },
      runnerAcceptanceRepository: {
        record: vi.fn(async () => {
          throw new Error("should_not_be_called");
        }),
      },
    });
    const response = await handler(makeRequest("/internal/v1/runner/accept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...receipt, sourceCode: "must never be accepted" }),
    }));

    expect(response.status).toBe(400);
    expect(findActivePublicKey).not.toHaveBeenCalled();
  });
});


describe("authenticated runner start endpoint", () => {
  const runnerId = "40000000-0000-4000-8000-000000000001";
  const startReceipt = {
    dispatchId: "50000000-0000-4000-8000-000000000001",
    executionId: "60000000-0000-4000-8000-000000000001",
    attemptId: "70000000-0000-4000-8000-000000000001",
    leaseToken: "80000000-0000-4000-8000-000000000001",
  };

  function encodeBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/g, "");
  }

  async function signedStartRequest(bodyValue: Record<string, string>) {
    const now = new Date();
    const timestamp = String(Math.floor(now.getTime() / 1000));
    const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const bodyText = JSON.stringify(bodyValue);
    const body = new TextEncoder().encode(bodyText);
    const keyPair = await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    ) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const message = await canonicalRunnerRequestMessage({
      keyId: "runner-start-key",
      method: "POST",
      path: "/internal/v1/runner/start",
      timestamp,
      nonce,
      body,
    });
    const signature = new Uint8Array(await crypto.subtle.sign(
      "Ed25519", keyPair.privateKey, new Uint8Array(message),
    ));
    return {
      request: new Request("https://api.skyhigh.example/internal/v1/runner/start", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [RUNNER_AUTH_HEADERS.keyId]: "runner-start-key",
          [RUNNER_AUTH_HEADERS.timestamp]: timestamp,
          [RUNNER_AUTH_HEADERS.nonce]: nonce,
          [RUNNER_AUTH_HEADERS.signature]: encodeBase64Url(signature),
        },
        body: bodyText,
      }),
      publicKey,
    };
  }

  it("authenticates the machine and returns the durable lease-fenced start receipt", async () => {
    const signed = await signedStartRequest(startReceipt);
    const start = vi.fn(async (input: RecordRunnerStartInput) => ({
      dispatchId: input.dispatchId,
      executionId: input.executionId,
      attemptId: input.attemptId,
      eventId: "a1000000-0000-4000-8000-000000000001",
      startedAt: "2026-11-13T08:30:00.000Z",
      replayed: false,
    }));
    const findActivePublicKey = vi.fn(async () => ({
      keyId: "runner-start-key",
      runnerId,
      publicKey: signed.publicKey,
    }));
    const consumeNonce = vi.fn(async () => true);
    const { handler, authenticator } = makeHarness({
      runnerIdentityRepository: { findActivePublicKey, consumeNonce },
      runnerStartRepository: { start },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(200);
    expect(await readJson(response)).toMatchObject({
      data: {
        started: true,
        replayed: false,
        dispatchId: startReceipt.dispatchId,
        executionId: startReceipt.executionId,
        attemptId: startReceipt.attemptId,
        eventId: "a1000000-0000-4000-8000-000000000001",
      },
    });
    expect(start).toHaveBeenCalledWith({
      ...startReceipt,
      runnerId,
      keyId: "runner-start-key",
    });
    expect(findActivePublicKey).toHaveBeenCalledOnce();
    expect(consumeNonce).toHaveBeenCalledOnce();
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });

  it("rejects extra fields before public-key lookup", async () => {
    const signedBody = { ...startReceipt, sourceCode: "source must never be sent to start" };
    const findActivePublicKey = vi.fn(async () => null);
    const start = vi.fn(async () => {
      throw new Error("must_not_start");
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey,
        consumeNonce: vi.fn(async () => true),
      },
      runnerStartRepository: { start },
    });

    const response = await handler(makeRequest("/internal/v1/runner/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(signedBody),
    }));

    expect(response.status).toBe(400);
    expect(await readJson(response)).toMatchObject({
      error: { code: "INVALID_RUNNER_START", retryable: false },
    });
    expect(findActivePublicKey).not.toHaveBeenCalled();
    expect(start).not.toHaveBeenCalled();
  });

  it("rejects a replayed nonce before attempting to start work", async () => {
    const signed = await signedStartRequest(startReceipt);
    const start = vi.fn(async () => {
      throw new Error("must_not_start");
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey: vi.fn(async () => ({
          keyId: "runner-start-key", runnerId, publicKey: signed.publicKey,
        })),
        consumeNonce: vi.fn(async () => false),
      },
      runnerStartRepository: { start },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(401);
    expect(await readJson(response)).toMatchObject({
      error: { code: "RUNNER_AUTHENTICATION_FAILED" },
    });
    expect(start).not.toHaveBeenCalled();
  });

  it("requires a durable acceptance receipt before changing job state", async () => {
    const signed = await signedStartRequest(startReceipt);
    const start = vi.fn(async () => {
      throw new RunnerStartNotAcceptedError();
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey: vi.fn(async () => ({
          keyId: "runner-start-key", runnerId, publicKey: signed.publicKey,
        })),
        consumeNonce: vi.fn(async () => true),
      },
      runnerStartRepository: { start },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(409);
    expect(await readJson(response)).toMatchObject({
      error: { code: "RUNNER_ACCEPTANCE_REQUIRED", retryable: false },
    });
    expect(start).toHaveBeenCalledOnce();
  });
});


describe("authenticated runner heartbeat endpoint", () => {
  const runnerId = "40000000-0000-4000-8000-000000000001";
  const heartbeatReceipt = {
    heartbeatId: "95000000-0000-4000-8000-000000000001",
    dispatchId: "50000000-0000-4000-8000-000000000001",
    executionId: "60000000-0000-4000-8000-000000000001",
    attemptId: "70000000-0000-4000-8000-000000000001",
    leaseToken: "80000000-0000-4000-8000-000000000001",
  };

  function encodeBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/g, "");
  }

  async function signedHeartbeatRequest(bodyValue: Record<string, string>) {
    const now = new Date();
    const timestamp = String(Math.floor(now.getTime() / 1000));
    const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const bodyText = JSON.stringify(bodyValue);
    const body = new TextEncoder().encode(bodyText);
    const keyPair = await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    ) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const message = await canonicalRunnerRequestMessage({
      keyId: "runner-heartbeat-key",
      method: "POST",
      path: "/internal/v1/runner/heartbeat",
      timestamp,
      nonce,
      body,
    });
    const signature = new Uint8Array(await crypto.subtle.sign(
      "Ed25519", keyPair.privateKey, new Uint8Array(message),
    ));
    return {
      request: new Request("https://api.skyhigh.example/internal/v1/runner/heartbeat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [RUNNER_AUTH_HEADERS.keyId]: "runner-heartbeat-key",
          [RUNNER_AUTH_HEADERS.timestamp]: timestamp,
          [RUNNER_AUTH_HEADERS.nonce]: nonce,
          [RUNNER_AUTH_HEADERS.signature]: encodeBase64Url(signature),
        },
        body: bodyText,
      }),
      publicKey,
    };
  }

  it("authenticates the runner and returns the renewed bounded lease expiry", async () => {
    const signed = await signedHeartbeatRequest(heartbeatReceipt);
    const renew = vi.fn(async (input: RecordRunnerHeartbeatInput) => ({
      heartbeatId: input.heartbeatId,
      dispatchId: input.dispatchId,
      executionId: input.executionId,
      leaseExpiresAt: "2026-11-13T08:32:00.000Z",
      replayed: false,
    }));
    const findActivePublicKey = vi.fn(async () => ({
      keyId: "runner-heartbeat-key",
      runnerId,
      publicKey: signed.publicKey,
    }));
    const consumeNonce = vi.fn(async () => true);
    const { handler, authenticator } = makeHarness({
      runnerIdentityRepository: { findActivePublicKey, consumeNonce },
      runnerHeartbeatRepository: { renew },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(200);
    expect(await readJson(response)).toMatchObject({
      data: {
        renewed: true,
        replayed: false,
        heartbeatId: heartbeatReceipt.heartbeatId,
        dispatchId: heartbeatReceipt.dispatchId,
        executionId: heartbeatReceipt.executionId,
        leaseExpiresAt: "2026-11-13T08:32:00.000Z",
      },
    });
    expect(renew).toHaveBeenCalledWith({
      ...heartbeatReceipt,
      runnerId,
      keyId: "runner-heartbeat-key",
    });
    expect(consumeNonce).toHaveBeenCalledOnce();
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });

  it("rejects extra heartbeat fields before public-key lookup", async () => {
    const findActivePublicKey = vi.fn(async () => null);
    const renew = vi.fn(async () => {
      throw new Error("must_not_renew");
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey,
        consumeNonce: vi.fn(async () => true),
      },
      runnerHeartbeatRepository: { renew },
    });

    const response = await handler(makeRequest("/internal/v1/runner/heartbeat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...heartbeatReceipt, sourceCode: "never send source in heartbeat" }),
    }));

    expect(response.status).toBe(400);
    expect(await readJson(response)).toMatchObject({
      error: { code: "INVALID_RUNNER_HEARTBEAT", retryable: false },
    });
    expect(findActivePublicKey).not.toHaveBeenCalled();
    expect(renew).not.toHaveBeenCalled();
  });

  it("rejects replayed request nonces before lease renewal", async () => {
    const signed = await signedHeartbeatRequest(heartbeatReceipt);
    const renew = vi.fn(async () => {
      throw new Error("must_not_renew");
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey: vi.fn(async () => ({
          keyId: "runner-heartbeat-key", runnerId, publicKey: signed.publicKey,
        })),
        consumeNonce: vi.fn(async () => false),
      },
      runnerHeartbeatRepository: { renew },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(401);
    expect(renew).not.toHaveBeenCalled();
  });

  it("requires a durable start receipt before extending a lease", async () => {
    const signed = await signedHeartbeatRequest(heartbeatReceipt);
    const renew = vi.fn(async () => {
      throw new RunnerHeartbeatNotStartedError();
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey: vi.fn(async () => ({
          keyId: "runner-heartbeat-key", runnerId, publicKey: signed.publicKey,
        })),
        consumeNonce: vi.fn(async () => true),
      },
      runnerHeartbeatRepository: { renew },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(409);
    expect(await readJson(response)).toMatchObject({
      error: { code: "RUNNER_START_REQUIRED", retryable: false },
    });
  });
});


describe("authenticated runner private artifact endpoint", () => {
  const runnerId = "40000000-0000-4000-8000-000000000001";
  const artifactRequest = {
    dispatchId: "50000000-0000-4000-8000-000000000001",
    executionId: "60000000-0000-4000-8000-000000000001",
    attemptId: "70000000-0000-4000-8000-000000000001",
    leaseToken: "80000000-0000-4000-8000-000000000001",
  };

  function encodeBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/g, "");
  }

  async function signedArtifactRequest(bodyValue: Record<string, string>) {
    const now = new Date();
    const timestamp = String(Math.floor(now.getTime() / 1000));
    const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const bodyText = JSON.stringify(bodyValue);
    const body = new TextEncoder().encode(bodyText);
    const keyPair = await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    ) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const message = await canonicalRunnerRequestMessage({
      keyId: "runner-artifact-key",
      method: "POST",
      path: "/internal/v1/runner/artifact",
      timestamp,
      nonce,
      body,
    });
    const signature = new Uint8Array(await crypto.subtle.sign(
      "Ed25519", keyPair.privateKey, new Uint8Array(message),
    ));
    return {
      request: new Request("https://api.skyhigh.example/internal/v1/runner/artifact", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [RUNNER_AUTH_HEADERS.keyId]: "runner-artifact-key",
          [RUNNER_AUTH_HEADERS.timestamp]: timestamp,
          [RUNNER_AUTH_HEADERS.nonce]: nonce,
          [RUNNER_AUTH_HEADERS.signature]: encodeBase64Url(signature),
        },
        body: bodyText,
      }),
      publicKey,
    };
  }

  it("returns private source and the action-scoped test bundle only to an authenticated runner", async () => {
    const signed = await signedArtifactRequest(artifactRequest);
    const artifact: RunnerExecutionArtifact = {
      executionId: artifactRequest.executionId,
      attemptId: artifactRequest.attemptId,
      problemVersionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      problemSlug: "two-sum",
      problemTitle: "Two Sum",
      action: "SUBMIT",
      language: "java",
      runtimeVersion: "25",
      sourceArtifactId: "a2000000-0000-4000-8000-000000000001",
      sourceSha256: "a".repeat(64),
      sourceCode: "public class Main {}",
      testBundleId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1-submit-1234567890abcdef",
      testBundleSha256: "b".repeat(64),
      testCases: [{
        testCaseId: "a3000000-0000-4000-8000-000000000001",
        sequence: 1,
        visibility: "HIDDEN",
        input: "4 9\n2 7 11 15",
        expectedOutput: "0 1",
      }],
    };
    const fetchArtifact = vi.fn(async (_input: FetchRunnerArtifactInput) => artifact);
    const findActivePublicKey = vi.fn(async () => ({
      keyId: "runner-artifact-key", runnerId, publicKey: signed.publicKey,
    }));
    const consumeNonce = vi.fn(async () => true);
    const { handler, authenticator } = makeHarness({
      runnerIdentityRepository: { findActivePublicKey, consumeNonce },
      runnerArtifactRepository: { fetch: fetchArtifact },
    });

    const response = await handler(signed.request);
    const body = await readJson<{ data: RunnerExecutionArtifact }>(response);

    expect(response.status).toBe(200);
    expect(body.data).toEqual(artifact);
    expect(fetchArtifact).toHaveBeenCalledWith({
      ...artifactRequest,
      runnerId,
      keyId: "runner-artifact-key",
    });
    expect(consumeNonce).toHaveBeenCalledOnce();
    expect(authenticator.authenticate).not.toHaveBeenCalled();
  });

  it("rejects extra fields before machine key lookup", async () => {
    const findActivePublicKey = vi.fn(async () => null);
    const fetchArtifact = vi.fn(async () => {
      throw new Error("must_not_fetch");
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey,
        consumeNonce: vi.fn(async () => true),
      },
      runnerArtifactRepository: { fetch: fetchArtifact },
    });

    const response = await handler(makeRequest("/internal/v1/runner/artifact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...artifactRequest, sourceCode: "must not be requested" }),
    }));

    expect(response.status).toBe(400);
    expect(await readJson(response)).toMatchObject({
      error: { code: "INVALID_RUNNER_ARTIFACT_REQUEST", retryable: false },
    });
    expect(findActivePublicKey).not.toHaveBeenCalled();
    expect(fetchArtifact).not.toHaveBeenCalled();
  });

  it("requires a durable start receipt before artifact retrieval", async () => {
    const signed = await signedArtifactRequest(artifactRequest);
    const fetchArtifact = vi.fn(async () => {
      throw new RunnerArtifactNotStartedError();
    });
    const { handler } = makeHarness({
      runnerIdentityRepository: {
        findActivePublicKey: vi.fn(async () => ({
          keyId: "runner-artifact-key", runnerId, publicKey: signed.publicKey,
        })),
        consumeNonce: vi.fn(async () => true),
      },
      runnerArtifactRepository: { fetch: fetchArtifact },
    });

    const response = await handler(signed.request);

    expect(response.status).toBe(409);
    expect(await readJson(response)).toMatchObject({
      error: { code: "RUNNER_START_REQUIRED", retryable: false },
    });
  });
});
