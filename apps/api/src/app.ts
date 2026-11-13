import type { Authenticator, ProblemRepository } from "./contracts";
import { DatabaseUnavailableError } from "./db/database-errors";
import type { PostgresExecutionEvidenceRepository } from "./db/execution-evidence-repository";
import {
  ExecutionProblemNotFoundError,
  IdempotencyConflictError,
  type CreateExecutionInput,
} from "./db/execution-intake-repository";

type ExecutionEvidenceReadRepository = Pick<
  PostgresExecutionEvidenceRepository,
  "listProblemAttemptHistory" | "listExecutionEvents"
> & Partial<Pick<PostgresExecutionEvidenceRepository, "getExecutionQueueStatus">>;
import type { Env } from "./env";
import type { PostgresRunnerIdentityRepository } from "./db/runner-identity-repository";
import type { PostgresRunnerDispatchLeaseRepository } from "./db/runner-dispatch-lease-repository";
import type { PostgresRunnerAcceptanceRepository } from "./db/runner-acceptance-repository";
import {
  RunnerAcceptanceConflictError,
  RunnerAcceptanceNotFoundError,
  RunnerAcceptanceStaleLeaseError,
  RunnerAcceptanceUnauthorizedError,
} from "./db/runner-acceptance-repository";
import { authenticateRunnerRequest } from "./services/runner-request-authenticator";

type ExecutionIntakeRepository = {
  create(input: CreateExecutionInput, idempotencyKey: string): Promise<{
    executionId: string;
    attemptId: string;
    replayed: boolean;
  }>;
};

interface ApiDependencies {
  readonly authenticator: Authenticator;
  readonly repository: ProblemRepository;
  readonly evidenceRepository?: ExecutionEvidenceReadRepository;
  readonly executionIntakeRepository?: ExecutionIntakeRepository;
  readonly runnerIdentityRepository?: Pick<PostgresRunnerIdentityRepository, "findActivePublicKey" | "consumeNonce">;
  readonly runnerDispatchLeaseRepository?: Pick<PostgresRunnerDispatchLeaseRepository, "claimFairBatchForRunner">;
  readonly runnerAcceptanceRepository?: Pick<PostgresRunnerAcceptanceRepository, "record">;
  readonly runtimeVersions?: { readonly java: string; readonly python: string };
  readonly allowedOrigins?: string;
}

interface ApiErrorBody {
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly retryable: boolean;
  };
  readonly correlationId: string;
}

function parseAllowedOrigins(value: string | undefined): ReadonlySet<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0),
  );
}

function requestCorrelationId(request: Request): string {
  const supplied = request.headers.get("X-Correlation-ID");
  if (supplied && /^[A-Za-z0-9._:-]{1,96}$/.test(supplied)) return supplied;
  return crypto.randomUUID();
}

function makeHeaders(
  requestId: string,
  origin: string | null,
  allowedOrigins: ReadonlySet<string>,
): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Correlation-ID": requestId,
  });

  if (origin && allowedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type, Idempotency-Key, X-Correlation-ID",
    );
    headers.append("Vary", "Origin");
  }
  return headers;
}

function jsonResponse(
  body: unknown,
  status: number,
  requestId: string,
  origin: string | null,
  allowedOrigins: ReadonlySet<string>,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: makeHeaders(requestId, origin, allowedOrigins),
  });
}

function errorResponse(
  code: string,
  message: string,
  status: number,
  retryable: boolean,
  requestId: string,
  origin: string | null,
  allowedOrigins: ReadonlySet<string>,
): Response {
  const body: ApiErrorBody = {
    error: { code, message, retryable },
    correlationId: requestId,
  };
  return jsonResponse(body, status, requestId, origin, allowedOrigins);
}

class RequestBodyTooLargeError extends Error {}
class InvalidRequestBodyError extends Error {}

async function readRawBody(request: Request, maximumBytes: number): Promise<Uint8Array> {
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new RequestBodyTooLargeError();
      }
      chunks.push(next.value);
    }
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) throw error;
    throw new InvalidRequestBodyError();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function readJsonBody(request: Request, maximumBytes: number): Promise<unknown> {
  const reader = request.body?.getReader();
  if (!reader) throw new InvalidRequestBodyError();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new RequestBodyTooLargeError();
      }
      chunks.push(next.value);
    }
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) throw error;
    throw new InvalidRequestBodyError();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new InvalidRequestBodyError();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidSlug(slug: string): boolean {
  return slug.length <= 64 && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug);
}

export function createApiHandler(dependencies: ApiDependencies) {
  const allowedOrigins = parseAllowedOrigins(dependencies.allowedOrigins);

  return async (request: Request): Promise<Response> => {
    const requestId = requestCorrelationId(request);
    const origin = request.headers.get("Origin");
    const url = new URL(request.url);
    const path = url.pathname;

    if (origin && !allowedOrigins.has(origin)) {
      return errorResponse(
        "ORIGIN_NOT_ALLOWED",
        "This origin is not allowed to call the API.",
        403,
        false,
        requestId,
        null,
        allowedOrigins,
      );
    }

    if (request.method === "OPTIONS") {
      if (!origin || !allowedOrigins.has(origin)) {
        return errorResponse(
          "ORIGIN_NOT_ALLOWED",
          "This origin is not allowed to call the API.",
          403,
          false,
          requestId,
          null,
          allowedOrigins,
        );
      }
      return new Response(null, {
        status: 204,
        headers: makeHeaders(requestId, origin, allowedOrigins),
      });
    }

    if (request.method === "GET" && path === "/healthz") {
      return jsonResponse(
        { status: "ok", service: "sky-high-coding-judge-api" },
        200,
        requestId,
        origin,
        allowedOrigins,
      );
    }

    if (request.method === "GET" && path === "/readyz") {
      try {
        await dependencies.repository.ping();
        return jsonResponse(
          { status: "ready" },
          200,
          requestId,
          origin,
          allowedOrigins,
        );
      } catch {
        return errorResponse(
          "DATABASE_NOT_READY",
          "The API database connection is not ready.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }
    }

    if (request.method === "POST" && path === "/internal/v1/runner/accept") {
      if (!dependencies.runnerIdentityRepository || !dependencies.runnerAcceptanceRepository) {
        return errorResponse(
          "RUNNER_CONTROL_PLANE_NOT_CONFIGURED",
          "Runner acceptance is temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      const mediaType = (request.headers.get("Content-Type") ?? "")
        .split(";")[0]?.trim().toLowerCase();
      if (mediaType !== "application/json") {
        return errorResponse("UNSUPPORTED_MEDIA_TYPE",
          "The runner acceptance request must use application/json.", 415, false,
          requestId, origin, allowedOrigins);
      }

      let rawBody: Uint8Array;
      let receiptBody: unknown;
      try {
        rawBody = await readRawBody(request, 2048);
        receiptBody = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawBody)) as unknown;
      } catch (error) {
        if (error instanceof RequestBodyTooLargeError) {
          return errorResponse("REQUEST_BODY_TOO_LARGE",
            "The runner acceptance request exceeds the allowed size.", 413, false,
            requestId, origin, allowedOrigins);
        }
        return errorResponse("INVALID_REQUEST_BODY",
          "The runner acceptance request must contain valid JSON.", 400, false,
          requestId, origin, allowedOrigins);
      }

      const receiptFields = [
        "acceptanceId", "dispatchId", "executionId", "attemptId", "leaseToken",
      ];
      if (!isRecord(receiptBody) ||
          Object.keys(receiptBody).length !== receiptFields.length ||
          Object.keys(receiptBody).some((key) => !receiptFields.includes(key)) ||
          receiptFields.some((key) => typeof receiptBody[key] !== "string" ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
              .test(receiptBody[key] as string))) {
        return errorResponse("INVALID_RUNNER_ACCEPTANCE",
          "The runner acceptance receipt contains invalid identifiers or fields.", 400, false,
          requestId, origin, allowedOrigins);
      }

      try {
        const authenticatedRunner = await authenticateRunnerRequest(
          request,
          rawBody,
          dependencies.runnerIdentityRepository,
        );
        if (!authenticatedRunner) {
          return errorResponse("RUNNER_AUTHENTICATION_FAILED",
            "The runner request could not be authenticated.", 401, false,
            requestId, origin, allowedOrigins);
        }

        const receiptBytes = new Uint8Array(rawBody);
        const digest = await crypto.subtle.digest("SHA-256", receiptBytes);
        const receiptSha256 = Array.from(new Uint8Array(digest), (byte) =>
          byte.toString(16).padStart(2, "0"),
        ).join("");

        const recorded = await dependencies.runnerAcceptanceRepository.record({
          acceptanceId: receiptBody.acceptanceId as string,
          dispatchId: receiptBody.dispatchId as string,
          executionId: receiptBody.executionId as string,
          attemptId: receiptBody.attemptId as string,
          leaseToken: receiptBody.leaseToken as string,
          runnerId: authenticatedRunner.runnerId,
          keyId: authenticatedRunner.keyId,
          receiptSha256,
        });
        return jsonResponse({
          data: {
            accepted: true,
            replayed: recorded.replayed,
            dispatchId: recorded.dispatchId,
            acceptanceId: recorded.acceptanceId,
            eventId: recorded.eventId,
            acceptedAt: recorded.acceptedAt,
          },
        }, 200, requestId, origin, allowedOrigins);
      } catch (error) {
        if (error instanceof RunnerAcceptanceUnauthorizedError) {
          return errorResponse("RUNNER_AUTHENTICATION_FAILED",
            "The runner identity is no longer authorized.", 401, false,
            requestId, origin, allowedOrigins);
        }
        if (error instanceof RunnerAcceptanceNotFoundError) {
          return errorResponse("RUNNER_DISPATCH_NOT_FOUND",
            "The dispatch does not match this acceptance receipt.", 404, false,
            requestId, origin, allowedOrigins);
        }
        if (error instanceof RunnerAcceptanceStaleLeaseError) {
          return errorResponse("RUNNER_LEASE_STALE",
            "The runner lease is no longer active.", 409, false,
            requestId, origin, allowedOrigins);
        }
        if (error instanceof RunnerAcceptanceConflictError) {
          return errorResponse("RUNNER_ACCEPTANCE_CONFLICT",
            "A different acceptance receipt already exists for this lease.", 409, false,
            requestId, origin, allowedOrigins);
        }
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse("RUNNER_CONTROL_PLANE_UNAVAILABLE",
            "Runner acceptance is temporarily unavailable.", 503, true,
            requestId, origin, allowedOrigins);
        }
        console.error("runner_acceptance_failed", { correlationId: requestId });
        return errorResponse("INTERNAL_ERROR",
          "The runner acceptance receipt could not be saved.", 500, true,
          requestId, origin, allowedOrigins);
      }
    }

    if (request.method === "POST" && path === "/internal/v1/runner/claim") {
      if (!dependencies.runnerIdentityRepository || !dependencies.runnerDispatchLeaseRepository) {
        return errorResponse(
          "RUNNER_CONTROL_PLANE_NOT_CONFIGURED",
          "Runner dispatch is temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      const mediaType = (request.headers.get("Content-Type") ?? "")
        .split(";")[0]?.trim().toLowerCase();
      if (mediaType !== "application/json") {
        return errorResponse("UNSUPPORTED_MEDIA_TYPE",
          "The runner claim request must use application/json.", 415, false,
          requestId, origin, allowedOrigins);
      }

      let rawBody: Uint8Array;
      let claimBody: unknown;
      try {
        rawBody = await readRawBody(request, 1024);
        claimBody = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawBody)) as unknown;
      } catch (error) {
        if (error instanceof RequestBodyTooLargeError) {
          return errorResponse("REQUEST_BODY_TOO_LARGE",
            "The runner claim request exceeds the allowed size.", 413, false,
            requestId, origin, allowedOrigins);
        }
        return errorResponse("INVALID_REQUEST_BODY",
          "The runner claim request must contain valid JSON.", 400, false,
          requestId, origin, allowedOrigins);
      }

      if (!isRecord(claimBody) ||
          Object.keys(claimBody).length !== 1 ||
          Object.keys(claimBody).some((key) => key !== "requestedSlots") ||
          !Number.isInteger(claimBody.requestedSlots) ||
          (claimBody.requestedSlots as number) < 1 ||
          (claimBody.requestedSlots as number) > 4) {
        return errorResponse("INVALID_RUNNER_CLAIM",
          "The runner claim must contain requestedSlots from 1 to 4.", 400, false,
          requestId, origin, allowedOrigins);
      }

      try {
        const authenticatedRunner = await authenticateRunnerRequest(
          request,
          rawBody,
          dependencies.runnerIdentityRepository,
        );
        if (!authenticatedRunner) {
          return errorResponse("RUNNER_AUTHENTICATION_FAILED",
            "The runner request could not be authenticated.", 401, false,
            requestId, origin, allowedOrigins);
        }

        const leases = await dependencies.runnerDispatchLeaseRepository.claimFairBatchForRunner(
          authenticatedRunner.runnerId,
          Math.min(claimBody.requestedSlots as number, 2),
          2,
          120,
        );
        return jsonResponse({
          data: leases.map((lease) => ({
            dispatchId: lease.id,
            executionId: lease.executionId,
            attemptId: lease.attemptId,
            protocolVersion: lease.protocolVersion,
            correlationId: lease.correlationId,
            deliveryAttempt: lease.deliveryAttempts,
            leaseToken: lease.leaseToken,
            leaseExpiresAt: lease.leaseExpiresAt,
          })),
          meta: {
            claimed: leases.length,
            maxActiveLeasesPerRunner: 2,
            leaseDurationSeconds: 120,
          },
        }, 200, requestId, origin, allowedOrigins);
      } catch (error) {
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse("RUNNER_CONTROL_PLANE_UNAVAILABLE",
            "Runner dispatch is temporarily unavailable.", 503, true,
            requestId, origin, allowedOrigins);
        }
        console.error("runner_claim_failed", { correlationId: requestId });
        return errorResponse("INTERNAL_ERROR",
          "Runner dispatch could not be claimed.", 500, true,
          requestId, origin, allowedOrigins);
      }
    }

    const isExecutionCreate = request.method === "POST" && path === "/api/v1/executions";
    const isProblemList = request.method === "GET" && path === "/api/v1/problems";
    const problemMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/problems\/([^/]+)$/)
      : null;
    const attemptHistoryMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/problems\/([^/]+)\/attempts$/)
      : null;
    const executionEventsMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/executions\/([^/]+)\/events$/)
      : null;
    const executionStatusMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/executions\/([^/]+)\/status$/)
      : null;

    if (!isExecutionCreate && !isProblemList && !problemMatch && !attemptHistoryMatch &&
        !executionEventsMatch && !executionStatusMatch) {
      return errorResponse(
        "NOT_FOUND",
        "The requested API route does not exist.",
        404,
        false,
        requestId,
        origin,
        allowedOrigins,
      );
    }

    let authentication;
    try {
      authentication = await dependencies.authenticator.authenticate(request);
    } catch {
      return errorResponse(
        "AUTH_PROVIDER_UNAVAILABLE",
        "The Sky High identity provider is temporarily unavailable.",
        503,
        true,
        requestId,
        origin,
        allowedOrigins,
      );
    }

    if (!authentication.authenticated) {
      if (authentication.reason === "provider_unavailable") {
        return errorResponse(
          "AUTH_PROVIDER_NOT_CONFIGURED",
          "The Sky High identity provider has not been connected to this API.",
          503,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      return errorResponse(
        "UNAUTHENTICATED",
        "A valid Sky High session is required.",
        401,
        false,
        requestId,
        origin,
        allowedOrigins,
      );
    }

    const principal = authentication.principal;
    if (!principal.tenantId || !principal.userId) {
      return errorResponse(
        "INVALID_IDENTITY_CONTEXT",
        "The authenticated identity is missing its tenant context.",
        403,
        false,
        requestId,
        origin,
        allowedOrigins,
      );
    }

    if (isExecutionCreate) {
      if (!dependencies.executionIntakeRepository) {
        return errorResponse("EXECUTION_INTAKE_NOT_CONFIGURED",
          "Code execution requests are temporarily unavailable.", 503, true,
          requestId, origin, allowedOrigins);
      }

      const idempotencyKey = request.headers.get("Idempotency-Key") ?? "";
      if (!/^[A-Za-z0-9._~-]{1,128}$/.test(idempotencyKey)) {
        return errorResponse("INVALID_IDEMPOTENCY_KEY",
          "A valid Idempotency-Key header is required.", 400, false,
          requestId, origin, allowedOrigins);
      }
      const mediaType = (request.headers.get("Content-Type") ?? "")
        .split(";")[0]?.trim().toLowerCase();
      if (mediaType !== "application/json") {
        return errorResponse("UNSUPPORTED_MEDIA_TYPE",
          "The request body must use application/json.", 415, false,
          requestId, origin, allowedOrigins);
      }
      const contentLength = request.headers.get("Content-Length");
      if (contentLength !== null &&
          (!/^[0-9]+$/.test(contentLength) || Number(contentLength) > 256 * 1024)) {
        return errorResponse("REQUEST_BODY_TOO_LARGE",
          "The execution request exceeds the allowed size.", 413, false,
          requestId, origin, allowedOrigins);
      }

      let body: unknown;
      try {
        body = await readJsonBody(request, 256 * 1024);
      } catch (error) {
        if (error instanceof RequestBodyTooLargeError) {
          return errorResponse("REQUEST_BODY_TOO_LARGE",
            "The execution request exceeds the allowed size.", 413, false,
            requestId, origin, allowedOrigins);
        }
        return errorResponse("INVALID_REQUEST_BODY",
          "The execution request must contain valid JSON.", 400, false,
          requestId, origin, allowedOrigins);
      }

      if (!isRecord(body) ||
          Object.keys(body).some((key) =>
            !["action", "problemSlug", "language", "sourceCode"].includes(key)) ||
          Object.keys(body).length !== 4) {
        return errorResponse("INVALID_EXECUTION_REQUEST",
          "The request must contain only action, problemSlug, language and sourceCode.", 400, false,
          requestId, origin, allowedOrigins);
      }

      const action = body.action;
      const problemSlug = body.problemSlug;
      const language = body.language;
      const sourceCode = body.sourceCode;
      if ((action !== "RUN" && action !== "SUBMIT") ||
          typeof problemSlug !== "string" || !isValidSlug(problemSlug) ||
          (language !== "java" && language !== "python") ||
          typeof sourceCode !== "string" || sourceCode.length === 0) {
        return errorResponse("INVALID_EXECUTION_REQUEST",
          "The execution request contains invalid action, problem, language or source code.", 400, false,
          requestId, origin, allowedOrigins);
      }

      const sourceByteLength = new TextEncoder().encode(sourceCode).byteLength;
      if (sourceByteLength > 200 * 1024) {
        return errorResponse("SOURCE_TOO_LARGE",
          "Source code must not exceed 200 KiB.", 413, false,
          requestId, origin, allowedOrigins);
      }

      const runtimeVersion = dependencies.runtimeVersions?.[language];
      if (!runtimeVersion || !/^[A-Za-z0-9._+-]{1,32}$/.test(runtimeVersion)) {
        return errorResponse("RUNTIME_POLICY_NOT_CONFIGURED",
          "The selected language runtime is not configured.", 503, false,
          requestId, origin, allowedOrigins);
      }

      try {
        const created = await dependencies.executionIntakeRepository.create({
          principal,
          action,
          problemSlug,
          language,
          runtimeVersion,
          sourceCode,
          correlationId: requestId,
        }, idempotencyKey);
        return jsonResponse({
          data: {
            executionId: created.executionId,
            attemptId: created.attemptId,
            action,
            accepted: true,
            replayed: created.replayed,
            statusUrl: `/api/v1/executions/${created.executionId}/status`,
          },
        }, 202, requestId, origin, allowedOrigins);
      } catch (error) {
        if (error instanceof ExecutionProblemNotFoundError) {
          return errorResponse("PROBLEM_NOT_FOUND",
            "The requested published problem was not found.", 404, false,
            requestId, origin, allowedOrigins);
        }
        if (error instanceof IdempotencyConflictError) {
          return errorResponse("IDEMPOTENCY_CONFLICT",
            "This Idempotency-Key was already used for a different request.", 409, false,
            requestId, origin, allowedOrigins);
        }
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse("DATABASE_UNAVAILABLE",
            "The execution request could not be saved right now.", 503, true,
            requestId, origin, allowedOrigins);
        }
        console.error("execution_intake_failed", { correlationId: requestId });
        return errorResponse("INTERNAL_ERROR",
          "The execution request could not be accepted.", 500, true,
          requestId, origin, allowedOrigins);
      }
    }

    if (attemptHistoryMatch) {
      if (!dependencies.evidenceRepository) {
        return errorResponse(
          "EVIDENCE_STORE_NOT_CONFIGURED",
          "Execution history is temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      let slug: string;
      try {
        slug = decodeURIComponent(attemptHistoryMatch[1] ?? "");
      } catch {
        return errorResponse(
          "INVALID_PROBLEM_ID",
          "The problem identifier is invalid.",
          400,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }
      if (!isValidSlug(slug)) {
        return errorResponse(
          "INVALID_PROBLEM_ID",
          "The problem identifier is invalid.",
          400,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      const rawLimit = url.searchParams.get("limit");
      const limit = rawLimit === null ? 30 : Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return errorResponse(
          "INVALID_LIMIT",
          "The limit must be an integer between 1 and 100.",
          400,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      try {
        const attempts = await dependencies.evidenceRepository.listProblemAttemptHistory(
          principal.tenantId,
          principal.userId,
          slug,
          limit,
        );
        return jsonResponse(
          { data: attempts, meta: { count: attempts.length, limit } },
          200,
          requestId,
          origin,
          allowedOrigins,
        );
      } catch (error) {
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse(
            "DATABASE_UNAVAILABLE",
            "Execution history is temporarily unavailable.",
            503,
            true,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        console.error("execution_history_read_failed", { correlationId: requestId });
        return errorResponse(
          "INTERNAL_ERROR",
          "Execution history could not be loaded.",
          500,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }
    }

    if (executionStatusMatch) {
      if (!dependencies.evidenceRepository?.getExecutionQueueStatus) {
        return errorResponse("QUEUE_STATUS_NOT_CONFIGURED",
          "Execution status is temporarily unavailable.", 503, true,
          requestId, origin, allowedOrigins);
      }

      let executionId: string;
      try {
        executionId = decodeURIComponent(executionStatusMatch[1] ?? "");
      } catch {
        executionId = "";
      }
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(executionId)) {
        return errorResponse("INVALID_EXECUTION_ID",
          "The execution identifier is invalid.", 400, false,
          requestId, origin, allowedOrigins);
      }

      try {
        const status = await dependencies.evidenceRepository.getExecutionQueueStatus(
          principal.tenantId, principal.userId, executionId,
        );
        if (!status) {
          return errorResponse("EXECUTION_NOT_FOUND",
            "The requested execution was not found.", 404, false,
            requestId, origin, allowedOrigins);
        }
        return jsonResponse({ data: status }, 200, requestId, origin, allowedOrigins);
      } catch (error) {
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse("DATABASE_UNAVAILABLE",
            "Execution status is temporarily unavailable.", 503, true,
            requestId, origin, allowedOrigins);
        }
        console.error("execution_queue_status_read_failed", { correlationId: requestId });
        return errorResponse("INTERNAL_ERROR",
          "Execution status could not be loaded.", 500, true,
          requestId, origin, allowedOrigins);
      }
    }

    if (executionEventsMatch) {
      if (!dependencies.evidenceRepository) {
        return errorResponse(
          "EVIDENCE_STORE_NOT_CONFIGURED",
          "Execution details are temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      let executionId: string;
      try {
        executionId = decodeURIComponent(executionEventsMatch[1] ?? "");
      } catch {
        executionId = "";
      }
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(executionId)) {
        return errorResponse(
          "INVALID_EXECUTION_ID",
          "The execution identifier is invalid.",
          400,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      try {
        const events = await dependencies.evidenceRepository.listExecutionEvents(
          principal.tenantId,
          principal.userId,
          executionId,
        );
        return jsonResponse(
          { data: events, meta: { count: events.length } },
          200,
          requestId,
          origin,
          allowedOrigins,
        );
      } catch (error) {
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse(
            "DATABASE_UNAVAILABLE",
            "Execution details are temporarily unavailable.",
            503,
            true,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        console.error("execution_events_read_failed", { correlationId: requestId });
        return errorResponse(
          "INTERNAL_ERROR",
          "Execution details could not be loaded.",
          500,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }
    }

    if (isProblemList) {
      const rawLimit = url.searchParams.get("limit");
      const limit = rawLimit === null ? 20 : Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) {
        return errorResponse(
          "INVALID_LIMIT",
          "The limit must be an integer between 1 and 50.",
          400,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      try {
        const problems = await dependencies.repository.listPublished(principal.tenantId, limit);
        return jsonResponse(
          { data: problems, meta: { count: problems.length, limit } },
          200,
          requestId,
          origin,
          allowedOrigins,
        );
      } catch (error) {
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse(
            "DATABASE_UNAVAILABLE",
            "The problem catalog is temporarily unavailable.",
            503,
            true,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        console.error("problem_catalog_list_failed", { correlationId: requestId });
        return errorResponse(
          "INTERNAL_ERROR",
          "The problem catalog could not be loaded.",
          500,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }
    }

    let slug: string;
    try {
      slug = decodeURIComponent(problemMatch?.[1] ?? "");
    } catch {
      return errorResponse(
        "INVALID_PROBLEM_ID",
        "The problem identifier is invalid.",
        400,
        false,
        requestId,
        origin,
        allowedOrigins,
      );
    }

    if (!isValidSlug(slug)) {
      return errorResponse(
        "INVALID_PROBLEM_ID",
        "The problem identifier is invalid.",
        400,
        false,
        requestId,
        origin,
        allowedOrigins,
      );
    }

    try {
      const problem = await dependencies.repository.getPublishedBySlug(
        principal.tenantId,
        slug,
      );
      if (!problem) {
        return errorResponse(
          "PROBLEM_NOT_FOUND",
          "The requested published problem was not found.",
          404,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      return jsonResponse(
        { data: problem },
        200,
        requestId,
        origin,
        allowedOrigins,
      );
    } catch (error) {
      if (error instanceof DatabaseUnavailableError) {
        return errorResponse(
          "DATABASE_UNAVAILABLE",
          "The problem catalog is temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }
      console.error("problem_catalog_detail_failed", { correlationId: requestId });
      return errorResponse(
        "INTERNAL_ERROR",
        "The problem details could not be loaded.",
        500,
        true,
        requestId,
        origin,
        allowedOrigins,
      );
    }
  };
}

export function buildApiHandler(
  env: Env,
  dependencies: Omit<ApiDependencies, "allowedOrigins">,
) {
  return createApiHandler({
    ...dependencies,
    ...(env.CORS_ALLOWED_ORIGINS !== undefined
      ? { allowedOrigins: env.CORS_ALLOWED_ORIGINS }
      : {}),
  });
}
