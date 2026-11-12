import type { Authenticator, ProblemRepository } from "./contracts";
import { DatabaseUnavailableError } from "./db/database-errors";
import type { PostgresExecutionEvidenceRepository } from "./db/execution-evidence-repository";
import {
  ExecutionSourceSnapshotIntegrityError,
  ExecutionSourceSnapshotNotFoundError,
  ExecutionSourceSnapshotUnavailableError,
  type PostgresExecutionSourceSnapshotRepository,
} from "./db/execution-source-snapshot-repository";
import {
  ExecutionSourceComparisonConflictError,
  ExecutionSourceComparisonLimitError,
  ExecutionSourceComparisonNotFoundError,
  type PostgresExecutionSourceComparisonRepository,
} from "./db/execution-source-comparison-repository";
import { diffSourceSnapshots, SourceDiffLimitError } from "./db/execution-source-diff";

type ExecutionEvidenceReadRepository = Pick<
  PostgresExecutionEvidenceRepository,
  "listProblemAttemptHistory" | "listExecutionEvents"
> & Partial<Pick<PostgresExecutionEvidenceRepository, "listProblemAttemptTimeline">>;
import type { Env } from "./env";

type ExecutionSourceSnapshotReadRepository = Pick<
  PostgresExecutionSourceSnapshotRepository,
  "getAttemptSourceSnapshot"
>;

interface ApiDependencies {
  readonly authenticator: Authenticator;
  readonly repository: ProblemRepository;
  readonly evidenceRepository?: ExecutionEvidenceReadRepository;
  readonly sourceSnapshotRepository?: ExecutionSourceSnapshotReadRepository;
  readonly sourceComparisonRepository?: Pick<PostgresExecutionSourceComparisonRepository, "getComparableAttemptSources">;
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
    headers.set("Access-Control-Allow-Methods", "GET, OPTIONS");
    headers.set(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type, X-Correlation-ID",
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

    const isProblemList = request.method === "GET" && path === "/api/v1/problems";
    const problemMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/problems\/([^/]+)$/)
      : null;
    const attemptHistoryMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/problems\/([^/]+)\/attempts$/)
      : null;
    const attemptTimelineMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/problems\/([^/]+)\/timeline$/)
      : null;
    const executionEventsMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/executions\/([^/]+)\/events$/)
      : null;
    const attemptSourceMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/attempts\/([^/]+)\/source$/)
      : null;
    const attemptDiffMatch = request.method === "GET"
      ? path.match(/^\/api\/v1\/attempts\/([^/]+)\/diff$/)
      : null;

    if (!isProblemList && !problemMatch && !attemptHistoryMatch && !attemptTimelineMatch && !executionEventsMatch && !attemptSourceMatch && !attemptDiffMatch) {
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


    if (attemptDiffMatch) {
      if (!dependencies.sourceComparisonRepository) {
        return errorResponse(
          "SOURCE_COMPARISON_STORE_NOT_CONFIGURED",
          "The requested source comparison is temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      let targetAttemptId: string;
      try {
        targetAttemptId = decodeURIComponent(attemptDiffMatch[1] ?? "");
      } catch {
        targetAttemptId = "";
      }
      const baseAttemptId = url.searchParams.get("baseAttemptId") ?? "";
      const isUuid = (value: string) =>
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
      if (!isUuid(targetAttemptId) || !isUuid(baseAttemptId) || targetAttemptId === baseAttemptId) {
        return errorResponse(
          "INVALID_ATTEMPT_COMPARISON",
          "Two distinct valid attempt identifiers are required.",
          400,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      try {
        const snapshots = await dependencies.sourceComparisonRepository.getComparableAttemptSources(
          principal.tenantId,
          principal.userId,
          baseAttemptId,
          targetAttemptId,
        );
        const diff = diffSourceSnapshots(
          snapshots.base.sourceCode,
          snapshots.target.sourceCode,
        );
        return jsonResponse(
          {
            data: {
              base: {
                attemptId: snapshots.base.attemptId,
                sourceSha256: snapshots.base.sourceSha256,
                sourceByteLength: snapshots.base.sourceByteLength,
              },
              target: {
                attemptId: snapshots.target.attemptId,
                sourceSha256: snapshots.target.sourceSha256,
                sourceByteLength: snapshots.target.sourceByteLength,
              },
              diff,
            },
          },
          200,
          requestId,
          origin,
          allowedOrigins,
        );
      } catch (error) {
        if (error instanceof ExecutionSourceComparisonNotFoundError) {
          return errorResponse(
            "ATTEMPT_COMPARISON_NOT_FOUND",
            "The requested source comparison was not found.",
            404,
            false,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        if (error instanceof ExecutionSourceComparisonConflictError) {
          return errorResponse(
            "ATTEMPTS_NOT_COMPARABLE",
            "The selected attempts cannot be compared.",
            409,
            false,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        if (
          error instanceof DatabaseUnavailableError ||
          error instanceof ExecutionSourceSnapshotUnavailableError
        ) {
          return errorResponse(
            "SOURCE_COMPARISON_UNAVAILABLE",
            "The requested source comparison is temporarily unavailable.",
            503,
            true,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        if (error instanceof ExecutionSourceSnapshotIntegrityError) {
          console.error("execution_source_comparison_integrity_failed", {
            correlationId: requestId,
          });
          return errorResponse(
            "SOURCE_SNAPSHOT_INTEGRITY_FAILED",
            "The saved source snapshots could not be verified.",
            500,
            false,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        if (error instanceof SourceDiffLimitError || error instanceof ExecutionSourceComparisonLimitError) {
          return errorResponse(
            "SOURCE_COMPARISON_LIMIT_EXCEEDED",
            "The selected source snapshots exceed the comparison limits.",
            413,
            false,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        console.error("execution_source_comparison_failed", {
          correlationId: requestId,
        });
        return errorResponse(
          "INTERNAL_ERROR",
          "The requested source comparison could not be generated.",
          500,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }
    }

    if (attemptSourceMatch) {
      if (!dependencies.sourceSnapshotRepository) {
        return errorResponse(
          "SOURCE_SNAPSHOT_STORE_NOT_CONFIGURED",
          "The saved source snapshot is temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      let attemptId: string;
      try {
        attemptId = decodeURIComponent(attemptSourceMatch[1] ?? "");
      } catch {
        attemptId = "";
      }
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(attemptId)) {
        return errorResponse(
          "INVALID_ATTEMPT_ID",
          "The attempt identifier is invalid.",
          400,
          false,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      try {
        const snapshot = await dependencies.sourceSnapshotRepository.getAttemptSourceSnapshot(
          principal.tenantId,
          principal.userId,
          attemptId,
        );
        return jsonResponse(
          { data: snapshot },
          200,
          requestId,
          origin,
          allowedOrigins,
        );
      } catch (error) {
        if (error instanceof ExecutionSourceSnapshotNotFoundError) {
          return errorResponse(
            "ATTEMPT_SOURCE_NOT_FOUND",
            "The requested source snapshot was not found.",
            404,
            false,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        if (
          error instanceof DatabaseUnavailableError ||
          error instanceof ExecutionSourceSnapshotUnavailableError
        ) {
          return errorResponse(
            "SOURCE_SNAPSHOT_UNAVAILABLE",
            "The saved source snapshot is temporarily unavailable.",
            503,
            true,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        if (error instanceof ExecutionSourceSnapshotIntegrityError) {
          console.error("execution_source_snapshot_integrity_failed", {
            correlationId: requestId,
          });
          return errorResponse(
            "SOURCE_SNAPSHOT_INTEGRITY_FAILED",
            "The saved source snapshot could not be verified.",
            500,
            false,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        console.error("execution_source_snapshot_read_failed", {
          correlationId: requestId,
        });
        return errorResponse(
          "INTERNAL_ERROR",
          "The saved source snapshot could not be loaded.",
          500,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }
    }

    if (attemptTimelineMatch) {
      if (!dependencies.evidenceRepository?.listProblemAttemptTimeline) {
        return errorResponse(
          "EVIDENCE_STORE_NOT_CONFIGURED",
          "The coding journey is temporarily unavailable.",
          503,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
      }

      let slug: string;
      try {
        slug = decodeURIComponent(attemptTimelineMatch[1] ?? "");
      } catch {
        slug = "";
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
        const timeline = await dependencies.evidenceRepository.listProblemAttemptTimeline(
          principal.tenantId,
          principal.userId,
          slug,
          limit,
        );
        return jsonResponse(
          { data: timeline, meta: { count: timeline.length, limit } },
          200,
          requestId,
          origin,
          allowedOrigins,
        );
      } catch (error) {
        if (error instanceof DatabaseUnavailableError) {
          return errorResponse(
            "DATABASE_UNAVAILABLE",
            "The coding journey is temporarily unavailable.",
            503,
            true,
            requestId,
            origin,
            allowedOrigins,
          );
        }
        console.error("execution_timeline_read_failed", { correlationId: requestId });
        return errorResponse(
          "INTERNAL_ERROR",
          "The coding journey could not be loaded.",
          500,
          true,
          requestId,
          origin,
          allowedOrigins,
        );
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
