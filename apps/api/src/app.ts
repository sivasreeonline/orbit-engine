import type { Authenticator, ProblemRepository } from "./contracts";
import { DatabaseUnavailableError } from "./db/database-errors";
import type { Env } from "./env";

interface ApiDependencies {
  readonly authenticator: Authenticator;
  readonly repository: ProblemRepository;
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

    if (!isProblemList && !problemMatch) {
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
    allowedOrigins: env.CORS_ALLOWED_ORIGINS,
  });
}
