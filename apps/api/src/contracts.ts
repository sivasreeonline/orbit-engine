export type Difficulty = "Easy" | "Medium" | "Hard";

export interface Principal {
  readonly userId: string;
  readonly tenantId: string;
  readonly roles: readonly string[];
}

export interface ProblemSummary {
  readonly id: string;
  readonly problemVersionId: string;
  readonly version: number;
  readonly title: string;
  readonly difficulty: Difficulty;
  readonly category: string;
  readonly tags: readonly string[];
  readonly summary: string;
}

export interface ProblemExample {
  readonly id: number;
  readonly input: string;
  readonly output: string;
  readonly explanation: string | null;
}

export interface ProblemDetails extends ProblemSummary {
  readonly statement: string;
  readonly inputFormat: readonly string[];
  readonly outputFormat: string;
  readonly constraints: readonly string[];
  readonly examples: readonly ProblemExample[];
}

export type AuthenticationResult =
  | { readonly authenticated: true; readonly principal: Principal }
  | { readonly authenticated: false; readonly reason: "missing" | "invalid" | "provider_unavailable" };

export interface Authenticator {
  authenticate(request: Request): Promise<AuthenticationResult>;
}

export interface ProblemRepository {
  ping(): Promise<void>;
  listPublished(tenantId: string, limit: number): Promise<readonly ProblemSummary[]>;
  getPublishedBySlug(tenantId: string, slug: string): Promise<ProblemDetails | null>;
}
