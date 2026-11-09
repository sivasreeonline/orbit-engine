import { buildApiHandler } from "./app";
import { UnconfiguredAuthenticator } from "./auth/unconfigured-authenticator";
import { PostgresProblemRepository } from "./db/problem-repository";
import type { Env } from "./env";

const authenticator = new UnconfiguredAuthenticator();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const repository = new PostgresProblemRepository(env);
    const handler = buildApiHandler(env, { authenticator, repository });
    return handler(request);
  },
};
