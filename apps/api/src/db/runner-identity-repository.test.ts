import { describe, expect, it } from "vitest";
import { DatabaseUnavailableError } from "./database-errors";
import {
  InvalidRunnerIdentityLookupError,
  PostgresRunnerIdentityRepository,
  RunnerIdentityRegistryIntegrityError,
} from "./runner-identity-repository";

interface Call {
  readonly text: string;
  readonly values: unknown[] | undefined;
}

function fakeClient(rows: Record<string, unknown>[] = [], failure?: Error) {
  const calls: Call[] = [];
  let ended = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      if (failure) throw failure;
      return { rows: rows as unknown as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, ended: () => ended };
}

const connection = "postgres://test-user:test-password@localhost/test";
const identityRow = {
  runner_id: "runner-java-01",
  pool_key: "java-linux",
  identity_subject: "service-subject-01",
  scopes: ["dispatch:claim", "dispatch:receipt"],
};

describe("PostgresRunnerIdentityRepository", () => {
  it("resolves only the exact verified issuer and subject to trusted registry fields", async () => {
    const fake = fakeClient([identityRow]);
    const repository = new PostgresRunnerIdentityRepository(connection, () => fake.client);

    await expect(repository.findActivePrincipal(
      "https://identity.example.test", "service-subject-01",
    )).resolves.toEqual({
      runnerId: "runner-java-01",
      poolId: "java-linux",
      subject: "service-subject-01",
      scopes: ["dispatch:claim", "dispatch:receipt"],
    });

    expect(fake.calls[1]?.text).toContain("identity.identity_issuer = $1");
    expect(fake.calls[1]?.text).toContain("identity.identity_subject = $2");
    expect(fake.calls[1]?.text).toContain("identity.status = 'ACTIVE'");
    expect(fake.calls[1]?.text).toContain("pool.status = 'ACTIVE'");
    expect(fake.calls[1]?.values).toEqual([
      "https://identity.example.test", "service-subject-01",
    ]);
    expect(fake.ended()).toBe(true);
  });

  it("returns null when the verified identity is unknown, suspended, revoked or in a disabled pool", async () => {
    const fake = fakeClient([]);
    const repository = new PostgresRunnerIdentityRepository(connection, () => fake.client);

    await expect(repository.findActivePrincipal(
      "https://identity.example.test", "unknown-subject",
    )).resolves.toBeNull();
    expect(fake.ended()).toBe(true);
  });

  it("fails closed when persisted scopes contain an unknown privilege", async () => {
    const fake = fakeClient([{ ...identityRow, scopes: ["dispatch:claim", "dispatch:admin"] }]);
    const repository = new PostgresRunnerIdentityRepository(connection, () => fake.client);

    await expect(repository.findActivePrincipal(
      "https://identity.example.test", "service-subject-01",
    )).rejects.toBeInstanceOf(RunnerIdentityRegistryIntegrityError);
    expect(fake.ended()).toBe(true);
  });

  it("rejects malformed or non-canonical lookup keys before connecting", async () => {
    const fake = fakeClient([identityRow]);
    const repository = new PostgresRunnerIdentityRepository(connection, () => fake.client);

    await expect(repository.findActivePrincipal("", "subject"))
      .rejects.toBeInstanceOf(InvalidRunnerIdentityLookupError);
    await expect(repository.findActivePrincipal(" https://issuer.test", "subject"))
      .rejects.toBeInstanceOf(InvalidRunnerIdentityLookupError);
    await expect(repository.findActivePrincipal("https://issuer.test", " subject"))
      .rejects.toBeInstanceOf(InvalidRunnerIdentityLookupError);
    await expect(repository.findActivePrincipal("x".repeat(513), "subject"))
      .rejects.toBeInstanceOf(InvalidRunnerIdentityLookupError);
    expect(fake.calls).toHaveLength(0);
  });

  it("fails closed when the registry database is not configured", async () => {
    const repository = new PostgresRunnerIdentityRepository(undefined);

    await expect(repository.findActivePrincipal(
      "https://identity.example.test", "service-subject-01",
    )).rejects.toBeInstanceOf(DatabaseUnavailableError);
  });

  it("maps database failures to a non-disclosing unavailable error and closes the client", async () => {
    const fake = fakeClient([], new Error("postgres://secret-user:secret-password@db"));
    const repository = new PostgresRunnerIdentityRepository(connection, () => fake.client);

    await expect(repository.findActivePrincipal(
      "https://identity.example.test", "service-subject-01",
    )).rejects.toBeInstanceOf(DatabaseUnavailableError);
    expect(fake.ended()).toBe(true);
  });
});
