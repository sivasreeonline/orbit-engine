import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

const KEY_PREFIX = "workload-nonce-v1:";
const MAX_PROOF_HORIZON_SECONDS = 90;
const CLOCK_SKEW_SECONDS = 30;
const MAX_ACTIVE_NONCES_PER_CALLER = 10_000;
const CALLER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NONCE = /^[A-Za-z0-9_-]{22,86}$/;

function validTime(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Durable, per-caller nonce replay barrier.
 *
 * Callers address one instance per callerId using idFromName(callerId).
 * The callerId remains part of the storage key as a second isolation check.
 * Insert-if-absent is performed in one storage transaction so concurrent
 * invocations cannot both consume the same nonce.
 */
export class WorkloadNonceReplayDO extends DurableObject<Env> {
  async consumeNonce(
    callerId: string,
    nonce: string,
    expiresAt: number,
    trustedNow: number,
  ): Promise<boolean> {
    if (
      typeof callerId !== "string" ||
      !CALLER_ID.test(callerId) ||
      typeof nonce !== "string" ||
      !NONCE.test(nonce) ||
      !validTime(expiresAt) ||
      !validTime(trustedNow) ||
      expiresAt <= trustedNow ||
      expiresAt - trustedNow > MAX_PROOF_HORIZON_SECONDS
    ) {
      return false;
    }

    const key = `${KEY_PREFIX}${callerId}:${nonce}`;
    const consumed = await this.ctx.storage.transaction(async (txn) => {
      const priorExpiry = await txn.get<number>(key);
      if (
        priorExpiry !== undefined &&
        priorExpiry + CLOCK_SKEW_SECONDS > trustedNow
      ) {
        return false;
      }

      const entries = await txn.list<number>({
        prefix: KEY_PREFIX,
        limit: MAX_ACTIVE_NONCES_PER_CALLER + 1,
      });
      let activeCount = 0;
      for (const [entryKey, entryExpiry] of entries) {
        if (entryExpiry + CLOCK_SKEW_SECONDS <= trustedNow) {
          await txn.delete(entryKey);
        } else {
          activeCount += 1;
        }
      }
      if (activeCount >= MAX_ACTIVE_NONCES_PER_CALLER) return false;

      await txn.put(key, expiresAt);
      return true;
    });

    if (consumed) {
      await this.scheduleCleanup(expiresAt);
    }
    return consumed;
  }

  private async scheduleCleanup(expiresAt: number): Promise<void> {
    const target = (expiresAt + CLOCK_SKEW_SECONDS) * 1_000;
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > target) {
      await this.ctx.storage.setAlarm(target);
    }
  }

  override async alarm(): Promise<void> {
    const trustedCleanupTime = Math.floor(Date.now() / 1_000);
    let earliestExpiry = Number.POSITIVE_INFINITY;

    await this.ctx.storage.transaction(async (txn) => {
      const entries = await txn.list<number>({
        prefix: KEY_PREFIX,
        limit: MAX_ACTIVE_NONCES_PER_CALLER + 1,
      });
      for (const [key, expiresAt] of entries) {
        const retainedUntil = expiresAt + CLOCK_SKEW_SECONDS;
        if (retainedUntil <= trustedCleanupTime) {
          await txn.delete(key);
        } else {
          earliestExpiry = Math.min(earliestExpiry, retainedUntil);
        }
      }
    });

    if (Number.isFinite(earliestExpiry)) {
      await this.ctx.storage.setAlarm(earliestExpiry * 1_000);
    } else {
      await this.ctx.storage.deleteAlarm();
    }
  }

  override async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }
}
