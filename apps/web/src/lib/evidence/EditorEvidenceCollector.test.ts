import { afterEach, describe, expect, it, vi } from "vitest";
import {
  EditorEvidenceCollector,
  type CapturedEvidence,
} from "./EditorEvidenceCollector";

const problem = {
  problemId: "SH-ARR-001",
  problemVersion: "1",
  language: "java" as const,
  initialSource: "public class Main {}",
};

function createIds() {
  let next = 0;
  return () => `00000000-0000-4000-8000-${String(++next).padStart(12, "0")}`;
}

async function startCollector(
  onRecord?: (record: CapturedEvidence) => void,
) {
  return EditorEvidenceCollector.start({
    ...problem,
    now: () => Date.now(),
    createId: createIds(),
    ...(onRecord ? { onRecord } : {}),
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("EditorEvidenceCollector", () => {
  it("starts only when explicitly invoked and records a hashed initial snapshot", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    const records = collector.getRecords();
    expect(records.map((record) => record.event.eventType)).toEqual([
      "SESSION_STARTED",
      "CODE_SNAPSHOT_CREATED",
    ]);
    expect(records[0]?.event.sessionId).toBe(records[1]?.event.sessionId);
    expect(records[0]?.event.sequence).toBe(1);
    expect(records[1]?.event.sequence).toBe(2);
    expect(records[1]?.snapshot?.kind).toBe("SESSION_START");
    expect(records[1]?.snapshot?.sourceCode).toBe(problem.initialSource);
    expect(records[1]?.snapshot?.sourceByteLength).toBe(
      new TextEncoder().encode(problem.initialSource).byteLength,
    );
    expect(records[1]?.snapshot?.contentSha256).toMatch(/^[a-f0-9]{64}$/);
    await collector.close();
  });

  it("captures changed editor content on the two-minute boundary, not on every keystroke", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    collector.noteEditorChange("public class Main { int value = 1; }");
    collector.noteEditorChange("public class Main { int value = 12; }");
    expect(collector.getRecords().filter((record) => record.snapshot).length).toBe(1);

    await vi.advanceTimersByTimeAsync(119_999);
    await collector.awaitScheduledWork();
    expect(collector.getRecords().filter((record) => record.snapshot).length).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    await collector.awaitScheduledWork();
    const snapshots = collector.getRecords().filter((record) => record.snapshot);
    expect(snapshots).toHaveLength(2);
    expect(snapshots[1]?.snapshot?.kind).toBe("PERIODIC");
    expect(snapshots[1]?.snapshot?.sourceCode).toContain("value = 12");
    expect(snapshots[1]?.event.metadata?.changeNotificationsSincePreviousSnapshot).toBe(2);
    await collector.close();
  });

  it("does not create a periodic full snapshot when the editor is unchanged", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
    await collector.awaitScheduledWork();
    const snapshots = collector.getRecords().filter((record) => record.snapshot);
    const checkpoints = collector.getRecords().filter(
      (record) => record.event.eventType === "CHECKPOINT_RECORDED",
    );
    expect(snapshots).toHaveLength(1);
    expect(checkpoints).toHaveLength(1);
    expect(checkpoints[0]?.event.snapshotId).toBe(snapshots[0]?.snapshot?.snapshotId);
    expect(checkpoints[0]?.event.metadata?.unchangedSincePreviousSnapshot).toBe(true);
    await collector.close();
  });

  it("records five-minute checkpoints that reference the latest snapshot", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    collector.noteEditorChange("class Main { int n = 1; }");
    await vi.advanceTimersByTimeAsync(2 * 60 * 1000);
    await collector.awaitScheduledWork();
    const periodic = collector.getRecords().find(
      (record) => record.snapshot?.kind === "PERIODIC",
    );
    expect(periodic?.snapshot).toBeDefined();

    await vi.advanceTimersByTimeAsync(3 * 60 * 1000);
    await collector.awaitScheduledWork();
    const checkpoint = collector.getRecords().find(
      (record) => record.event.eventType === "CHECKPOINT_RECORDED",
    );
    expect(checkpoint?.event.snapshotId).toBe(periodic?.snapshot?.snapshotId);
    expect(checkpoint?.event.contentSha256).toBe(periodic?.snapshot?.contentSha256);
    await collector.close();
  });

  it("creates distinct immutable snapshots for Run and Submit even when code is identical", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    const run = await collector.captureAttempt("RUN", problem.initialSource, "java");
    const submit = await collector.captureAttempt("SUBMIT", problem.initialSource, "java");

    expect(run.snapshotId).not.toBe(submit.snapshotId);
    expect(run.contentSha256).toBe(submit.contentSha256);
    expect(run.kind).toBe("RUN");
    expect(submit.kind).toBe("SUBMIT");
    const attempts = collector.getRecords().filter(
      (record) => record.event.eventType === "RUN_REQUESTED" ||
        record.event.eventType === "SUBMIT_REQUESTED",
    );
    expect(attempts).toHaveLength(2);
    expect(attempts[0]?.event.snapshotId).toBe(run.snapshotId);
    expect(attempts[1]?.event.snapshotId).toBe(submit.snapshotId);
    await collector.close();
  });

  it("flushes changed code at session end and then rejects further changes", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    collector.noteEditorChange("class Main { int finalValue = 7; }");
    await collector.close();
    const records = collector.getRecords();
    expect(records.at(-2)?.snapshot?.kind).toBe("SESSION_END");
    expect(records.at(-1)?.event.eventType).toBe("SESSION_ENDED");
    expect(collector.getSummary().active).toBe(false);
    expect(() => collector.noteEditorChange("class Main {}")).not.toThrow();
  });

  it("does not create a duplicate periodic snapshot when edits return to the last saved source", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    collector.noteEditorChange("class Main { int value = 1; }");
    collector.noteEditorChange(problem.initialSource);
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
    await collector.awaitScheduledWork();

    expect(collector.getRecords().filter((record) => record.snapshot)).toHaveLength(1);
    expect(collector.getSummary().pendingChangeCount).toBe(2);
    await collector.close();
  });

  it("segments language changes into a new context snapshot", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    await collector.changeContext("python", "print('hello')");
    const latest = collector.getRecords().filter((record) => record.snapshot).at(-1);
    const contextEvent = collector.getRecords().find(
      (record) => record.event.eventType === "EDITOR_CONTEXT_CHANGED",
    );
    expect(latest?.snapshot?.kind).toBe("CONTEXT_CHANGE");
    expect(latest?.snapshot?.language).toBe("python");
    expect(contextEvent?.event.language).toBe("python");
    await collector.close();
  });

  it("keeps per-session event sequence strictly increasing", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-13T05:00:00.000Z"));
    const collector = await startCollector();

    collector.noteEditorChange("class Main { int x = 2; }");
    await vi.advanceTimersByTimeAsync(2 * 60 * 1000);
    await collector.awaitScheduledWork();
    await collector.captureAttempt("RUN", "class Main { int x = 2; }", "java");
    await vi.advanceTimersByTimeAsync(3 * 60 * 1000);
    await collector.awaitScheduledWork();
    const sequences = collector.getRecords().map((record) => record.event.sequence);
    expect(sequences).toEqual(sequences.map((_, index) => index + 1));
    await collector.close();
  });
});
