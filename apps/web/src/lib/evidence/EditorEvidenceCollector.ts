export type EvidenceLanguage = "java" | "python";
export type SnapshotKind = "SESSION_START" | "PERIODIC" | "CONTEXT_CHANGE" | "RUN" | "SUBMIT" | "SESSION_END";
export type EvidenceEventType =
  | "SESSION_STARTED"
  | "CODE_SNAPSHOT_CREATED"
  | "CHECKPOINT_RECORDED"
  | "EDITOR_CONTEXT_CHANGED"
  | "RUN_REQUESTED"
  | "SUBMIT_REQUESTED"
  | "SESSION_ENDED";

export interface EditorEvidenceSnapshot {
  readonly snapshotId: string;
  readonly sessionId: string;
  readonly sequence: number;
  readonly problemId: string;
  readonly problemVersion: string;
  readonly language: EvidenceLanguage;
  readonly kind: SnapshotKind;
  readonly sourceCode: string;
  readonly sourceByteLength: number;
  readonly contentSha256: string;
  readonly capturedAt: string;
}

export interface EditorEvidenceEvent {
  readonly schemaVersion: 1;
  readonly eventId: string;
  readonly sessionId: string;
  readonly sequence: number;
  readonly eventType: EvidenceEventType;
  readonly occurredAt: string;
  readonly problemId: string;
  readonly problemVersion: string;
  readonly language: EvidenceLanguage;
  readonly snapshotId?: string;
  readonly contentSha256?: string;
  readonly metadata?: Readonly<Record<string, string | number | boolean>>;
}

export interface CapturedEvidence {
  readonly event: EditorEvidenceEvent;
  readonly snapshot?: EditorEvidenceSnapshot;
}

export interface EditorEvidenceCollectorOptions {
  readonly problemId: string;
  readonly problemVersion: string;
  readonly language: EvidenceLanguage;
  readonly initialSource: string;
  readonly onRecord?: (record: CapturedEvidence) => void;
  readonly now?: () => number;
  readonly createId?: () => string;
  readonly setTimer?: (callback: () => void, delayMs: number) => ReturnType<typeof setTimeout>;
  readonly clearTimer?: (timer: ReturnType<typeof setTimeout>) => void;
}

export interface EditorEvidenceSummary {
  readonly sessionId: string;
  readonly eventCount: number;
  readonly snapshotCount: number;
  readonly lastSnapshotAt: string;
  readonly lastCheckpointAt: string;
  readonly pendingChangeCount: number;
  readonly active: boolean;
}

const CHANGE_CAPTURE_INTERVAL_MS = 2 * 60 * 1000;
const CHECKPOINT_INTERVAL_MS = 5 * 60 * 1000;

function defaultCreateId(): string {
  if (!globalThis.crypto?.randomUUID) {
    throw new Error("secure_random_uuid_unavailable");
  }
  return globalThis.crypto.randomUUID();
}

async function sha256(sourceCode: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("web_crypto_unavailable");
  }
  const bytes = new TextEncoder().encode(sourceCode);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
}

/**
 * Captures only the active Sky High editor document. Records remain in page
 * memory until an authenticated evidence-ingestion service is connected.
 * It intentionally does not use localStorage, IndexedDB, clipboard APIs,
 * screenshots, or device-wide activity collection.
 */
export class EditorEvidenceCollector {
  private readonly options: EditorEvidenceCollectorOptions;
  private readonly now: () => number;
  private readonly createId: () => string;
  private readonly scheduleTimer: NonNullable<EditorEvidenceCollectorOptions["setTimer"]>;
  private readonly cancelTimer: NonNullable<EditorEvidenceCollectorOptions["clearTimer"]>;
  private readonly records: CapturedEvidence[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private sequence = 0;
  private active = true;
  private processing = false;
  private sourceCode: string;
  private language: EvidenceLanguage;
  private latestSnapshot: EditorEvidenceSnapshot | null = null;
  private lastSnapshotAt: number;
  private lastCheckpointAt: number;
  private pendingChangeCount = 0;
  private totalChangeNotifications = 0;
  private dirty = false;
  private disposed = false;

  private constructor(options: EditorEvidenceCollectorOptions) {
    this.options = options;
    this.now = options.now ?? Date.now;
    this.createId = options.createId ?? defaultCreateId;
    this.scheduleTimer = options.setTimer ?? ((callback, delayMs) => setTimeout(callback, delayMs));
    this.cancelTimer = options.clearTimer ?? ((timer) => clearTimeout(timer));
    this.sourceCode = options.initialSource;
    this.language = options.language;
    this.lastSnapshotAt = this.now();
    this.lastCheckpointAt = this.now();
  }

  static async start(options: EditorEvidenceCollectorOptions): Promise<EditorEvidenceCollector> {
    if (!options.problemId || !options.problemVersion) {
      throw new Error("problem_context_required");
    }
    const collector = new EditorEvidenceCollector(options);
    collector.emit({
      eventType: "SESSION_STARTED",
      metadata: { captureMode: "in-memory-preview", changeIntervalSeconds: 120, checkpointSeconds: 300 },
    });
    await collector.captureSnapshot("SESSION_START");
    collector.scheduleNext();
    return collector;
  }

  noteEditorChange(sourceCode: string): void {
    if (!this.active || this.disposed || sourceCode === this.sourceCode) return;
    this.sourceCode = sourceCode;
    this.pendingChangeCount += 1;
    this.totalChangeNotifications += 1;
    this.dirty = this.sourceCode !== this.latestSnapshot?.sourceCode;
    this.scheduleNext();
  }

  async changeContext(language: EvidenceLanguage, sourceCode: string): Promise<void> {
    if (!this.active || this.disposed) return;
    if (language === this.language && sourceCode === this.sourceCode) return;
    if (this.dirty) {
      await this.captureSnapshot("PERIODIC");
    }
    this.language = language;
    this.sourceCode = sourceCode;
    await this.captureSnapshot("CONTEXT_CHANGE");
    this.emit({
      eventType: "EDITOR_CONTEXT_CHANGED",
      snapshotId: this.latestSnapshot?.snapshotId,
      contentSha256: this.latestSnapshot?.contentSha256,
      metadata: { language },
    });
    this.scheduleNext();
  }

  async captureAttempt(action: "RUN" | "SUBMIT", sourceCode: string, language: EvidenceLanguage): Promise<EditorEvidenceSnapshot> {
    if (!this.active || this.disposed) {
      throw new Error("evidence_session_not_active");
    }
    this.noteEditorChange(sourceCode);
    this.language = language;
    const snapshot = await this.captureSnapshot(action);
    this.emit({
      eventType: action === "RUN" ? "RUN_REQUESTED" : "SUBMIT_REQUESTED",
      snapshotId: snapshot.snapshotId,
      contentSha256: snapshot.contentSha256,
      metadata: { snapshotKind: action },
    });
    this.scheduleNext();
    return snapshot;
  }

  getSummary(): EditorEvidenceSummary {
    return Object.freeze({
      sessionId: this.sessionId,
      eventCount: this.records.length,
      snapshotCount: this.records.filter((record) => record.snapshot !== undefined).length,
      lastSnapshotAt: new Date(this.lastSnapshotAt).toISOString(),
      lastCheckpointAt: new Date(this.lastCheckpointAt).toISOString(),
      pendingChangeCount: this.pendingChangeCount,
      active: this.active,
    });
  }

  getRecords(): readonly CapturedEvidence[] {
    return Object.freeze([...this.records]);
  }

  async close(): Promise<void> {
    if (!this.active || this.disposed) return;
    this.active = false;
    this.disposed = true;
    if (this.timer !== null) {
      this.cancelTimer(this.timer);
      this.timer = null;
    }
    if (this.latestSnapshot === null || this.dirty) {
      await this.captureSnapshot("SESSION_END", true);
    }
    this.emit({
      eventType: "SESSION_ENDED",
      snapshotId: this.latestSnapshot?.snapshotId,
      contentSha256: this.latestSnapshot?.contentSha256,
      metadata: { totalChangeNotifications: this.totalChangeNotifications },
    });
  }

  private get sessionId(): string {
    const sessionStarted = this.records.find((record) => record.event.eventType === "SESSION_STARTED");
    if (!sessionStarted) throw new Error("session_start_event_missing");
    return sessionStarted.event.sessionId;
  }

  private async captureSnapshot(kind: SnapshotKind, allowClosing = false): Promise<EditorEvidenceSnapshot> {
    if ((!this.active && !allowClosing) || this.disposed && !allowClosing) {
      throw new Error("evidence_session_not_active");
    }
    const source = this.sourceCode;
    const changesSincePreviousSnapshot = this.pendingChangeCount;
    const capturedAtMs = this.now();
    const sourceBytes = new TextEncoder().encode(source);
    const snapshotId = this.createId();
    const contentSha256 = await sha256(source);
    const eventSequence = this.sequence + 1;
    const snapshot: EditorEvidenceSnapshot = Object.freeze({
      snapshotId,
      sessionId: this.sessionId,
      sequence: eventSequence,
      problemId: this.options.problemId,
      problemVersion: this.options.problemVersion,
      language: this.language,
      kind,
      sourceCode: source,
      sourceByteLength: sourceBytes.byteLength,
      contentSha256,
      capturedAt: new Date(capturedAtMs).toISOString(),
    });
    this.latestSnapshot = snapshot;
    this.lastSnapshotAt = capturedAtMs;
    this.pendingChangeCount = 0;
    this.dirty = false;
    this.emit({
      eventType: "CODE_SNAPSHOT_CREATED",
      snapshotId,
      contentSha256,
      metadata: {
        kind,
        sourceByteLength: sourceBytes.byteLength,
        changeNotificationsSincePreviousSnapshot: changesSincePreviousSnapshot,
      },
    }, snapshot);
    return snapshot;
  }

  private emit(
    fields: {
      readonly eventType: EvidenceEventType;
      readonly snapshotId?: string;
      readonly contentSha256?: string;
      readonly metadata?: Readonly<Record<string, string | number | boolean>>;
    },
    snapshot?: EditorEvidenceSnapshot,
  ): void {
    this.sequence += 1;
    const event: EditorEvidenceEvent = Object.freeze({
      schemaVersion: 1,
      eventId: this.createId(),
      sessionId: this.records[0]?.event.sessionId ?? this.createId(),
      sequence: this.sequence,
      eventType: fields.eventType,
      occurredAt: new Date(this.now()).toISOString(),
      problemId: this.options.problemId,
      problemVersion: this.options.problemVersion,
      language: this.language,
      ...(fields.snapshotId ? { snapshotId: fields.snapshotId } : {}),
      ...(fields.contentSha256 ? { contentSha256: fields.contentSha256 } : {}),
      ...(fields.metadata ? { metadata: Object.freeze({ ...fields.metadata }) } : {}),
    });
    const record: CapturedEvidence = Object.freeze({
      event,
      ...(snapshot ? { snapshot } : {}),
    });
    this.records.push(record);
    this.options.onRecord?.(record);
  }

  private scheduleNext(): void {
    if (!this.active || this.disposed || this.processing) return;
    if (this.timer !== null) {
      this.cancelTimer(this.timer);
      this.timer = null;
    }
    const now = this.now();
    const changeDue = this.dirty
      ? this.lastSnapshotAt + CHANGE_CAPTURE_INTERVAL_MS
      : Number.POSITIVE_INFINITY;
    const checkpointDue = this.lastCheckpointAt + CHECKPOINT_INTERVAL_MS;
    const dueAt = Math.min(changeDue, checkpointDue);
    this.timer = this.scheduleTimer(() => {
      this.timer = null;
      void this.processDue();
    }, Math.max(0, dueAt - now));
  }

  private async processDue(): Promise<void> {
    if (!this.active || this.disposed || this.processing) return;
    this.processing = true;
    try {
      const now = this.now();
      if (this.dirty && now >= this.lastSnapshotAt + CHANGE_CAPTURE_INTERVAL_MS) {
        await this.captureSnapshot("PERIODIC");
      }
      if (this.active && now >= this.lastCheckpointAt + CHECKPOINT_INTERVAL_MS) {
        this.lastCheckpointAt = now;
        this.emit({
          eventType: "CHECKPOINT_RECORDED",
          snapshotId: this.latestSnapshot?.snapshotId,
          contentSha256: this.latestSnapshot?.contentSha256,
          metadata: {
            unchangedSincePreviousSnapshot: this.sourceCode === this.latestSnapshot?.sourceCode,
          },
        });
      }
    } finally {
      this.processing = false;
      this.scheduleNext();
    }
  }
}
