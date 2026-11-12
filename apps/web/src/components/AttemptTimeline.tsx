import { useEffect, useMemo, useState } from "react";

type AttemptAction = "RUN" | "SUBMIT";
type DiffKind = "EQUAL" | "INSERT" | "DELETE";

interface TimelineEvent {
  sequenceId: string;
  eventId: string;
  eventType: string;
  actorKind: string;
  phaseStatus: string | null;
  safeCode: string | null;
  durationMs: string | null;
  createdAt: string;
}

interface TimelineEntry {
  attemptId: string;
  executionId: string;
  action: AttemptAction;
  language: "java" | "python";
  runtimeVersion: string;
  sourceSha256: string;
  sourceByteLength: number;
  createdAt: string;
  executionState: string;
  infrastructureStatus: string | null;
  compilationStatus: string | null;
  verdict: string | null;
  cleanupStatus: string | null;
  testsTotal: number | null;
  testsPassed: number | null;
  elapsedMs: string | null;
  peakMemoryBytes: string | null;
  resultSha256: string | null;
  events: TimelineEvent[];
}

interface SourceSnapshot {
  attemptId: string;
  sourceSha256: string;
  sourceByteLength: string;
  sourceCode: string;
}

interface DiffOperation {
  kind: DiffKind;
  text: string;
  baseLine: number | null;
  targetLine: number | null;
}

interface DiffResult {
  operations: DiffOperation[];
  baseLineCount: number;
  targetLineCount: number;
  equalLineCount: number;
  insertedLineCount: number;
  deletedLineCount: number;
}

interface DiffPayload {
  base: { attemptId: string; sourceSha256: string; sourceByteLength: number };
  target: { attemptId: string; sourceSha256: string; sourceByteLength: number };
  diff: DiffResult;
}

interface ApiEnvelope<T> {
  data: T;
  meta?: { count: number; limit: number };
  error?: { code?: string; message?: string };
}

const apiBase = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    method: "GET",
    credentials: "include",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  const body = await response.json() as ApiEnvelope<T>;
  if (!response.ok) {
    throw new Error(body.error?.message ?? `Request failed (${response.status})`);
  }
  return body.data;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function formatBytes(value: number): string {
  return value < 1024 ? `${value} B` : `${(value / 1024).toFixed(1)} KB`;
}

function statusLabel(value: string | null): string {
  if (!value) return "Pending";
  return value.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
}

interface AttemptTimelineProps {
  problemSlug: string;
}

export default function AttemptTimeline({ problemSlug }: AttemptTimelineProps) {
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSnapshot, setSelectedSnapshot] = useState<SourceSnapshot | null>(null);
  const [snapshotLoading, setSnapshotLoading] = useState<string | null>(null);
  const [selectedForDiff, setSelectedForDiff] = useState<string[]>([]);
  const [diff, setDiff] = useState<DiffPayload | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  async function loadTimeline() {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGet<TimelineEntry[]>(
        `/api/v1/problems/${encodeURIComponent(problemSlug)}/timeline?limit=50`,
      );
      setEntries(data);
      setSelectedForDiff([]);
      setDiff(null);
      setSelectedSnapshot(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The coding journey could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadTimeline();
    // The problem slug is the identity of this timeline.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [problemSlug]);

  async function openSnapshot(entry: TimelineEntry) {
    setSnapshotLoading(entry.attemptId);
    setDetailError(null);
    setDiff(null);
    try {
      const snapshot = await apiGet<SourceSnapshot>(
        `/api/v1/attempts/${encodeURIComponent(entry.attemptId)}/source`,
      );
      setSelectedSnapshot(snapshot);
    } catch (cause) {
      setDetailError(cause instanceof Error ? cause.message : "The saved source could not be opened.");
    } finally {
      setSnapshotLoading(null);
    }
  }

  function toggleDiffSelection(attemptId: string) {
    setDetailError(null);
    setDiff(null);
    setSelectedForDiff((current) => {
      if (current.includes(attemptId)) return current.filter((id) => id !== attemptId);
      if (current.length === 2) return [current[1]!, attemptId];
      return [...current, attemptId];
    });
  }

  async function compareSelected() {
    if (selectedForDiff.length !== 2) return;
    setDiffLoading(true);
    setDetailError(null);
    setSelectedSnapshot(null);
    try {
      const selected = selectedForDiff
        .map((id) => entries.find((entry) => entry.attemptId === id))
        .filter((entry): entry is TimelineEntry => Boolean(entry))
        .sort((left, right) =>
          Date.parse(left.createdAt) - Date.parse(right.createdAt) ||
          left.attemptId.localeCompare(right.attemptId),
        );
      if (selected.length !== 2) throw new Error("Select two attempts that are still in the loaded history.");
      const [baseAttempt, targetAttempt] = selected;
      const result = await apiGet<DiffPayload>(
        `/api/v1/attempts/${encodeURIComponent(targetAttempt!.attemptId)}/diff?baseAttemptId=${encodeURIComponent(baseAttempt!.attemptId)}`,
      );
      setDiff(result);
    } catch (cause) {
      setDetailError(cause instanceof Error ? cause.message : "The selected attempts could not be compared.");
    } finally {
      setDiffLoading(false);
    }
  }

  const selectedEntries = useMemo(
    () => selectedForDiff.map((id) => entries.find((entry) => entry.attemptId === id)).filter((entry): entry is TimelineEntry => Boolean(entry)),
    [entries, selectedForDiff],
  );

  return (
    <section className="attempt-timeline" aria-label="Coding attempt timeline">
      <div className="timeline-toolbar">
        <div>
          <strong>Your coding journey</strong>
          <p>Every saved Run and Submit is a separate historical attempt.</p>
        </div>
        <button className="timeline-refresh" type="button" onClick={() => void loadTimeline()} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {loading && <p className="timeline-state" role="status">Loading your saved attempts…</p>}
      {!loading && error && (
        <div className="timeline-state timeline-error" role="alert">
          <strong>History is not available</strong>
          <p>{error}</p>
          <small>Sign in with a configured Sky High account and ensure the authenticated API is reachable.</small>
          <button type="button" onClick={() => void loadTimeline()}>Try again</button>
        </div>
      )}
      {!loading && !error && entries.length === 0 && (
        <div className="timeline-state">
          <strong>No saved attempts yet</strong>
          <p>Once authenticated Run and Submit requests are connected, your coding journey will appear here.</p>
        </div>
      )}

      {!loading && !error && entries.length > 0 && (
        <>
          <div className="timeline-compare-bar">
            <span>{selectedForDiff.length}/2 selected for comparison</span>
            <div className="timeline-compare-actions">
              <button type="button" onClick={() => { setSelectedForDiff([]); setDiff(null); }} disabled={selectedForDiff.length === 0}>
                Clear
              </button>
              <button type="button" onClick={() => void compareSelected()} disabled={selectedForDiff.length !== 2 || diffLoading}>
                {diffLoading ? "Comparing…" : "Compare attempts"}
              </button>
            </div>
          </div>

          <ol className="timeline-list">
            {entries.map((entry) => (
              <li className="timeline-item" key={entry.attemptId}>
                <span className={entry.action === "SUBMIT" ? "timeline-marker submit" : "timeline-marker run"} aria-hidden="true" />
                <article className="timeline-card">
                  <div className="timeline-card-top">
                    <div className="timeline-card-heading">
                      <span className={entry.action === "SUBMIT" ? "timeline-action submit" : "timeline-action run"}>{entry.action}</span>
                      <strong>{statusLabel(entry.verdict ?? entry.executionState)}</strong>
                    </div>
                    <time dateTime={entry.createdAt}>{formatDate(entry.createdAt)}</time>
                  </div>
                  <div className="timeline-metadata">
                    <span>{entry.language === "java" ? "Java" : "Python"} {entry.runtimeVersion}</span>
                    <span>{formatBytes(entry.sourceByteLength)}</span>
                    {entry.testsTotal !== null && <span>{entry.testsPassed ?? 0}/{entry.testsTotal} tests passed</span>}
                    {entry.elapsedMs !== null && <span>{entry.elapsedMs} ms</span>}
                  </div>
                  <div className="timeline-phases">
                    <span>Compile: {statusLabel(entry.compilationStatus)}</span>
                    <span>Infrastructure: {statusLabel(entry.infrastructureStatus)}</span>
                    <span>Cleanup: {statusLabel(entry.cleanupStatus)}</span>
                  </div>
                  {entry.events.length > 0 && (
                    <details className="timeline-events">
                      <summary>{entry.events.length} lifecycle events</summary>
                      <ol>
                        {entry.events.map((event) => (
                          <li key={event.eventId}>
                            <span>{statusLabel(event.eventType)}</span>
                            <small>{statusLabel(event.phaseStatus)} · {formatDate(event.createdAt)}</small>
                            {event.safeCode && <code>{event.safeCode}</code>}
                          </li>
                        ))}
                      </ol>
                    </details>
                  )}
                  <div className="timeline-card-actions">
                    <button type="button" onClick={() => void openSnapshot(entry)} disabled={snapshotLoading === entry.attemptId}>
                      {snapshotLoading === entry.attemptId ? "Opening…" : "Open saved code"}
                    </button>
                    <label>
                      <input
                        type="checkbox"
                        checked={selectedForDiff.includes(entry.attemptId)}
                        onChange={() => toggleDiffSelection(entry.attemptId)}
                        aria-label={`Select ${entry.action} attempt from ${formatDate(entry.createdAt)} for comparison`}
                      />
                      Compare
                    </label>
                  </div>
                </article>
              </li>
            ))}
          </ol>
          {selectedEntries.length === 2 && (
            <p className="timeline-selection-note">
              Comparing older selection as the base against the newer selection as the target.
            </p>
          )}
        </>
      )}

      {detailError && <p className="timeline-detail-error" role="alert">{detailError}</p>}

      {selectedSnapshot && (
        <section className="timeline-source-view" aria-label="Historical source snapshot">
          <div className="timeline-detail-heading">
            <div><strong>Historical source snapshot</strong><small>Read-only · does not change the active editor</small></div>
            <button type="button" onClick={() => setSelectedSnapshot(null)}>Close</button>
          </div>
          <div className="timeline-source-meta">
            <span>{formatBytes(Number(selectedSnapshot.sourceByteLength))}</span>
            <code>SHA-256 {selectedSnapshot.sourceSha256}</code>
          </div>
          <pre><code>{selectedSnapshot.sourceCode}</code></pre>
        </section>
      )}

      {diff && (
        <section className="timeline-diff-view" aria-label="Historical source comparison">
          <div className="timeline-detail-heading">
            <div><strong>Attempt comparison</strong><small>Base: {diff.base.attemptId.slice(0, 8)} · Target: {diff.target.attemptId.slice(0, 8)}</small></div>
            <button type="button" onClick={() => setDiff(null)}>Close</button>
          </div>
          <div className="timeline-diff-summary">
            <span>{diff.diff.equalLineCount} unchanged</span>
            <span className="inserted">{diff.diff.insertedLineCount} added</span>
            <span className="deleted">{diff.diff.deletedLineCount} removed</span>
          </div>
          <pre className="timeline-diff-code"><code>{diff.diff.operations.map((operation, index) => (
            <span className={`timeline-diff-line ${operation.kind.toLowerCase()}`} key={`${index}-${operation.kind}`}>
              <span className="timeline-diff-sign">{operation.kind === "INSERT" ? "+" : operation.kind === "DELETE" ? "−" : " "}</span>
              {operation.text}
            </span>
          ))}</code></pre>
        </section>
      )}
    </section>
  );
}
