interface EvidenceCapturePanelProps {
  active: boolean;
  starting: boolean;
  eventCount: number;
  snapshotCount: number;
  pendingCount: number;
  syncState: "idle" | "syncing" | "synced" | "pending" | "error";
  syncError: string | null;
  sessionId: string | null;
  onStart: () => void;
  onStop: () => void;
  onRetry: () => void;
}

const syncLabels: Record<EvidenceCapturePanelProps["syncState"], string> = {
  idle: "Not connected",
  syncing: "Syncing",
  synced: "All events synchronized",
  pending: "Waiting to synchronize",
  error: "Synchronization needs attention",
};

export default function EvidenceCapturePanel({
  active,
  starting,
  eventCount,
  snapshotCount,
  pendingCount,
  syncState,
  syncError,
  sessionId,
  onStart,
  onStop,
  onRetry,
}: EvidenceCapturePanelProps) {
  return (
    <section
      className={active ? "evidence-capture-panel is-active" : "evidence-capture-panel"}
      aria-label="Optional coding evidence capture"
    >
      <div className="evidence-capture-copy">
        <div className="evidence-capture-heading">
          <span className="evidence-capture-indicator" aria-hidden="true" />
          <strong>{active ? "Coding evidence capture is active" : "Optional coding evidence capture"}</strong>
          <span className="evidence-capture-preview-tag">OPT-IN · NOTICE V1</span>
        </div>
        <p>
          When you start, snapshots of this editor's source code and coding-session events
          are sent to your authenticated Sky High account. We capture the initial code,
          changed code every 2 minutes, 5-minute checkpoints, separate Run/Submit snapshots,
          and a final snapshot when you end the session. We do not read your clipboard,
          take screenshots, or monitor other apps.
        </p>
        <p>
          Unsent records stay in this browser tab's memory and may be lost if you close or
          refresh it before synchronization completes. Capture starts only after the
          evidence service confirms your session.
        </p>
        {(active || pendingCount > 0 || syncState !== "idle") && (
          <div className="evidence-capture-stats" aria-live="polite">
            {active && <span>{eventCount} events</span>}
            {active && <span>{snapshotCount} code snapshots</span>}
            <span>{pendingCount} pending</span>
            <span>{syncLabels[syncState]}</span>
            {sessionId && <span>Session {sessionId.slice(0, 8)}…</span>}
          </div>
        )}
        {syncError && (
          <p className="evidence-capture-error" role="alert">{syncError}</p>
        )}
      </div>

      <div className="evidence-capture-actions">
        {active ? (
          <button
            className="evidence-capture-button is-stop"
            type="button"
            onClick={onStop}
            disabled={starting}
          >
            End capture session
          </button>
        ) : (
          <button
            className="evidence-capture-button"
            type="button"
            onClick={onStart}
            disabled={starting || pendingCount > 0}
          >
            {starting ? "Connecting…" : "I agree — start capture"}
          </button>
        )}
        {pendingCount > 0 && (
          <button
            className="evidence-capture-button evidence-capture-retry"
            type="button"
            onClick={onRetry}
            disabled={syncState === "syncing"}
          >
            {syncState === "syncing" ? "Syncing…" : "Retry sync"}
          </button>
        )}
      </div>
    </section>
  );
}
