interface EvidenceCapturePanelProps {
  active: boolean;
  eventCount: number;
  snapshotCount: number;
  onStart: () => void;
  onStop: () => void;
}

export default function EvidenceCapturePanel({
  active,
  eventCount,
  snapshotCount,
  onStart,
  onStop,
}: EvidenceCapturePanelProps) {
  return (
    <section className={active ? "evidence-capture-panel is-active" : "evidence-capture-panel"} aria-label="Coding evidence capture">
      <div className="evidence-capture-copy">
        <div className="evidence-capture-heading">
          <span className="evidence-capture-indicator" aria-hidden="true" />
          <strong>{active ? "Evidence capture active" : "Evidence capture is off"}</strong>
          {active && <span className="evidence-capture-preview-tag">IN-MEMORY PREVIEW</span>}
        </div>
        <p>
          {active
            ? "This preview captures the editor document every 2 minutes when changed, checkpoints every 5 minutes, and separate Run/Submit snapshots. Nothing is uploaded or saved to disk."
            : "Start an explicitly disclosed preview session to record editor snapshots. Evidence stays in this browser's memory only; nothing is uploaded or saved to disk."}
        </p>
        {active && (
          <div className="evidence-capture-stats" aria-live="polite">
            <span>{eventCount} events</span>
            <span>{snapshotCount} snapshots</span>
            <span>2 min / 5 min cadence</span>
          </div>
        )}
      </div>
      <button
        className={active ? "evidence-capture-button is-stop" : "evidence-capture-button"}
        type="button"
        onClick={active ? onStop : onStart}
      >
        {active ? "End capture session" : "Start capture session"}
      </button>
    </section>
  );
}
