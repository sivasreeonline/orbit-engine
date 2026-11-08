import type { ExecutionAction } from "../lib/execution/ExecutionAdapter";

interface EditorActionsProps {
  onReset: () => void;
  onRun: () => void;
  onSubmit: () => void;
  pendingAction: ExecutionAction | null;
}

export default function EditorActions({
  onReset,
  onRun,
  onSubmit,
  pendingAction,
}: EditorActionsProps) {
  return (
    <div className="editor-action-dock" aria-label="Code actions">
      <button
        className="reset-button action-reset-button"
        onClick={onReset}
        type="button"
        aria-label="Reset code to starter template"
        title="Reset code to starter template"
      >
        <svg
          aria-hidden="true"
          viewBox="0 0 24 24"
          width="14"
          height="14"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M3 11a8.5 8.5 0 1 0 2.6-6.1L3 7.5" />
          <path d="M3 2.8v4.7h4.7" />
        </svg>
        <span>Reset code</span>
      </button>

      <div className="editor-action-hint">
        <span className="action-hint-indicator" />
        <span>Preview only · secure execution is not connected</span>
      </div>

      <div className="editor-run-actions">
        <button
          className="editor-run-button"
          type="button"
          onClick={onRun}
          disabled={pendingAction !== null}
        >
          <span aria-hidden="true">▶</span>
          {pendingAction === "RUN" ? "Preparing…" : "Run"}
        </button>
        <button
          className="editor-submit-button"
          type="button"
          onClick={onSubmit}
          disabled={pendingAction !== null}
        >
          {pendingAction === "SUBMIT" ? "Preparing…" : "Submit"}
          <span aria-hidden="true">→</span>
        </button>
      </div>
    </div>
  );
}
