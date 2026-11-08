import type { ExecutionAction } from "../lib/execution/ExecutionAdapter";

interface EditorActionsProps {
  onReset: () => void;
  onRun: () => void;
  onSubmit: () => void;
  pendingAction: ExecutionAction | null;
}

export default function EditorActions({ onReset, onRun, onSubmit, pendingAction }: EditorActionsProps) {
  return (
    <div className="editor-action-dock" aria-label="Code actions">
      <button className="reset-button action-reset-button" onClick={onReset} type="button">
        <span aria-hidden="true">↺</span>Reset code
      </button>
      <div className="editor-action-hint">
        <span className="action-hint-indicator" />
        <span>Preview only · secure execution is not connected</span>
      </div>
      <div className="editor-run-actions">
        <button className="editor-run-button" type="button" onClick={onRun} disabled={pendingAction !== null}>
          <span aria-hidden="true">▶</span>{pendingAction === "RUN" ? "Preparing…" : "Run"}
        </button>
        <button className="editor-submit-button" type="button" onClick={onSubmit} disabled={pendingAction !== null}>
          {pendingAction === "SUBMIT" ? "Preparing…" : "Submit"}<span aria-hidden="true">→</span>
        </button>
      </div>
    </div>
  );
}
