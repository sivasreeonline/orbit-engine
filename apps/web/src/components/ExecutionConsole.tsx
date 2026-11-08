import type { ExecutionAction, ExecutionFeedback } from "../lib/execution/ExecutionAdapter";
import type { ProblemDefinition } from "../types/problem";

type ConsoleTab = "output" | "fixtures" | "history";
type FocusMode = "none" | "editor" | "problem";

interface ExecutionConsoleProps {
  problem: ProblemDefinition;
  activeTab: ConsoleTab;
  onTabChange: (tab: ConsoleTab) => void;
  feedback: ExecutionFeedback | null;
  focusMode: FocusMode;
  onFocusModeChange: (mode: FocusMode) => void;
  onRun: () => void;
  onSubmit: () => void;
  pendingAction: ExecutionAction | null;
}

export type { ConsoleTab, FocusMode };

export default function ExecutionConsole({
  problem,
  activeTab,
  onTabChange,
  feedback,
  focusMode,
  onFocusModeChange,
  onRun,
  onSubmit,
  pendingAction,
}: ExecutionConsoleProps) {
  return (
    <section className="console-card" aria-label="Execution results">
      <div className="console-header">
        <div className="console-title">
          <span className="console-title-icon" aria-hidden="true">&gt;_</span>
          <div>
            <strong>Run & output</strong>
            <small>Review the result of your code</small>
          </div>
        </div>

        <div className="console-header-actions">
          <div className="focus-actions" aria-label="Workspace focus controls">
            <button
              className={focusMode === "problem" ? "focus-toggle active" : "focus-toggle"}
              type="button"
              aria-pressed={focusMode === "problem"}
              onClick={() => onFocusModeChange(focusMode === "problem" ? "none" : "problem")}
              title="Focus on the problem statement with output beside it"
            >
              <span aria-hidden="true">▤</span>
              {focusMode === "problem" ? "Exit problem focus" : "Focus problem"}
            </button>
            <button
              className={focusMode === "editor" ? "focus-toggle active" : "focus-toggle"}
              type="button"
              aria-pressed={focusMode === "editor"}
              onClick={() => onFocusModeChange(focusMode === "editor" ? "none" : "editor")}
              title="Focus on the code editor with output beside it"
            >
              <span aria-hidden="true">⌘</span>
              {focusMode === "editor" ? "Exit editor focus" : "Focus editor"}
            </button>
          </div>
        </div>
      </div>

      <div className="console-subnav">
        <div className="console-tabs" role="tablist" aria-label="Console sections">
          <button
            className={activeTab === "output" ? "console-tab active" : "console-tab"}
            onClick={() => onTabChange("output")}
            role="tab"
            aria-selected={activeTab === "output"}
          >
            Output
          </button>
          <button
            className={activeTab === "fixtures" ? "console-tab active" : "console-tab"}
            onClick={() => onTabChange("fixtures")}
            role="tab"
            aria-selected={activeTab === "fixtures"}
          >
            Sample cases
          </button>
          <button
            className={activeTab === "history" ? "console-tab active" : "console-tab"}
            onClick={() => onTabChange("history")}
            role="tab"
            aria-selected={activeTab === "history"}
          >
            History
          </button>
        </div>
        <span className="console-status">ENGINE NOT CONNECTED</span>
      </div>

      <div className="console-body" role="tabpanel">
        {activeTab === "output" && (
          feedback ? (
            <div className="execution-notice" role="status">
              <div className="notice-icon">!</div>
              <div>
                <div className="notice-title">{feedback.heading}</div>
                <p>{feedback.message}</p>
                <p className="notice-detail">{feedback.details}</p>
                <span className="mock-label">MOCK ADAPTER · NO VERDICT</span>
              </div>
            </div>
          ) : (
            <div className="console-empty">
              <div className="console-prompt">&gt;_</div>
              <div>
                <strong>Your output will appear here</strong>
                <p>
                  The editor is ready. Secure execution becomes available after
                  the isolated runner and authenticated API are connected.
                </p>
              </div>
            </div>
          )
        )}

        {activeTab === "fixtures" && (
          <div className="fixture-list">
            <p className="fixture-disclaimer">
              Sample cases are reference data; they have not been evaluated against your code.
            </p>
            {problem.examples.map((example) => (
              <article className="fixture-row" key={example.id}>
                <div>
                  <strong>Sample {example.id}</strong>
                  <span>Input</span>
                  <pre>{example.input}</pre>
                </div>
                <div>
                  <span>Expected output</span>
                  <pre>{example.output}</pre>
                </div>
              </article>
            ))}
          </div>
        )}

        {activeTab === "history" && (
          <div className="console-empty">
            <div className="console-prompt">↗</div>
            <div>
              <strong>Attempt history is not connected</strong>
              <p>
                This preview does not persist code, runs, submissions, scores or student records.
              </p>
            </div>
          </div>
        )}
      </div>

      <div className="console-action-dock">
        <div className="console-action-hint">
          <span className="action-hint-indicator" />
          <span>Preview only · secure execution is not connected</span>
        </div>
        <div className="console-run-actions">
          <button
            className="console-run-button"
            type="button"
            onClick={onRun}
            disabled={pendingAction !== null}
          >
            <span aria-hidden="true">▶</span>
            {pendingAction === "RUN" ? "Preparing…" : "Run"}
          </button>
          <button
            className="console-submit-button"
            type="button"
            onClick={onSubmit}
            disabled={pendingAction !== null}
          >
            {pendingAction === "SUBMIT" ? "Preparing…" : "Submit"}
            <span aria-hidden="true">→</span>
          </button>
        </div>
      </div>
    </section>
  );
}
