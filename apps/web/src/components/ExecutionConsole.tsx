import type { ExecutionFeedback } from "../lib/execution/ExecutionAdapter";
import type { ProblemDefinition } from "../types/problem";

type ConsoleTab = "output" | "fixtures" | "history";

interface ExecutionConsoleProps {
  problem: ProblemDefinition;
  activeTab: ConsoleTab;
  onTabChange: (tab: ConsoleTab) => void;
  feedback: ExecutionFeedback | null;
}

export type { ConsoleTab };

export default function ExecutionConsole({
  problem,
  activeTab,
  onTabChange,
  feedback,
}: ExecutionConsoleProps) {
  return (
    <section className="console-card" aria-label="Execution results">
      <div className="console-header">
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
            Sample fixtures
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
        <span className="console-caption">Local preview only</span>
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
              <strong>Ready when you are</strong>
              <p>
                Run and Submit controls are wired to a preview-only adapter.
                No code will execute until the secure runner is integrated.
              </p>
            </div>
          )
        )}

        {activeTab === "fixtures" && (
          <div className="fixture-list">
            <p className="fixture-disclaimer">
              Reference fixtures only. These expected outputs have not been
              evaluated against your current code.
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
            <strong>Attempt history is not connected</strong>
            <p>
              This UI preview does not persist code, runs, submissions, scores
              or student records.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
