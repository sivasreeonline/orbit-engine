import type { ExecutionFeedback } from "../lib/execution/ExecutionAdapter";
import AttemptTimeline from "./AttemptTimeline";
import type { ProblemDefinition } from "../types/problem";

export type OutputTab = "output" | "samples" | "history";

interface ExecutionOutputProps {
  problem: ProblemDefinition;
  activeTab: OutputTab;
  onTabChange: (tab: OutputTab) => void;
  feedback: ExecutionFeedback | null;
  problemSlug: string;
}

export default function ExecutionOutput({
  problem,
  activeTab,
  onTabChange,
  feedback,
  problemSlug,
}: ExecutionOutputProps) {
  return (
    <section className="output-panel" aria-label="Execution output">
      <header className="output-panel-header">
        <div className="output-panel-title">
          <span className="output-panel-icon" aria-hidden="true">&gt;_</span>
          <div>
            <strong>Run & output</strong>
            <small>Execution results and test data</small>
          </div>
        </div>
        <span className="output-engine-status">
          <span />
          ENGINE NOT CONNECTED
        </span>
      </header>

      <div className="output-tabs" role="tablist" aria-label="Output sections">
        <button
          className={activeTab === "output" ? "output-tab active" : "output-tab"}
          type="button"
          role="tab"
          aria-selected={activeTab === "output"}
          onClick={() => onTabChange("output")}
        >
          Output
        </button>
        <button
          className={activeTab === "samples" ? "output-tab active" : "output-tab"}
          type="button"
          role="tab"
          aria-selected={activeTab === "samples"}
          onClick={() => onTabChange("samples")}
        >
          Sample cases
        </button>
        <button
          className={activeTab === "history" ? "output-tab active" : "output-tab"}
          type="button"
          role="tab"
          aria-selected={activeTab === "history"}
          onClick={() => onTabChange("history")}
        >
          History
        </button>
      </div>

      <div className="output-panel-content" role="tabpanel">
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
            <div className="output-empty">
              <span className="output-empty-icon">&gt;_</span>
              <div>
                <strong>Your output will appear here</strong>
                <p>
                  Run your code from the editor. Secure execution becomes available
                  after the isolated runner and authenticated API are connected.
                </p>
              </div>
            </div>
          )
        )}

        {activeTab === "samples" && (
          <div className="output-sample-list">
            <p className="output-disclaimer">
              Reference fixtures only. These expected results have not been
              evaluated against your current source code.
            </p>
            {problem.examples.map((example) => (
              <article className="output-sample-card" key={example.id}>
                <strong>Sample {example.id}</strong>
                <div className="output-sample-grid">
                  <div>
                    <span>Input</span>
                    <pre>{example.input}</pre>
                  </div>
                  <div>
                    <span>Expected output</span>
                    <pre>{example.output}</pre>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}

        {activeTab === "history" && <AttemptTimeline problemSlug={problemSlug} />}
      </div>
    </section>
  );
}
