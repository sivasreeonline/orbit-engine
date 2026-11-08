import type { ProblemDefinition } from "../types/problem";

interface ProblemDetailsProps {
  problem: ProblemDefinition;
  activeTab: "description" | "submissions";
  onTabChange: (tab: "description" | "submissions") => void;
}

export default function ProblemDetails({
  problem,
  activeTab,
  onTabChange,
}: ProblemDetailsProps) {
  return (
    <section className="problem-card" aria-label="Problem details">
      <div className="problem-tabs" role="tablist" aria-label="Problem sections">
        <button
          className={activeTab === "description" ? "problem-tab active" : "problem-tab"}
          onClick={() => onTabChange("description")}
          role="tab"
          aria-selected={activeTab === "description"}
        >
          Description
        </button>
        <button
          className={activeTab === "submissions" ? "problem-tab active" : "problem-tab"}
          onClick={() => onTabChange("submissions")}
          role="tab"
          aria-selected={activeTab === "submissions"}
        >
          Submissions
        </button>
      </div>

      {activeTab === "description" ? (
        <div className="problem-content">
          <div className="problem-intro">
            <span className="eyebrow">PROBLEM STATEMENT</span>
            <p>{problem.statement}</p>
          </div>

          <section className="detail-section">
            <h2>Input format</h2>
            <ol className="format-list">
              {problem.inputFormat.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ol>
          </section>

          <section className="detail-section">
            <h2>Output format</h2>
            <p>{problem.outputFormat}</p>
          </section>

          <section className="detail-section">
            <h2>Examples</h2>
            <div className="example-list">
              {problem.examples.map((example) => (
                <article className="example-card" key={example.id}>
                  <div className="example-heading">Example {example.id}</div>
                  <div className="example-grid">
                    <div>
                      <span>Input</span>
                      <pre>{example.input}</pre>
                    </div>
                    <div>
                      <span>Expected output</span>
                      <pre>{example.output}</pre>
                    </div>
                  </div>
                  <p className="example-explanation">{example.explanation}</p>
                </article>
              ))}
            </div>
          </section>

          <section className="detail-section">
            <h2>Constraints</h2>
            <ul className="constraints-list">
              {problem.constraints.map((constraint) => (
                <li key={constraint}>
                  <code>{constraint}</code>
                </li>
              ))}
            </ul>
          </section>

          <div className="problem-note">
            <span className="note-dot" />
            Console input/output format · Java 25 and Python 3.14
          </div>
        </div>
      ) : (
        <div className="empty-state submissions-empty">
          <div className="empty-state-icon">↗</div>
          <h2>No recorded submissions</h2>
          <p>
            Official submission history will appear here after the authenticated
            API and database are connected. This preview does not save attempts.
          </p>
        </div>
      )}
    </section>
  );
}
