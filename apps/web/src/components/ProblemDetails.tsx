import type { ProblemDefinition } from "../types/problem";

interface ProblemDetailsProps {
  problem: ProblemDefinition;
  activeTab: "description" | "submissions";
  onTabChange: (tab: "description" | "submissions") => void;
  isFocused: boolean;
  onFocus: () => void;
}

export default function ProblemDetails({
  problem,
  activeTab,
  onTabChange,
  isFocused,
  onFocus,
}: ProblemDetailsProps) {
  return (
    <section className="problem-card" aria-label="Problem details">
      <div className="problem-panel-heading">
        <div className="panel-heading-icon" aria-hidden="true">01</div>
        <div className="panel-heading-copy">
          <strong>Challenge briefing</strong>
          <span>Read the requirements carefully</span>
        </div>
        <span className="panel-heading-spacer" />
        <span className="panel-lockup">SH / 001</span>
        <button
          className={isFocused ? "panel-focus-button active" : "panel-focus-button"}
          type="button"
          onClick={onFocus}
          aria-pressed={isFocused}
        >
          <svg aria-hidden="true" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="M8 3H5a2 2 0 0 0-2 2v3" />
          <path d="M16 3h3a2 2 0 0 1 2 2v3" />
          <path d="M21 16v3a2 2 0 0 1-2 2h-3" />
          <path d="M3 16v3a2 2 0 0 0 2 2h3" />
                      </svg>
          {isFocused ? "Exit focus" : "Focus problem"}
        </button>
      </div>

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
            <div className="challenge-kicker">
              <span className="challenge-kicker-dot" />
              THE CHALLENGE
            </div>
            <h2>{problem.title}</h2>
            <p>{problem.statement}</p>
          </div>

          <section className="detail-section">
            <h3><span className="section-index">01</span> Input format</h3>
            <ol className="format-list">
              {problem.inputFormat.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ol>
          </section>

          <section className="detail-section">
            <h3><span className="section-index">02</span> Output format</h3>
            <p>{problem.outputFormat}</p>
          </section>

          <section className="detail-section">
            <h3><span className="section-index">03</span> Examples</h3>
            <div className="example-list">
              {problem.examples.map((example) => (
                <article className="example-card" key={example.id}>
                  <div className="example-heading">
                    <span>Example {String(example.id).padStart(2, "0")}</span>
                    <span className="example-heading-label">SAMPLE CASE</span>
                  </div>
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
            <h3><span className="section-index">04</span> Constraints</h3>
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
            Console input/output · Java 25 and Python 3.14
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
