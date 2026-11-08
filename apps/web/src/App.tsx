import { lazy, Suspense, useState } from "react";
const CodeEditor = lazy(() => import("./components/CodeEditor"));
import ExecutionOutput, {
  type OutputTab,
} from "./components/ExecutionOutput";
import ProblemDetails from "./components/ProblemDetails";
import { twoSumProblem, starterCode } from "./data/twoSumProblem";
import { MockExecutionAdapter } from "./lib/execution/MockExecutionAdapter";
import type {
  ExecutionAction,
  ExecutionFeedback,
} from "./lib/execution/ExecutionAdapter";
import type { SupportedLanguage } from "./types/problem";

type FocusMode = "none" | "editor" | "problem";

const mockAdapter = new MockExecutionAdapter();

const runtimeVersions: Record<SupportedLanguage, string> = {
  java: "25",
  python: "3.14",
};

const navigationItems = [
  { label: "Practice", icon: "⌘", active: true },
  { label: "Assessments", icon: "▤", active: false },
  { label: "Learning path", icon: "↗", active: false },
  { label: "Bookmarks", icon: "◇", active: false },
];

export default function App() {
  const [language, setLanguage] = useState<SupportedLanguage>("java");
  const [sourceByLanguage, setSourceByLanguage] = useState<
    Record<SupportedLanguage, string>
  >(starterCode);
  const [problemTab, setProblemTab] = useState<"description" | "submissions">(
    "description",
  );
  const [focusMode, setFocusMode] = useState<FocusMode>("none");
  const [outputTab, setOutputTab] = useState<OutputTab>("output");
  const [feedback, setFeedback] = useState<ExecutionFeedback | null>(null);
  const [pendingAction, setPendingAction] = useState<ExecutionAction | null>(
    null,
  );

  const sourceCode = sourceByLanguage[language];

  function updateSource(value: string) {
    setSourceByLanguage((current) => ({
      ...current,
      [language]: value,
    }));
  }

  function resetStarter() {
    setSourceByLanguage((current) => ({
      ...current,
      [language]: starterCode[language],
    }));
    setFeedback(null);
  }

  async function handleExecution(action: ExecutionAction) {
    setPendingAction(action);
    setOutputTab("output");
    setFeedback(null);

    try {
      const result = await mockAdapter.execute({
        problemId: twoSumProblem.id,
        problemVersion: "1",
        language,
        runtimeVersion: runtimeVersions[language],
        action,
        sourceCode,
      });
      setFeedback(result);
      if (focusMode === "none") {
        setFocusMode("editor");
      }
    } catch {
      setFeedback({
        mode: "MOCK",
        state: "NOT_CONNECTED",
        action,
        heading: "Preview adapter unavailable",
        message: "No code was executed and no verdict was produced.",
        details:
          "The execution integration is not configured in this frontend preview.",
      });
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Sky High Coding Judge home">
          <span className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
          <span className="brand-copy">
            <strong>sky high</strong>
            <small>CODING JUDGE</small>
          </span>
        </a>

        <nav className="primary-nav" aria-label="Main navigation">
          {navigationItems.map((item) => (
            <button
              className={item.active ? "primary-nav-item active" : "primary-nav-item"}
              key={item.label}
              type="button"
              aria-current={item.active ? "page" : undefined}
              disabled={!item.active}
              title={item.active ? item.label : `${item.label} — coming later`}
            >
              <span aria-hidden="true">{item.icon}</span>
              {item.label}
              {!item.active && <span className="nav-soon">SOON</span>}
            </button>
          ))}
        </nav>

        <div className="topbar-actions">
          <div className="environment-pill">
            <span className="environment-dot" />
            <span>Development preview</span>
          </div>
          <span className="preview-pill">MOCK MODE</span>
          <a
            className="topbar-link"
            href="https://github.com/sivasreeonline/orbit-engine"
            target="_blank"
            rel="noreferrer"
            aria-label="Open source repository"
          >
            ↗
          </a>
          <div className="profile-avatar" aria-label="Student profile">
            S
          </div>
        </div>
      </header>

      <main className="workspace">
        <div className="workspace-topline">
          <div className="breadcrumb">
            <span>Practice arena</span>
            <span className="breadcrumb-separator">/</span>
            <span>{twoSumProblem.category}</span>
            <span className="breadcrumb-separator">/</span>
            <strong>{twoSumProblem.title}</strong>
          </div>
          <div className="workspace-context-badge">
            <span className="context-badge-dot" />
            CONSOLE INPUT / OUTPUT
          </div>
        </div>

        <section className="page-heading">
          <div className="heading-main">
            <div className="problem-overline">
              <span className="problem-id">{twoSumProblem.id}</span>
              <span className="overline-divider">/</span>
              <span>CODING CHALLENGE</span>
            </div>
            <h1>
              Solve the problem<span className="heading-period">.</span>
            </h1>
            <p>
              Think clearly. Write clean code. Build your problem-solving journey.
            </p>
          </div>
          <div className="heading-meta">
            <span className="difficulty-badge">
              <span className="difficulty-dot" />
              {twoSumProblem.difficulty}
            </span>
            {twoSumProblem.tags.map((tag) => (
              <span className="topic-chip" key={tag}>
                {tag}
              </span>
            ))}
            <span className="sample-count">
              <span className="sample-count-icon">▦</span>
              {twoSumProblem.examples.length} sample cases
            </span>
          </div>
        </section>

        <div
          className={`workspace-grid ${focusMode === "none" ? "" : `focus-${focusMode}-mode`}`.trim()}
        >
          {focusMode !== "editor" && (
            <ProblemDetails
              problem={twoSumProblem}
              activeTab={problemTab}
              onTabChange={setProblemTab}
              isFocused={focusMode === "problem"}
              onFocus={() =>
                setFocusMode((current) =>
                  current === "problem" ? "none" : "problem",
                )
              }
            />
          )}

          {focusMode !== "problem" && (
            <section className="editor-workspace" aria-label="Coding workspace">
              <section className="editor-card" aria-label="Code editor">
                <div className="editor-toolbar">
                  <div className="editor-toolbar-title">
                    <span className="editor-window-mark" aria-hidden="true">
                      <span />
                      <span />
                      <span />
                    </span>
                    <div className="editor-title-copy">
                      <strong>Code workspace</strong>
                      <small>Make your approach count</small>
                    </div>
                  </div>

                  <div className="editor-controls">
                    <label className="language-select-label" htmlFor="language-select">
                      Language
                    </label>
                    <select
                      id="language-select"
                      value={language}
                      onChange={(event) =>
                        setLanguage(event.target.value as SupportedLanguage)
                      }
                      aria-label="Programming language"
                    >
                      <option value="java">Java 25</option>
                      <option value="python">Python 3.14</option>
                    </select>
                    <button
                      className={
                        focusMode === "editor"
                          ? "panel-focus-button active"
                          : "panel-focus-button"
                      }
                      onClick={() =>
                        setFocusMode((current) =>
                          current === "editor" ? "none" : "editor",
                        )
                      }
                      type="button"
                      aria-pressed={focusMode === "editor"}
                    >
                      <span aria-hidden="true">⌘</span>
                      {focusMode === "editor" ? "Exit focus" : "Focus editor"}
                    </button>
                  </div>
                </div>

                <Suspense
                  fallback={
                    <div className="editor-loading" role="status">
                      <span className="loading-spinner" />
                      Preparing editor…
                    </div>
                  }
                >
                  <CodeEditor
                    language={language}
                    value={sourceCode}
                    onChange={updateSource}
                  />
                </Suspense>

                <div className="editor-footer">
                  <span className="editor-footer-language">
                    <span className="footer-language-dot" />
                    {language === "java" ? "Java 25" : "Python 3.14"}
                  </span>
                  <span>UTF-8</span>
                  <span>Spaces: 4</span>
                  <span className="footer-spacer" />
                  <span className="local-edit-label">LOCAL EDITOR STATE</span>
                </div>
              </section>

              <div className="editor-action-dock">
                <button
                  className="reset-button action-reset-button"
                  onClick={resetStarter}
                  type="button"
                >
                  <span aria-hidden="true">↺</span>
                  Reset code
                </button>
                <div className="editor-action-hint">
                  <span className="action-hint-indicator" />
                  <span>Preview only · secure execution is not connected</span>
                </div>
                <div className="editor-run-actions">
                  <button
                    className="editor-run-button"
                    type="button"
                    onClick={() => void handleExecution("RUN")}
                    disabled={pendingAction !== null}
                  >
                    <span aria-hidden="true">▶</span>
                    {pendingAction === "RUN" ? "Preparing…" : "Run"}
                  </button>
                  <button
                    className="editor-submit-button"
                    type="button"
                    onClick={() => void handleExecution("SUBMIT")}
                    disabled={pendingAction !== null}
                  >
                    {pendingAction === "SUBMIT" ? "Preparing…" : "Submit"}
                    <span aria-hidden="true">→</span>
                  </button>
                </div>
              </div>

              {feedback && (
                <div className="execution-feedback" role="status">
                  <span className="feedback-icon">!</span>
                  <div>
                    <strong>{feedback.heading}</strong>
                    <p>{feedback.message}</p>
                    <small>{feedback.details} · MOCK ADAPTER · NO VERDICT</small>
                  </div>
                  <button
                    type="button"
                    className="feedback-dismiss"
                    onClick={() => setFeedback(null)}
                    aria-label="Dismiss execution feedback"
                  >
                    ×
                  </button>
                </div>
              )}
            </section>
          )}

          {focusMode !== "none" && (
            <ExecutionOutput
              problem={twoSumProblem}
              activeTab={outputTab}
              onTabChange={setOutputTab}
              feedback={feedback}
            />
          )}
        </div>

        <footer className="workspace-footer">
          <span>SKY HIGH CODING JUDGE</span>
          <span className="footer-status-dot" />
          <span>Preview environment</span>
          <span className="footer-spacer" />
          <span>Java 25</span>
          <span className="footer-separator">·</span>
          <span>Python 3.14</span>
        </footer>
      </main>
    </div>
  );
}
