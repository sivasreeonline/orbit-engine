import { lazy, Suspense, useState } from "react";
const CodeEditor = lazy(() => import("./components/CodeEditor"));
import ExecutionConsole, {
  type ConsoleTab,
} from "./components/ExecutionConsole";
import ProblemDetails from "./components/ProblemDetails";
import { twoSumProblem, starterCode } from "./data/twoSumProblem";
import { MockExecutionAdapter } from "./lib/execution/MockExecutionAdapter";
import type {
  ExecutionAction,
  ExecutionFeedback,
} from "./lib/execution/ExecutionAdapter";
import type { SupportedLanguage } from "./types/problem";

const mockAdapter = new MockExecutionAdapter();

const runtimeVersions: Record<SupportedLanguage, string> = {
  java: "25",
  python: "3.14",
};

const navigationItems = [
  { label: "Practice", icon: "⌘", active: true },
  { label: "Assessments", icon: "▤", active: false },
  { label: "My progress", icon: "↗", active: false },
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
  const [consoleTab, setConsoleTab] = useState<ConsoleTab>("output");
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
    setConsoleTab("output");

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

        <div className="topbar-center">
          <div className="topbar-context">
            <span className="topbar-kicker">STUDENT WORKSPACE</span>
            <strong>Problem-solving studio</strong>
          </div>
          <span className="topbar-divider" />
          <span className="environment-pill">
            <span className="environment-dot" />
            Development preview
          </span>
          <span className="preview-pill">MOCK MODE</span>
        </div>

        <div className="topbar-actions">
          <a
            className="topbar-link"
            href="https://github.com/sivasreeonline/orbit-engine"
            target="_blank"
            rel="noreferrer"
          >
            <span className="topbar-link-icon">↗</span>
            Repository
          </a>
          <div className="profile-avatar" aria-label="Student profile">
            S
          </div>
        </div>
      </header>

      <div className="app-frame">
        <aside className="sidebar" aria-label="Main navigation">
          <div className="sidebar-top">
            <div className="sidebar-section-label">LEARNING SPACE</div>
            <nav className="sidebar-nav">
              {navigationItems.map((item) => (
                <button
                  className={item.active ? "nav-item active" : "nav-item"}
                  key={item.label}
                  type="button"
                  aria-current={item.active ? "page" : undefined}
                  disabled={!item.active}
                  title={item.active ? item.label : `${item.label} — coming later`}
                >
                  <span className="nav-icon" aria-hidden="true">
                    {item.icon}
                  </span>
                  <span className="nav-label">{item.label}</span>
                  {!item.active && <span className="nav-item-soon">SOON</span>}
                </button>
              ))}
            </nav>
          </div>

          <div className="sidebar-bottom">
            <div className="sidebar-runner-card">
              <div className="runner-card-top">
                <span className="runner-status-dot" />
                <span>EXECUTION ENGINE</span>
              </div>
              <strong>Not connected</strong>
              <p>The secure runner is being prepared.</p>
              <span className="runner-card-mode">PREVIEW ENVIRONMENT</span>
            </div>
            <a
              className="sidebar-help"
              href="https://github.com/sivasreeonline/orbit-engine"
              target="_blank"
              rel="noreferrer"
            >
              <span className="help-mark">?</span>
              <span>Help & documentation</span>
            </a>
            <div className="sidebar-version">SKY HIGH · BUILD 0.1.0</div>
          </div>
        </aside>

        <main className="workspace">
          <div className="workspace-topline">
            <div className="breadcrumb">
              <span>Practice</span>
              <span className="breadcrumb-separator">/</span>
              <span>{twoSumProblem.category}</span>
              <span className="breadcrumb-separator">/</span>
              <strong>{twoSumProblem.title}</strong>
            </div>
            <div className="workspace-context-badge">
              <span className="context-badge-dot" />
              CONSOLE I/O CHALLENGE
            </div>
          </div>

          <section className="page-heading">
            <div className="heading-main">
              <div className="problem-overline">
                <span className="problem-id">{twoSumProblem.id}</span>
                <span className="overline-divider">/</span>
                <span>ARRAYS & HASHING</span>
              </div>
              <h1>{twoSumProblem.title}</h1>
              <p>{twoSumProblem.summary}</p>
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

          <div className="workspace-grid">
            <ProblemDetails
              problem={twoSumProblem}
              activeTab={problemTab}
              onTabChange={setProblemTab}
            />

            <div className="editor-column">
              <section className="editor-card" aria-label="Code editor">
                <div className="editor-toolbar">
                  <div className="editor-toolbar-title">
                    <span className="editor-window-mark">
                      <span />
                      <span />
                      <span />
                    </span>
                    <div>
                      <strong>Solution workspace</strong>
                      <small>Write, review and refine your approach</small>
                    </div>
                  </div>

                  <div className="editor-controls">
                    <div className="editor-file">
                      <span className="file-icon" aria-hidden="true">
                        {language === "java" ? "J" : "Py"}
                      </span>
                      <span>{language === "java" ? "Main.java" : "main.py"}</span>
                      <span className="file-dot" aria-label="Local editor state" />
                    </div>
                    <span className="toolbar-divider" />
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
                    <button className="reset-button" onClick={resetStarter} type="button">
                      Reset code
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

                <div className="action-bar">
                  <div className="action-hint">
                    <span className="hint-key">i</span>
                    <span>Preview only · code execution is not connected</span>
                  </div>
                  <div className="action-buttons">
                    <button
                      className="run-button"
                      type="button"
                      onClick={() => void handleExecution("RUN")}
                      disabled={pendingAction !== null}
                    >
                      <span aria-hidden="true">▶</span>
                      {pendingAction === "RUN" ? "Preparing…" : "Run code"}
                    </button>
                    <button
                      className="submit-button"
                      type="button"
                      onClick={() => void handleExecution("SUBMIT")}
                      disabled={pendingAction !== null}
                    >
                      {pendingAction === "SUBMIT" ? "Preparing…" : "Submit solution"}
                      <span aria-hidden="true">→</span>
                    </button>
                  </div>
                </div>
              </section>

              <ExecutionConsole
                problem={twoSumProblem}
                activeTab={consoleTab}
                onTabChange={setConsoleTab}
                feedback={feedback}
              />
            </div>
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
    </div>
  );
}
