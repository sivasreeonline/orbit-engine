import { lazy, Suspense, useState } from "react";
const CodeEditor = lazy(() => import("./components/CodeEditor"));
import ExecutionConsole, {
  type ConsoleTab,
} from "./components/ExecutionConsole";
import ProblemDetails from "./components/ProblemDetails";
import { twoSumProblem, starterCode } from "./data/twoSumProblem";
import {
  MockExecutionAdapter,
} from "./lib/execution/MockExecutionAdapter";
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
  { label: "My progress", icon: "⌁", active: false },
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
  const editorLanguage = language;

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
          <span className="environment-dot" />
          <span>Development preview</span>
          <span className="preview-pill">MOCK MODE</span>
        </div>

        <div className="topbar-actions">
          <a
            className="topbar-link"
            href="https://github.com/sivasreeonline/orbit-engine"
            target="_blank"
            rel="noreferrer"
          >
            Repository <span aria-hidden="true">↗</span>
          </a>
          <div className="profile-avatar" aria-label="Student profile">
            S
          </div>
        </div>
      </header>

      <div className="app-frame">
        <aside className="sidebar" aria-label="Main navigation">
          <div className="sidebar-section-label">WORKSPACE</div>
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
              </button>
            ))}
          </nav>

          <div className="sidebar-bottom">
            <div className="sidebar-divider" />
            <div className="sidebar-help">
              <span className="help-mark">?</span>
              <span>Help centre</span>
            </div>
            <div className="sidebar-version">BUILD 0.1.0</div>
          </div>
        </aside>

        <main className="workspace">
          <div className="breadcrumb">
            <span>Practice</span>
            <span className="breadcrumb-separator">/</span>
            <span>{twoSumProblem.category}</span>
            <span className="breadcrumb-separator">/</span>
            <strong>{twoSumProblem.title}</strong>
          </div>

          <section className="page-heading">
            <div>
              <div className="problem-overline">
                <span className="problem-id">{twoSumProblem.id}</span>
                <span className="overline-divider">·</span>
                <span>CODING PROBLEM</span>
              </div>
              <h1>{twoSumProblem.title}</h1>
              <p>{twoSumProblem.summary}</p>
            </div>
            <div className="heading-meta">
              <span className="difficulty-badge">{twoSumProblem.difficulty}</span>
              {twoSumProblem.tags.map((tag) => (
                <span className="topic-chip" key={tag}>
                  {tag}
                </span>
              ))}
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
                  <div className="editor-file">
                    <span className="file-icon" aria-hidden="true">
                      {language === "java" ? "J" : "Py"}
                    </span>
                    <span>{language === "java" ? "Main.java" : "main.py"}</span>
                    <span className="file-dot" aria-label="Unsaved local edits" />
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
                    <button className="reset-button" onClick={resetStarter} type="button">
                      Reset
                    </button>
                  </div>
                </div>

                <Suspense fallback={<div className="editor-loading" role="status">Loading code editor…</div>}>
                  <CodeEditor
                    language={editorLanguage}
                    value={sourceCode}
                    onChange={updateSource}
                  />
                </Suspense>

                <div className="editor-footer">
                  <span>UTF-8</span>
                  <span>Spaces: 4</span>
                  <span>{language === "java" ? "Java 25" : "Python 3.14"}</span>
                  <span className="footer-spacer" />
                  <span className="local-edit-label">LOCAL EDITOR STATE</span>
                </div>

                <div className="action-bar">
                  <div className="action-hint">
                    <span className="hint-key">i</span>
                    <span>Preview actions only · execution is not connected</span>
                  </div>
                  <div className="action-buttons">
                    <button
                      className="run-button"
                      type="button"
                      onClick={() => void handleExecution("RUN")}
                      disabled={pendingAction !== null}
                    >
                      <span aria-hidden="true">▶</span>
                      {pendingAction === "RUN" ? "Preparing…" : "Run"}
                    </button>
                    <button
                      className="submit-button"
                      type="button"
                      onClick={() => void handleExecution("SUBMIT")}
                      disabled={pendingAction !== null}
                    >
                      {pendingAction === "SUBMIT" ? "Preparing…" : "Submit"}
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
            <span>Sky High Coding Judge</span>
            <span>Execution adapter: mock</span>
            <span>No source code is sent to a server in this preview.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
