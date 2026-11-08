import { lazy, Suspense, useState } from "react";
const CodeEditor = lazy(() => import("./components/CodeEditor"));
import ExecutionConsole, {
  type ConsoleTab,
  type FocusMode,
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
  const [consoleTab, setConsoleTab] = useState<ConsoleTab>("output");
  const [feedback, setFeedback] = useState<ExecutionFeedback | null>(null);
  const [pendingAction, setPendingAction] = useState<ExecutionAction | null>(
    null,
  );
  const [focusMode, setFocusMode] = useState<FocusMode>("none");

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

        <div className={`workspace-grid ${focusMode === "none" ? "" : `focus-${focusMode}-mode`}`.trim()}>
          {focusMode !== "editor" && (
            <ProblemDetails
              problem={twoSumProblem}
              activeTab={problemTab}
              onTabChange={setProblemTab}
            />
          )}

          {focusMode !== "problem" && (
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
            </section>
          )}

          <ExecutionConsole
            problem={twoSumProblem}
            activeTab={consoleTab}
            onTabChange={setConsoleTab}
            feedback={feedback}
            focusMode={focusMode}
            onFocusModeChange={setFocusMode}
            onRun={() => void handleExecution("RUN")}
            onSubmit={() => void handleExecution("SUBMIT")}
            pendingAction={pendingAction}
          />
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
