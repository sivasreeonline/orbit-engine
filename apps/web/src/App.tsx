import { lazy, Suspense, useEffect, useState } from "react";
const CodeEditor = lazy(() => import("./components/CodeEditor"));
import EditorActions from "./components/EditorActions";
import ExecutionOutput, { type OutputTab } from "./components/ExecutionOutput";
import ProblemDetails from "./components/ProblemDetails";
import ProblemGuide from "./components/ProblemGuide";
import AmbientDonuts from "./components/AmbientDonuts";
import { twoSumProblem, starterCode } from "./data/twoSumProblem";
import { MockExecutionAdapter } from "./lib/execution/MockExecutionAdapter";
import type { ExecutionAction, ExecutionFeedback } from "./lib/execution/ExecutionAdapter";
import type { SupportedLanguage } from "./types/problem";

type FocusMode = "none" | "editor" | "problem";
const mockAdapter = new MockExecutionAdapter();
const runtimeVersions: Record<SupportedLanguage, string> = { java: "25", python: "3.14" };
const navigationItems = [
  { label: "Practice", icon: "⌘", active: true },
  { label: "Assessments", icon: "▤", active: false },
  { label: "Learning path", icon: "↗", active: false },
  { label: "Bookmarks", icon: "◇", active: false },
];

export default function App() {
  const [language, setLanguage] = useState<SupportedLanguage>("java");
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      return window.localStorage.getItem("sky-high-theme") === "light"
        ? "light"
        : "dark";
    } catch {
      return "dark";
    }
  });
  const [sourceByLanguage, setSourceByLanguage] = useState<Record<SupportedLanguage, string>>(starterCode);
  const [problemTab, setProblemTab] = useState<"description" | "submissions">("description");
  const [focusMode, setFocusMode] = useState<FocusMode>("none");
  const [outputTab, setOutputTab] = useState<OutputTab>("output");
  const [feedback, setFeedback] = useState<ExecutionFeedback | null>(null);
  const [pendingAction, setPendingAction] = useState<ExecutionAction | null>(null);
  const sourceCode = sourceByLanguage[language];

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    try {
      window.localStorage.setItem("sky-high-theme", theme);
    } catch {
      // Theme switching still works for this session when storage is unavailable.
    }
  }, [theme]);

  function toggleTheme() {
    setTheme((current) => (current === "dark" ? "light" : "dark"));
  }

  function updateSource(value: string) {
    setSourceByLanguage((current) => ({ ...current, [language]: value }));
  }

  function resetStarter() {
    setSourceByLanguage((current) => ({ ...current, [language]: starterCode[language] }));
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
      if (focusMode === "none") setFocusMode("editor");
    } catch {
      setFeedback({
        mode: "MOCK",
        state: "NOT_CONNECTED",
        action,
        heading: "Preview adapter unavailable",
        message: "No code was executed and no verdict was produced.",
        details: "The execution integration is not configured in this frontend preview.",
      });
    } finally {
      setPendingAction(null);
    }
  }

  const editorActions = (
    <EditorActions
      onReset={resetStarter}
      onRun={() => void handleExecution("RUN")}
      onSubmit={() => void handleExecution("SUBMIT")}
      pendingAction={pendingAction}
    />
  );

  return (
    <div className="app-shell" data-theme={theme}>
      {theme === "light" && <AmbientDonuts />}
      <header className="topbar">
        <a className="brand" href="/" aria-label="Sky High Coding Judge home">
          <span className="brand-mark" aria-hidden="true"><span /><span /><span /></span>
          <span className="brand-copy"><strong>sky high</strong><small>CODING JUDGE</small></span>
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
              <span aria-hidden="true">{item.icon}</span>{item.label}
              {!item.active && <span className="nav-soon">SOON</span>}
            </button>
          ))}
        </nav>
        <div className="topbar-actions">
          <div className="environment-pill"><span className="environment-dot" /><span>Development preview</span></div>
          <span className="preview-pill">MOCK MODE</span>
          <button
            className="theme-toggle"
            type="button"
            onClick={toggleTheme}
            aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            aria-pressed={theme === "light"}
          >
            {theme === "dark" ? (
              <svg aria-hidden="true" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.65 17.65l1.42 1.42M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.65 6.35l1.42-1.42" />
              </svg>
            ) : (
              <svg aria-hidden="true" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M20.5 14.2A8.5 8.5 0 0 1 9.8 3.5 8.5 8.5 0 1 0 20.5 14.2Z" />
              </svg>
            )}
            <span>{theme === "dark" ? "Light" : "Dark"}</span>
          </button>
          <a className="topbar-link" href="https://github.com/sivasreeonline/orbit-engine" target="_blank" rel="noreferrer" aria-label="Open source repository">↗</a>
          <div className="profile-avatar" aria-label="Student profile">S</div>
        </div>
      </header>

      <main className="workspace">
        <div className="workspace-topline">
          <div className="breadcrumb">
            <span>Practice arena</span><span className="breadcrumb-separator">/</span>
            <span>{twoSumProblem.category}</span><span className="breadcrumb-separator">/</span>
            <strong>{twoSumProblem.title}</strong>
          </div>
          <div className="workspace-context-badge"><span className="context-badge-dot" />CONSOLE INPUT / OUTPUT</div>
        </div>

        <section className="page-heading">
          <div className="heading-main">
            <div className="problem-overline"><span className="problem-id">{twoSumProblem.id}</span><span className="overline-divider">/</span><span>CODING CHALLENGE</span></div>
            <h1>Solve the problem<span className="heading-period">.</span></h1>
            <p>Think clearly. Write clean code. Build your problem-solving journey.</p>
          </div>
          <div className="heading-meta">
            <span className="difficulty-badge"><span className="difficulty-dot" />{twoSumProblem.difficulty}</span>
            {twoSumProblem.tags.map((tag) => <span className="topic-chip" key={tag}>{tag}</span>)}
          </div>
        </section>

        <div className={`workspace-grid ${focusMode === "none" ? "" : `focus-${focusMode}-mode`}`.trim()}>
          {focusMode !== "editor" && (
            <ProblemDetails
              problem={twoSumProblem}
              activeTab={problemTab}
              onTabChange={setProblemTab}
              isFocused={focusMode === "problem"}
              onFocus={() => setFocusMode((current) => current === "problem" ? "none" : "problem")}
            />
          )}

          {focusMode !== "problem" && (
            <section className="editor-workspace" aria-label="Coding workspace">
              <section className="editor-card" aria-label="Code editor">
                <div className="problem-panel-heading editor-panel-heading">
                  <div className="panel-heading-icon" aria-hidden="true">02</div>
                  <div className="panel-heading-copy">
                    <strong>Code workspace</strong>
                    <span>Make your approach count</span>
                  </div>
                  <span className="panel-heading-spacer" />
                  <div className="editor-controls">
                    <label className="language-select-label" htmlFor="language-select">Language</label>
                    <select
                      id="language-select"
                      value={language}
                      onChange={(event) => setLanguage(event.target.value as SupportedLanguage)}
                      aria-label="Programming language"
                    >
                      <option value="java">Java 25</option>
                      <option value="python">Python 3.14</option>
                    </select>
                    <button
                      className={focusMode === "editor" ? "panel-focus-button active" : "panel-focus-button"}
                      onClick={() => setFocusMode((current) => current === "editor" ? "none" : "editor")}
                      type="button"
                      aria-pressed={focusMode === "editor"}
                    >
                      <svg aria-hidden="true" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M8 3H5a2 2 0 0 0-2 2v3" />
                        <path d="M16 3h3a2 2 0 0 1 2 2v3" />
                        <path d="M21 16v3a2 2 0 0 1-2 2h-3" />
                        <path d="M3 16v3a2 2 0 0 0 2 2h3" />
                      </svg>
                      {focusMode === "editor" ? "Exit focus" : "Focus editor"}
                    </button>
                  </div>
                </div>
                <Suspense fallback={<div className="editor-loading" role="status"><span className="loading-spinner" />Preparing editor…</div>}>
                  <CodeEditor language={language} value={sourceCode} onChange={updateSource} theme={theme} />
                </Suspense>
              </section>

              {focusMode === "none" && editorActions}
              {focusMode === "none" && feedback && (
                <div className="execution-feedback" role="status">
                  <span className="feedback-icon">!</span>
                  <div><strong>{feedback.heading}</strong><p>{feedback.message}</p><small>{feedback.details} · MOCK ADAPTER · NO VERDICT</small></div>
                  <button type="button" className="feedback-dismiss" onClick={() => setFeedback(null)} aria-label="Dismiss execution feedback">×</button>
                </div>
              )}
            </section>
          )}

          {focusMode === "editor" && (
            <section className="focus-side-column" aria-label="Execution output and controls">
              <ExecutionOutput problem={twoSumProblem} activeTab={outputTab} onTabChange={setOutputTab} feedback={feedback} />
              {editorActions}
            </section>
          )}

          {focusMode === "problem" && <ProblemGuide problem={twoSumProblem} />}
        </div>

        <footer className="workspace-footer">
          <span>SKY HIGH CODING JUDGE</span><span className="footer-status-dot" /><span>Preview environment</span>
          <span className="footer-spacer" /><span>Java 25</span><span className="footer-separator">·</span><span>Python 3.14</span>
        </footer>
      </main>
    </div>
  );
}
