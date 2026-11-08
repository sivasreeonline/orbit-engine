import { useState } from "react";
import type { ProblemDefinition } from "../types/problem";

type GuideTab = "overview" | "constraints" | "hints";
interface ProblemGuideProps { problem: ProblemDefinition; }

const hints = [
  "For a current value x, calculate the partner value needed to reach the target.",
  "Ask whether that partner value has already appeared earlier in the array.",
  "Remember each visited value together with its original index. Check for the partner before storing the current value, so one array element is never used twice.",
];

export default function ProblemGuide({ problem }: ProblemGuideProps) {
  const [activeTab, setActiveTab] = useState<GuideTab>("overview");
  const [revealedHints, setRevealedHints] = useState(0);
  const isHashMapProblem = problem.tags.some((tag) => tag.toLowerCase().includes("hash"));

  return (
    <aside className="problem-guide-panel" aria-label="Problem guide">
      <header className="problem-guide-header">
        <div className="problem-guide-title">
          <span className="problem-guide-icon" aria-hidden="true">✦</span>
          <div><strong>Problem guide</strong><small>Understand the challenge before coding</small></div>
        </div>
        <span className="guide-mode-pill">GUIDED PRACTICE</span>
      </header>

      <div className="problem-guide-tabs" role="tablist" aria-label="Problem guide sections">
        <button className={activeTab === "overview" ? "problem-guide-tab active" : "problem-guide-tab"} type="button" role="tab" aria-selected={activeTab === "overview"} onClick={() => setActiveTab("overview")}>Overview</button>
        <button className={activeTab === "constraints" ? "problem-guide-tab active" : "problem-guide-tab"} type="button" role="tab" aria-selected={activeTab === "constraints"} onClick={() => setActiveTab("constraints")}>Constraints</button>
        <button className={activeTab === "hints" ? "problem-guide-tab active" : "problem-guide-tab"} type="button" role="tab" aria-selected={activeTab === "hints"} onClick={() => setActiveTab("hints")}>Guided hints</button>
      </div>

      <div className="problem-guide-content" role="tabpanel">
        {activeTab === "overview" && (
          <div className="guide-overview">
            <div className="guide-topic-card">
              <span className="guide-eyebrow">TOPIC</span><strong>{problem.category}</strong>
              <div className="guide-tag-row">{problem.tags.map((tag) => <span className="guide-tag" key={tag}>{tag}</span>)}</div>
            </div>
            <div className="guide-section">
              <div className="guide-section-heading"><span className="guide-section-index">01</span><strong>What are you solving?</strong></div>
              <p>Find two distinct elements whose sum equals the target, then return their original zero-based indices.</p>
            </div>
            <div className="guide-section">
              <div className="guide-section-heading"><span className="guide-section-index">02</span><strong>What should you notice?</strong></div>
              <ul><li>The same array element cannot be used twice.</li><li>Negative values are allowed.</li><li>The answer must preserve the original indices.</li></ul>
            </div>
            <div className="guide-callout">
              <span className="guide-callout-icon">◇</span>
              <div><strong>Problem-solving lens</strong><p>{isHashMapProblem ? "Think about the value that completes the target and how to remember values you have already visited." : "Identify what information from earlier elements could help you process the current element."}</p></div>
            </div>
          </div>
        )}

        {activeTab === "constraints" && (
          <div className="guide-constraints">
            <p className="guide-intro">Constraints help you judge which approaches will scale.</p>
            {problem.constraints.map((constraint, index) => (
              <div className="guide-constraint-row" key={constraint}><span>{String(index + 1).padStart(2, "0")}</span><code>{constraint}</code></div>
            ))}
            <div className="guide-callout"><span className="guide-callout-icon">!</span><div><strong>Think about scale</strong><p>With up to 100,000 elements, consider how the number of operations grows as the input gets larger.</p></div></div>
          </div>
        )}

        {activeTab === "hints" && (
          <div className="guide-hints">
            <p className="guide-intro">Reveal one hint at a time. Try to make progress before opening the next.</p>
            {hints.slice(0, revealedHints).map((hint, index) => (
              <article className="guide-hint-card" key={hint}><span>HINT {index + 1}</span><p>{hint}</p></article>
            ))}
            {revealedHints < hints.length ? (
              <button className="reveal-hint-button" type="button" onClick={() => setRevealedHints((count) => Math.min(count + 1, hints.length))}>
                <span aria-hidden="true">＋</span>{revealedHints === 0 ? "Reveal first hint" : "Reveal next hint"}
              </button>
            ) : <p className="hints-complete">All guided hints revealed. Try implementing the idea yourself.</p>}
          </div>
        )}
      </div>
    </aside>
  );
}
