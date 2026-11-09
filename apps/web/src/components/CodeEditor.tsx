import { useEffect, useMemo, useRef, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { java } from "@codemirror/lang-java";
import { python } from "@codemirror/lang-python";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags } from "@lezer/highlight";
import type { SupportedLanguage } from "../types/problem";

interface CodeEditorProps {
  language: SupportedLanguage;
  theme: "dark" | "light";
  value: string;
  onChange: (value: string) => void;
}

export default function CodeEditor({
  language,
  theme,
  value,
  onChange,
}: CodeEditorProps) {
  const pythonHighlighting = useMemo(() => {
    const colors = theme === "dark"
      ? {
          keyword: "#F472B6",
          control: "#FB7185",
          definition: "#C084FC",
          string: "#5EEAD4",
          number: "#FDBA74",
          boolean: "#FBBF24",
          comment: "#94A3B8",
          function: "#60A5FA",
          className: "#FDE047",
          typeName: "#22D3EE",
          variable: "#E2E8F0",
          property: "#F9A8D4",
          operator: "#C4B5FD",
          punctuation: "#A8B5C7",
          meta: "#F0ABFC",
        }
      : {
          keyword: "#A21CAF",
          control: "#BE185D",
          definition: "#7E22CE",
          string: "#047857",
          number: "#C2410C",
          boolean: "#A16207",
          comment: "#7C7182",
          function: "#1D4ED8",
          className: "#8A5B00",
          typeName: "#0F766E",
          variable: "#1F2937",
          property: "#BE185D",
          operator: "#7C3AED",
          punctuation: "#64748B",
          meta: "#A64AC9",
        };

    return syntaxHighlighting(HighlightStyle.define([
      { tag: tags.keyword, color: colors.keyword, fontWeight: "700" },
      { tag: tags.controlKeyword, color: colors.control, fontWeight: "700" },
      { tag: tags.definitionKeyword, color: colors.definition, fontWeight: "700" },
      { tag: tags.operatorKeyword, color: colors.definition, fontWeight: "650" },
      { tag: tags.string, color: colors.string },
      { tag: tags.number, color: colors.number, fontWeight: "650" },
      { tag: tags.bool, color: colors.boolean, fontWeight: "700" },
      { tag: tags.null, color: colors.boolean, fontWeight: "700" },
      { tag: tags.comment, color: colors.comment, fontStyle: "italic" },
      { tag: tags.function(tags.variableName), color: colors.function, fontWeight: "650" },
      { tag: tags.definition(tags.variableName), color: colors.function, fontWeight: "650" },
      { tag: tags.className, color: colors.className, fontWeight: "700" },
      { tag: tags.typeName, color: colors.typeName, fontWeight: "650" },
      { tag: tags.variableName, color: colors.variable },
      { tag: tags.propertyName, color: colors.property },
      { tag: tags.operator, color: colors.operator, fontWeight: "600" },
      { tag: tags.punctuation, color: colors.punctuation },
      { tag: tags.meta, color: colors.meta, fontWeight: "650" },
    ]));
  }, [theme]);

  const extensions = useMemo(
    () => language === "java"
      ? [java()]
      : [python(), pythonHighlighting],
    [language, pythonHighlighting],
  );
  const previousLanguage = useRef(language);
  const [watermarkAnimationId, setWatermarkAnimationId] = useState(0);

  useEffect(() => {
    if (previousLanguage.current !== language) {
      previousLanguage.current = language;
      setWatermarkAnimationId((current) => current + 1);
    }
  }, [language]);

  return (
    <div
      className="code-editor"
      aria-label="Source code editor"
      onKeyDown={(event) => {
        if (event.key === "Enter" && !event.repeat) {
          setWatermarkAnimationId((current) => current + 1);
        }
      }}
    >
      <CodeMirror
        value={value}
        height="100%"
        width="100%"
        theme={theme}
        extensions={extensions}
        onChange={onChange}
        basicSetup={{
          lineNumbers: true,
          foldGutter: true,
          highlightActiveLine: true,
          highlightActiveLineGutter: true,
          tabSize: 4,
        }}
        aria-label={`${language.toUpperCase()} source editor`}
      />
      <svg
        key={watermarkAnimationId}
        className={
          language === "java"
            ? watermarkAnimationId > 0
              ? "editor-language-watermark editor-language-watermark--java is-changing"
              : "editor-language-watermark editor-language-watermark--java"
            : watermarkAnimationId > 0
              ? "editor-language-watermark editor-language-watermark--python is-changing"
              : "editor-language-watermark editor-language-watermark--python"
        }
        viewBox={language === "java" ? "0 0 420 130" : "0 0 620 130"}
        role="img"
        aria-label={`${language.toUpperCase()} watermark`}
        aria-hidden="true"
      >
        <text
          className="watermark-word"
          x="10"
          y="112"
          textLength={language === "java" ? "400" : "600"}
          lengthAdjust="spacingAndGlyphs"
        >
          {language === "java" ? "JAVA" : "PYTHON"}
        </text>
        <g className="watermark-guide-lines">
          {language === "java" ? (
            <>
              <path className="watermark-guide watermark-guide--1" pathLength="1" d="M18 22 L84 22 L84 76 L72 94 L54 104 L30 104" />
              <path className="watermark-guide watermark-guide--2" pathLength="1" d="M112 104 L150 20 L188 104 M128 70 L172 70" />
              <path className="watermark-guide watermark-guide--3" pathLength="1" d="M212 22 L250 104 L288 22" />
              <path className="watermark-guide watermark-guide--4" pathLength="1" d="M312 104 L350 20 L388 104 M328 70 L372 70" />
            </>
          ) : (
            <>
              <path className="watermark-guide watermark-guide--1" pathLength="1" d="M20 106 L20 20 L70 20 L88 34 L88 50 L70 64 L20 64" />
              <path className="watermark-guide watermark-guide--2" pathLength="1" d="M114 20 L150 62 L186 20 M150 62 L150 106" />
              <path className="watermark-guide watermark-guide--3" pathLength="1" d="M214 20 L286 20 M250 20 L250 106" />
              <path className="watermark-guide watermark-guide--4" pathLength="1" d="M320 20 L320 106 M380 20 L380 106 M320 63 L380 63" />
              <path className="watermark-guide watermark-guide--5" pathLength="1" d="M450 20 L475 20 L490 40 L490 86 L475 106 L435 106 L420 86 L420 40 L435 20 Z" />
              <path className="watermark-guide watermark-guide--6" pathLength="1" d="M520 106 L520 20 L580 106 L580 20" />
            </>
          )}
        </g>
      </svg>
    </div>
  );
}
