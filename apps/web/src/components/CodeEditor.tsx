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
      <span
        key={watermarkAnimationId}
        className={
          watermarkAnimationId > 0
            ? "editor-language-watermark is-changing"
            : "editor-language-watermark"
        }
        aria-hidden="true"
      >
        {language === "java" ? "JAVA" : "PYTHON"}
      </span>
    </div>
  );
}
