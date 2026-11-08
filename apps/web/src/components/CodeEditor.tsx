import { useMemo } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { java } from "@codemirror/lang-java";
import { python } from "@codemirror/lang-python";
import type { SupportedLanguage } from "../types/problem";

interface CodeEditorProps {
  language: SupportedLanguage;
  value: string;
  onChange: (value: string) => void;
}

export default function CodeEditor({
  language,
  value,
  onChange,
}: CodeEditorProps) {
  const extensions = useMemo(
    () => [language === "java" ? java() : python()],
    [language],
  );

  return (
    <div className="code-editor" aria-label="Source code editor">
      <CodeMirror
        value={value}
        height="100%"
        width="100%"
        theme="dark"
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
    </div>
  );
}
