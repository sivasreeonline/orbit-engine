export type SupportedLanguage = "java" | "python";

export interface ProblemExample {
  id: number;
  input: string;
  output: string;
  explanation: string;
}

export interface ProblemDefinition {
  id: string;
  title: string;
  difficulty: "Easy" | "Medium" | "Hard";
  category: string;
  tags: string[];
  summary: string;
  statement: string;
  inputFormat: string[];
  outputFormat: string;
  constraints: string[];
  examples: ProblemExample[];
}
