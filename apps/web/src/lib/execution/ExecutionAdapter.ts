import type { SupportedLanguage } from "../../types/problem";

export type ExecutionAction = "RUN" | "SUBMIT";

export interface ExecutionRequest {
  problemId: string;
  problemVersion: string;
  language: SupportedLanguage;
  runtimeVersion: string;
  action: ExecutionAction;
  sourceCode: string;
}

export interface ExecutionFeedback {
  mode: "MOCK";
  state: "NOT_CONNECTED";
  action: ExecutionAction;
  heading: string;
  message: string;
  details: string;
}

export interface ExecutionAdapter {
  execute(request: ExecutionRequest): Promise<ExecutionFeedback>;
}
