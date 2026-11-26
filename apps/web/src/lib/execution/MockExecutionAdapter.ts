import type {
  ExecutionAdapter,
  ExecutionFeedback,
  ExecutionRequest,
} from "./ExecutionAdapter";

/**
 * UI-only adapter for M1 frontend development.
 *
 * This adapter deliberately does not execute, evaluate, transmit, save, or log
 * student source code. It must be replaced by the authenticated asynchronous
 * API adapter only after the M0 runner security gates pass.
 */
export class MockExecutionAdapter implements ExecutionAdapter {
  async execute(request: ExecutionRequest): Promise<ExecutionFeedback> {
    const isRun = request.action === "RUN";

    return {
      mode: "MOCK",
      state: "NOT_CONNECTED",
      action: request.action,
      heading: "Execution service not connected",
      message: isRun
        ? "Run is not available in this preview. Your code was not executed."
        : "Submit is not available in this preview. No verdict or score was produced.",
      details:
        "The student workspace is connected only to a local preview adapter. The M0 isolated runner and authenticated Sky High API have not been connected.",
    };
  }
}
