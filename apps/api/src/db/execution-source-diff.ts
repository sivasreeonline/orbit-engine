export type SourceDiffOperationKind = "EQUAL" | "INSERT" | "DELETE";

export interface SourceDiffOperation {
  readonly kind: SourceDiffOperationKind;
  readonly text: string;
  readonly baseLine: number | null;
  readonly targetLine: number | null;
}

export interface SourceDiffResult {
  readonly operations: readonly SourceDiffOperation[];
  readonly baseLineCount: number;
  readonly targetLineCount: number;
  readonly equalLineCount: number;
  readonly insertedLineCount: number;
  readonly deletedLineCount: number;
}

export class SourceDiffLimitError extends Error {
  constructor(readonly limit: "SOURCE_BYTES" | "LINE_COUNT" | "WORK_BUDGET") {
    super("source_diff_limit_exceeded");
    this.name = "SourceDiffLimitError";
  }
}

export interface SourceDiffLimits {
  readonly maxSourceBytes: number;
  readonly maxLines: number;
  readonly maxCells: number;
}

export const DEFAULT_SOURCE_DIFF_LIMITS: SourceDiffLimits = {
  maxSourceBytes: 128 * 1024,
  maxLines: 4_000,
  maxCells: 4_000_000,
};

/**
 * Split source into newline-preserving line tokens. A final unterminated line
 * remains distinct from the same text followed by LF or CRLF.
 */
export function splitSourceLines(source: string): string[] {
  if (source.length === 0) return [];

  const lines: string[] = [];
  let start = 0;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === "\n") {
      lines.push(source.slice(start, index + 1));
      start = index + 1;
    } else if (char === "\r") {
      if (source[index + 1] === "\n") {
        lines.push(source.slice(start, index + 2));
        index += 1;
        start = index + 1;
      } else {
        lines.push(source.slice(start, index + 1));
        start = index + 1;
      }
    }
  }

  if (start < source.length) lines.push(source.slice(start));
  return lines;
}

/**
 * Deterministic line diff using a bounded LCS matrix.
 * Ties prefer DELETE before INSERT, giving stable output for repeated lines.
 * The matrix allocation is bounded before any quadratic work begins.
 */
export function diffSourceSnapshots(
  baseSource: string,
  targetSource: string,
  limits: SourceDiffLimits = DEFAULT_SOURCE_DIFF_LIMITS,
): SourceDiffResult {
  const encoder = new TextEncoder();
  if (
    encoder.encode(baseSource).byteLength > limits.maxSourceBytes ||
    encoder.encode(targetSource).byteLength > limits.maxSourceBytes
  ) {
    throw new SourceDiffLimitError("SOURCE_BYTES");
  }

  const base = splitSourceLines(baseSource);
  const target = splitSourceLines(targetSource);

  if (base.length > limits.maxLines || target.length > limits.maxLines) {
    throw new SourceDiffLimitError("LINE_COUNT");
  }

  const rows = base.length + 1;
  const columns = target.length + 1;
  const cells = rows * columns;
  if (!Number.isSafeInteger(cells) || cells > limits.maxCells) {
    throw new SourceDiffLimitError("WORK_BUDGET");
  }

  const lcs = new Uint32Array(cells);
  const at = (row: number, column: number): number => row * columns + column;

  for (let row = base.length - 1; row >= 0; row -= 1) {
    for (let column = target.length - 1; column >= 0; column -= 1) {
      const index = at(row, column);
      if (base[row] === target[column]) {
        lcs[index] = 1 + lcs[at(row + 1, column + 1)]!;
      } else {
        lcs[index] = Math.max(
          lcs[at(row + 1, column)]!,
          lcs[at(row, column + 1)]!,
        );
      }
    }
  }

  const operations: SourceDiffOperation[] = [];
  let baseIndex = 0;
  let targetIndex = 0;
  let equalLineCount = 0;
  let insertedLineCount = 0;
  let deletedLineCount = 0;

  while (baseIndex < base.length || targetIndex < target.length) {
    if (
      baseIndex < base.length &&
      targetIndex < target.length &&
      base[baseIndex] === target[targetIndex]
    ) {
      operations.push({
        kind: "EQUAL",
        text: base[baseIndex]!,
        baseLine: baseIndex + 1,
        targetLine: targetIndex + 1,
      });
      baseIndex += 1;
      targetIndex += 1;
      equalLineCount += 1;
      continue;
    }

    const deleteScore = baseIndex < base.length
      ? lcs[at(baseIndex + 1, targetIndex)]!
      : -1;
    const insertScore = targetIndex < target.length
      ? lcs[at(baseIndex, targetIndex + 1)]!
      : -1;

    if (baseIndex < base.length && (targetIndex >= target.length || deleteScore >= insertScore)) {
      operations.push({
        kind: "DELETE",
        text: base[baseIndex]!,
        baseLine: baseIndex + 1,
        targetLine: null,
      });
      baseIndex += 1;
      deletedLineCount += 1;
    } else {
      operations.push({
        kind: "INSERT",
        text: target[targetIndex]!,
        baseLine: null,
        targetLine: targetIndex + 1,
      });
      targetIndex += 1;
      insertedLineCount += 1;
    }
  }

  return {
    operations,
    baseLineCount: base.length,
    targetLineCount: target.length,
    equalLineCount,
    insertedLineCount,
    deletedLineCount,
  };
}
