import { describe, expect, it } from "vitest";
import {
  diffSourceSnapshots,
  SourceDiffLimitError,
  splitSourceLines,
} from "./execution-source-diff";

describe("splitSourceLines", () => {
  it("preserves LF, CRLF, lone CR and an unterminated final line", () => {
    expect(splitSourceLines("one\r\ntwo\nthree\rfour")).toEqual([
      "one\r\n", "two\n", "three\r", "four",
    ]);
  });

  it("returns no lines for an empty source and preserves a final newline", () => {
    expect(splitSourceLines("")).toEqual([]);
    expect(splitSourceLines("one\n")).toEqual(["one\n"]);
  });
});

describe("diffSourceSnapshots", () => {
  it("marks identical source as equal", () => {
    const result = diffSourceSnapshots("a\nβ\n", "a\nβ\n");
    expect(result.operations.map((item) => item.kind)).toEqual(["EQUAL", "EQUAL"]);
    expect(result.equalLineCount).toBe(2);
    expect(result.insertedLineCount).toBe(0);
    expect(result.deletedLineCount).toBe(0);
  });

  it("represents insertions and deletions with stable line numbers", () => {
    const result = diffSourceSnapshots("first\nremoved\nlast\n", "first\nadded\nlast\n");
    expect(result.operations).toEqual([
      { kind: "EQUAL", text: "first\n", baseLine: 1, targetLine: 1 },
      { kind: "DELETE", text: "removed\n", baseLine: 2, targetLine: null },
      { kind: "INSERT", text: "added\n", baseLine: null, targetLine: 2 },
      { kind: "EQUAL", text: "last\n", baseLine: 3, targetLine: 3 },
    ]);
  });

  it("preserves CRLF versus LF, whitespace, Unicode and final-newline changes", () => {
    const result = diffSourceSnapshots("  café\r\nend", " café\nend\n");
    expect(result.operations.map((item) => item.kind)).toEqual([
      "DELETE", "DELETE", "INSERT", "INSERT",
    ]);
    expect(result.operations.map((item) => item.text)).toEqual([
      "  café\r\n", "end", " café\n", "end\n",
    ]);
  });

  it("handles empty source on either side", () => {
    expect(diffSourceSnapshots("", "new\n").operations).toEqual([
      { kind: "INSERT", text: "new\n", baseLine: null, targetLine: 1 },
    ]);
    expect(diffSourceSnapshots("old\n", "").operations).toEqual([
      { kind: "DELETE", text: "old\n", baseLine: 1, targetLine: null },
    ]);
  });

  it("uses a deterministic delete-first tie break for repeated lines", () => {
    const first = diffSourceSnapshots("x\nx\n", "x\n");
    const second = diffSourceSnapshots("x\nx\n", "x\n");
    expect(first).toEqual(second);
  });

  it("rejects source over the byte limit", () => {
    expect(() => diffSourceSnapshots("é", "é", {
      maxSourceBytes: 1, maxLines: 10, maxCells: 100,
    })).toThrowError(SourceDiffLimitError);
  });

  it("rejects source over the line limit", () => {
    expect(() => diffSourceSnapshots("a\nb", "a\nb", {
      maxSourceBytes: 100, maxLines: 1, maxCells: 100,
    })).toThrowError(SourceDiffLimitError);
  });

  it("rejects comparisons that exceed the quadratic work budget", () => {
    expect(() => diffSourceSnapshots("a\nb", "a\nb", {
      maxSourceBytes: 100, maxLines: 10, maxCells: 8,
    })).toThrowError(SourceDiffLimitError);
  });
});