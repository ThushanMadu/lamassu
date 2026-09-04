import { describe, expect, it } from "vitest";
import { atOrAbove, countBySeverity, parseThreshold } from "../src/core/threshold.js";
import { SEVERITIES, toSeverity, type Severity, type Vulnerability } from "../src/types.js";

const at = (severity: Severity): Vulnerability => ({
  id: `GHSA-test-${severity}`,
  module: `pkg-${severity}`,
  severity,
  title: `A ${severity} issue`,
  foundVersions: [],
});

const oneOfEach = SEVERITIES.map(at);

describe("parseThreshold", () => {
  it("accepts every severity level", () => {
    for (const s of SEVERITIES) expect(parseThreshold(s)).toBe(s);
  });

  it("defaults to high when nothing is given", () => {
    expect(parseThreshold(undefined)).toBe("high");
  });

  it("is case and whitespace insensitive", () => {
    expect(parseThreshold("  CRITICAL ")).toBe("critical");
  });

  it("rejects an unknown level rather than guessing", () => {
    expect(() => parseThreshold("severe")).toThrow(/unknown severity/);
  });
});

describe("toSeverity", () => {
  it("maps 'medium' onto 'moderate'", () => {
    expect(toSeverity("medium")).toBe("moderate");
  });

  it("falls back to info for anything unrecognised", () => {
    expect(toSeverity(undefined)).toBe("info");
    expect(toSeverity("weird")).toBe("info");
  });
});

describe("atOrAbove", () => {
  it("includes everything at info", () => {
    expect(atOrAbove(oneOfEach, "info")).toHaveLength(5);
  });

  it("includes only critical at critical", () => {
    const found = atOrAbove(oneOfEach, "critical");
    expect(found.map((v) => v.severity)).toEqual(["critical"]);
  });

  it("is inclusive of the threshold itself", () => {
    const found = atOrAbove(oneOfEach, "high");
    expect(found.map((v) => v.severity).sort()).toEqual(["critical", "high"]);
  });

  it("holds at every boundary", () => {
    // At level i, exactly the levels from i upward should survive.
    SEVERITIES.forEach((level, i) => {
      expect(atOrAbove(oneOfEach, level)).toHaveLength(SEVERITIES.length - i);
    });
  });
});

describe("countBySeverity", () => {
  it("counts each level and reports zeroes for the rest", () => {
    expect(countBySeverity([at("high"), at("high"), at("low")])).toEqual({
      info: 0,
      low: 1,
      moderate: 0,
      high: 2,
      critical: 0,
    });
  });
});
