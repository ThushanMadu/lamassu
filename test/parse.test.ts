import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditParseError, parseAuditOutput } from "../src/core/parse.js";
import type { Vulnerability } from "../src/types.js";

const fixture = (name: string) =>
  readFileSync(join(import.meta.dirname, "fixtures", name), "utf8");

/**
 * Every fixture describes the same two advisories in a different package
 * manager's format. If normalisation works, they must all come out the same.
 */
const FORMATS = {
  "npm 7+ (auditReportVersion 2)": "npm-v2.json",
  "advisories map (npm 6, pnpm, Yarn 2-3, Bun)": "advisories-v1.json",
  "Yarn 1 NDJSON": "yarn1.ndjson",
  "Yarn 4 tree report NDJSON": "yarn4-tree.ndjson",
  "Yarn 4 --recursive map": "yarn4-recursive.json",
} as const;

const byModule = (list: Vulnerability[]) =>
  Object.fromEntries(list.map((v) => [v.module, v]));

describe("parseAuditOutput", () => {
  describe("recognises every known format", () => {
    for (const [label, file] of Object.entries(FORMATS)) {
      it(label, () => {
        const found = parseAuditOutput(fixture(file));
        expect(found).toHaveLength(2);
        expect(found.map((v) => v.module).sort()).toEqual(["lodash", "minimist"]);
      });
    }
  });

  /**
   * The central promise of the package: whichever package manager produced the
   * report, the same vulnerability normalises to the same record.
   */
  it("normalises all five formats to the same advisories", () => {
    const results = Object.values(FORMATS).map((f) => byModule(parseAuditOutput(fixture(f))));

    for (const result of results) {
      expect(result.lodash).toMatchObject({
        id: "GHSA-35JH-R3H4-6JHM",
        module: "lodash",
        severity: "high",
        title: "Command Injection in lodash",
        url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
      });
      expect(result.minimist).toMatchObject({
        id: "GHSA-VH95-RMGR-6W4M",
        module: "minimist",
        severity: "moderate",
        title: "Prototype Pollution in minimist",
      });
    }
  });

  it("keys findings on the GHSA id, not the package manager's numeric id", () => {
    for (const file of Object.values(FORMATS)) {
      for (const v of parseAuditOutput(fixture(file))) {
        expect(v.id).toMatch(/^GHSA-/);
      }
    }
  });

  it("reports resolved versions when the format provides them", () => {
    // npm v2 reports affected ranges and install paths but never the resolved
    // version, so it is the one format that legitimately has none.
    for (const file of ["advisories-v1.json", "yarn1.ndjson", "yarn4-tree.ndjson", "yarn4-recursive.json"]) {
      const found = byModule(parseAuditOutput(fixture(file)));
      expect(found.lodash!.foundVersions, file).toContain("4.17.15");
      expect(found.minimist!.foundVersions, file).toContain("1.2.0");
    }
    expect(byModule(parseAuditOutput(fixture("npm-v2.json"))).lodash!.foundVersions).toEqual([]);
  });

  describe("refuses to guess", () => {
    /**
     * The worst possible failure for a security gate is silently reporting
     * "no vulnerabilities" because it could not understand the output. Every
     * unrecognised input must throw instead.
     */
    it("throws on output that is not JSON at all", () => {
      expect(() => parseAuditOutput(fixture("not-json.txt"))).toThrow(AuditParseError);
    });

    it("throws on empty output", () => {
      expect(() => parseAuditOutput("")).toThrow(AuditParseError);
      expect(() => parseAuditOutput("   \n  ")).toThrow(AuditParseError);
    });

    it("throws on a JSON document in no known shape", () => {
      expect(() => parseAuditOutput('{"totally":"unexpected"}')).toThrow(AuditParseError);
    });

    it("throws on a JSON array", () => {
      expect(() => parseAuditOutput("[1,2,3]")).toThrow(AuditParseError);
    });

    /**
     * Regression: any parseable NDJSON stream that no parser recognised was
     * reported as a clean audit. A package manager changing its line format
     * could therefore hide every vulnerability while exiting 0.
     */
    it("throws on NDJSON in an unknown format rather than reporting clean", () => {
      const ndjson = '{"totally":"unexpected"}\n{"totally":"unexpected"}';
      expect(() => parseAuditOutput(ndjson)).toThrow(AuditParseError);
    });

    it("throws when a summary claims findings we could not parse", () => {
      // Saying "3 high" while presenting no parseable advisories is a parse
      // failure, not an empty result.
      const doc = JSON.stringify({
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 3, critical: 0 } },
      });
      expect(() => parseAuditOutput(doc)).toThrow(AuditParseError);
    });

    /**
     * Observed with Yarn 4 on a slow connection: Yarn's own 60s network timeout
     * fires, it prints a stack trace where JSON was expected, and the user is
     * told the *format* was unrecognised - sending them after a parser bug that
     * does not exist. Say what actually happened instead.
     */
    it("recognises a package manager error and says so", () => {
      const yarnTimeout = [
        "➤ YN0001: RequestError: Timeout awaiting 'socket' for 60000ms",
        "    at ClientRequest.<anonymous> (/Users/x/.cache/node/corepack/v1/yarn/4.9.1/yarn.js:147:14230)",
      ].join("\n");
      expect(() => parseAuditOutput(yarnTimeout)).toThrow(/reported an error instead of audit results/);
      expect(() => parseAuditOutput(yarnTimeout)).toThrow(/--timeout/);
    });

    it("includes what it actually received, so the failure is diagnosable", () => {
      expect(() => parseAuditOutput('{"totally":"unexpected"}')).toThrow(/totally/);
      expect(() => parseAuditOutput('{"totally":"unexpected"}')).toThrow(/LAMASSU_DUMP_RAW/);
    });
  });

  describe("clean reports need positive evidence", () => {
    it("accepts an npm summary that reports zero findings", () => {
      expect(parseAuditOutput(fixture("npm-clean.json"))).toEqual([]);
    });

    it("accepts a Yarn 1 summary that reports zero findings", () => {
      const clean = JSON.stringify({
        type: "auditSummary",
        data: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 } },
      });
      expect(parseAuditOutput(`${clean}\n`)).toEqual([]);
    });

    it("rejects a Yarn 1 summary that reports findings but lists none", () => {
      const inconsistent = JSON.stringify({
        type: "auditSummary",
        data: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 2, critical: 0 } },
      });
      expect(() => parseAuditOutput(`${inconsistent}\n`)).toThrow(AuditParseError);
    });

    it("accepts an empty advisories map", () => {
      expect(parseAuditOutput('{"advisories":{},"metadata":{}}')).toEqual([]);
    });
  });

  /**
   * Regression: findings were sorted by comparing the severity *strings*, which
   * orders them alphabetically - moderate, low, high, critical - putting the
   * most dangerous finding at the bottom of the report. Caught by a live
   * `npm audit`, not by fixtures, which held only two adjacent severities.
   */
  it("orders findings most severe first", () => {
    const doc = {
      advisories: Object.fromEntries(
        [
          ["low", "GHSA-xhjh-pmcv-23jw"],
          ["critical", "GHSA-xvch-5gv4-984h"],
          ["moderate", "GHSA-vh95-rmgr-6w4m"],
          ["high", "GHSA-35jh-r3h4-6jhm"],
          ["info", "GHSA-p6mc-m468-83gw"],
        ].map(([severity, ghsa], i) => [
          String(i),
          {
            id: i,
            github_advisory_id: ghsa,
            module_name: `pkg-${severity}`,
            severity,
            title: `${severity} issue`,
            findings: [],
          },
        ]),
      ),
    };
    const order = parseAuditOutput(JSON.stringify(doc)).map((v) => v.severity);
    expect(order).toEqual(["critical", "high", "moderate", "low", "info"]);
  });

  /**
   * Captured from a real `yarn npm audit --json --recursive` on Yarn 4.9.1.
   * The hand-written Yarn 4 fixture above was reconstructed from documentation;
   * this one is what the tool actually emits, at realistic volume.
   */
  describe("real Yarn 4.9.1 output", () => {
    const real = () => parseAuditOutput(fixture("yarn4-real-4.9.1.ndjson"));

    it("parses all 33 advisories", () => {
      expect(real()).toHaveLength(33);
    });

    it("finds every direct dependency", () => {
      expect([...new Set(real().map((v) => v.module))].sort()).toEqual([
        "axios",
        "lodash",
        "minimist",
      ]);
    });

    it("orders most severe first", () => {
      const found = real();
      expect(found[0]!.severity).toBe("critical");
      expect(found.at(-1)!.severity).toBe("low");
    });

    it("captures resolved versions, which npm's format cannot provide", () => {
      expect(real().every((v) => v.foundVersions.length > 0)).toBe(true);
    });

    it("agrees with npm on the same project", () => {
      // npm reported the same 33 advisories for this fixture. Two entirely
      // different output formats must normalise to the same answer, or the
      // package's central claim does not hold.
      const counts = real().reduce<Record<string, number>>((acc, v) => {
        acc[v.severity] = (acc[v.severity] ?? 0) + 1;
        return acc;
      }, {});
      expect(counts).toEqual({ critical: 1, high: 14, moderate: 17, low: 1 });
    });
  });

  it("de-duplicates the same advisory reported under several packages", () => {
    const doc = JSON.parse(fixture("advisories-v1.json"));
    doc.advisories["9999"] = {
      ...doc.advisories["1097130"],
      id: 9999,
      findings: [{ version: "4.17.11", paths: ["a>lodash"] }],
    };
    const found = parseAuditOutput(JSON.stringify(doc));
    expect(found).toHaveLength(2);
    // Both resolved versions survive the merge.
    expect(found.find((v) => v.module === "lodash")!.foundVersions.sort()).toEqual([
      "4.17.11",
      "4.17.15",
    ]);
  });
});
