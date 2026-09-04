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

  it("treats a clean report as no vulnerabilities", () => {
    expect(parseAuditOutput(fixture("npm-clean.json"))).toEqual([]);
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
