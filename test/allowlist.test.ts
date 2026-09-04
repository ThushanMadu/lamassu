import { describe, expect, it } from "vitest";
import { applyAllowlist, parseEntry } from "../src/core/allowlist.js";
import type { Vulnerability } from "../src/types.js";

const vuln = (over: Partial<Vulnerability> = {}): Vulnerability => ({
  id: "GHSA-35JH-R3H4-6JHM",
  module: "lodash",
  severity: "high",
  title: "Command Injection in lodash",
  foundVersions: ["4.17.15"],
  ...over,
});

describe("parseEntry", () => {
  it("reads a bare advisory id", () => {
    expect(parseEntry("GHSA-35jh-r3h4-6jhm")).toEqual({ id: "GHSA-35jh-r3h4-6jhm" });
  });

  it("reads a package-scoped entry", () => {
    expect(parseEntry("lodash|GHSA-35jh-r3h4-6jhm")).toEqual({
      id: "GHSA-35jh-r3h4-6jhm",
      module: "lodash",
    });
  });

  it("reads a version-scoped entry", () => {
    expect(parseEntry("lodash@4.17.15|GHSA-35jh-r3h4-6jhm")).toEqual({
      id: "GHSA-35jh-r3h4-6jhm",
      module: "lodash",
      version: "4.17.15",
    });
  });

  it("does not mistake a scoped package name for a version", () => {
    expect(parseEntry("@babel/core|GHSA-35jh-r3h4-6jhm")).toEqual({
      id: "GHSA-35jh-r3h4-6jhm",
      module: "@babel/core",
    });
  });

  it("reads a scoped package with a version", () => {
    expect(parseEntry("@babel/core@7.0.0|GHSA-35jh-r3h4-6jhm")).toEqual({
      id: "GHSA-35jh-r3h4-6jhm",
      module: "@babel/core",
      version: "7.0.0",
    });
  });
});

describe("applyAllowlist", () => {
  it("suppresses a matching bare id", () => {
    const result = applyAllowlist([vuln()], ["GHSA-35jh-r3h4-6jhm"]);
    expect(result.remaining).toHaveLength(0);
    expect(result.suppressed).toHaveLength(1);
  });

  it("matches case-insensitively", () => {
    expect(applyAllowlist([vuln()], ["ghsa-35jh-r3h4-6jhm"]).remaining).toHaveLength(0);
  });

  it("also accepts the numeric advisory id", () => {
    const v = vuln({ source: 1097130 });
    expect(applyAllowlist([v], ["1097130"]).remaining).toHaveLength(0);
  });

  /**
   * audit-ci's defect (IBM/audit-ci#356): a bare id there suppresses the
   * advisory wherever it appears, so an entry written for one package silently
   * absorbs the same advisory surfacing somewhere else. Scoping fixes that.
   */
  describe("scoping prevents over-matching", () => {
    it("a package-scoped entry does not suppress the same advisory elsewhere", () => {
      const elsewhere = vuln({ module: "other-package" });
      const result = applyAllowlist([elsewhere], ["lodash|GHSA-35jh-r3h4-6jhm"]);
      expect(result.remaining).toHaveLength(1);
      expect(result.suppressed).toHaveLength(0);
    });

    it("a version-scoped entry does not suppress a different installed version", () => {
      const other = vuln({ foundVersions: ["4.17.20"] });
      const result = applyAllowlist([other], ["lodash@4.17.15|GHSA-35jh-r3h4-6jhm"]);
      expect(result.remaining).toHaveLength(1);
    });

    it("a version-scoped entry suppresses the version it names", () => {
      const result = applyAllowlist([vuln()], ["lodash@4.17.15|GHSA-35jh-r3h4-6jhm"]);
      expect(result.remaining).toHaveLength(0);
    });
  });

  describe("expiry", () => {
    const rule = { id: "GHSA-35jh-r3h4-6jhm", expires: "2026-01-01" };

    it("suppresses before the expiry date", () => {
      const result = applyAllowlist([vuln()], [rule], new Date("2025-12-31"));
      expect(result.remaining).toHaveLength(0);
      expect(result.expired).toHaveLength(0);
    });

    it("stops suppressing after the expiry date, and says so", () => {
      const result = applyAllowlist([vuln()], [rule], new Date("2026-06-01"));
      expect(result.remaining).toHaveLength(1);
      expect(result.expired).toHaveLength(1);
    });
  });

  describe("unused entries", () => {
    it("reports an entry that matched nothing", () => {
      const result = applyAllowlist([vuln()], [
        "GHSA-35jh-r3h4-6jhm",
        "GHSA-vh95-rmgr-6w4m",
      ]);
      expect(result.remaining).toHaveLength(0);
      expect(result.unused).toHaveLength(1);
      expect(result.unused[0]!.id).toBe("GHSA-vh95-rmgr-6w4m");
    });

    it("does not report an entry that did match", () => {
      expect(applyAllowlist([vuln()], ["GHSA-35jh-r3h4-6jhm"]).unused).toHaveLength(0);
    });

    it("counts an expired entry as expired, not unused", () => {
      const result = applyAllowlist(
        [vuln()],
        [{ id: "GHSA-35jh-r3h4-6jhm", expires: "2020-01-01" }],
        new Date("2026-01-01"),
      );
      expect(result.expired).toHaveLength(1);
      expect(result.unused).toHaveLength(0);
    });
  });

  it("leaves everything alone when the allowlist is empty", () => {
    const result = applyAllowlist([vuln(), vuln({ module: "minimist" })], []);
    expect(result.remaining).toHaveLength(2);
    expect(result.unused).toHaveLength(0);
  });
});
