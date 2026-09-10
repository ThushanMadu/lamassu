import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ConfigError,
  findConfigFile,
  resolveConfig,
  stripJsonComments,
} from "../src/config.js";

const dirs: string[] = [];

function projectWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "lamassu-test-"));
  dirs.push(dir);
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(join(dir, name), contents);
  }
  return dir;
}

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("stripJsonComments", () => {
  it("removes line and block comments", () => {
    const input = `{
      // a line comment
      "severity": "high", /* a block comment */
      "allowlist": []
    }`;
    expect(JSON.parse(stripJsonComments(input))).toEqual({ severity: "high", allowlist: [] });
  });

  it("leaves comment-like text inside strings alone", () => {
    const input = '{"reason": "see http://example.com/x // not a comment"}';
    expect(JSON.parse(stripJsonComments(input)).reason).toBe(
      "see http://example.com/x // not a comment",
    );
  });

  it("handles escaped quotes inside strings", () => {
    const input = '{"reason": "say \\"hi\\" // still a string"}';
    expect(JSON.parse(stripJsonComments(input)).reason).toBe('say "hi" // still a string');
  });

  it("drops trailing commas so VS Code / audit-ci .jsonc files still parse", () => {
    const input = `{
      "severity": "high",
      "allowlist": [
        "GHSA-xxxx-xxxx-xxxx", // last item
      ],
    }`;
    expect(JSON.parse(stripJsonComments(input))).toEqual({
      severity: "high",
      allowlist: ["GHSA-xxxx-xxxx-xxxx"],
    });
  });

  it("does not touch a comma that only looks trailing inside a string", () => {
    const input = '{"note": "a, b, c]"}';
    expect(JSON.parse(stripJsonComments(input)).note).toBe("a, b, c]");
  });
});

describe("native config", () => {
  it("loads lamassu.json", () => {
    const dir = projectWith({ "lamassu.json": '{"severity":"critical","skipDev":true}' });
    const config = resolveConfig({}, dir);
    expect(config.severity).toBe("critical");
    expect(config.skipDev).toBe(true);
  });

  it("loads lamassu.jsonc with comments", () => {
    const dir = projectWith({
      "lamassu.jsonc": '{ // policy\n "severity": "low" }',
    });
    expect(resolveConfig({}, dir).severity).toBe("low");
  });

  it("lets command line options win over the file", () => {
    const dir = projectWith({ "lamassu.json": '{"severity":"low"}' });
    expect(resolveConfig({ severity: "critical" }, dir).severity).toBe("critical");
  });

  it("falls back to defaults when there is no config file", () => {
    const dir = projectWith({});
    expect(resolveConfig({}, dir).severity).toBe("high");
    expect(findConfigFile(dir)).toBeUndefined();
  });

  describe("rejects bad input rather than ignoring it", () => {
    it("an unknown option is probably a typo", () => {
      const dir = projectWith({ "lamassu.json": '{"severty":"high"}' });
      expect(() => resolveConfig({}, dir)).toThrow(ConfigError);
    });

    it("an unparseable expiry date would otherwise never expire", () => {
      const dir = projectWith({
        "lamassu.json": '{"allowlist":[{"id":"GHSA-x","expires":"next tuesday"}]}',
      });
      expect(() => resolveConfig({}, dir)).toThrow(/not a valid date/);
    });

    /** Number(true) is 1, so a boolean would silently become a 1s timeout. */
    it("a boolean timeout is not a number", () => {
      const dir = projectWith({ "lamassu.json": '{"timeoutSeconds": true}' });
      expect(() => resolveConfig({}, dir)).toThrow(/must be a positive number/);
    });

    it("a string timeout is not a number", () => {
      const dir = projectWith({ "lamassu.json": '{"timeoutSeconds": "300"}' });
      expect(() => resolveConfig({}, dir)).toThrow(/must be a positive number/);
    });

    it("a timeout beyond Node's timer range would fire immediately", () => {
      const dir = projectWith({ "lamassu.json": '{"timeoutSeconds": 99999999999}' });
      expect(() => resolveConfig({}, dir)).toThrow(/at most/);
    });

    it("accepts a sensible numeric timeout", () => {
      const dir = projectWith({ "lamassu.json": '{"timeoutSeconds": 600}' });
      expect(resolveConfig({}, dir).timeoutSeconds).toBe(600);
    });

    it("malformed JSON", () => {
      const dir = projectWith({ "lamassu.json": "{ not json" });
      expect(() => resolveConfig({}, dir)).toThrow(/could not parse/);
    });

    it("an allowlist that is not an array", () => {
      const dir = projectWith({ "lamassu.json": '{"allowlist":"GHSA-x"}' });
      expect(() => resolveConfig({}, dir)).toThrow(/must be an array/);
    });
  });
});

/**
 * The people most likely to want lamassu are those currently blocked on
 * audit-ci, so an unchanged audit-ci config must keep working.
 */
describe("audit-ci compatibility", () => {
  it("translates the severity booleans", () => {
    const dir = projectWith({ "audit-ci.json": '{"moderate":true}' });
    expect(resolveConfig({}, dir).severity).toBe("moderate");
  });

  it("takes the lowest level when several booleans are set", () => {
    const dir = projectWith({ "audit-ci.json": '{"low":true,"high":true}' });
    expect(resolveConfig({}, dir).severity).toBe("low");
  });

  it("reads a real-world audit-ci.jsonc unchanged", () => {
    const dir = projectWith({
      "audit-ci.jsonc": `{
        // config copied straight from a working project
        "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
        "moderate": true,
        "package-manager": "pnpm",
        "report-type": "full",
        "skip-dev": true,
        "allowlist": ["GHSA-35jh-r3h4-6jhm"]
      }`,
    });
    const config = resolveConfig({}, dir);
    expect(config.severity).toBe("moderate");
    expect(config.packageManager).toBe("pnpm");
    expect(config.skipDev).toBe(true);
    expect(config.allowlist).toEqual(["GHSA-35jh-r3h4-6jhm"]);
  });

  it("announces compatibility mode", () => {
    const dir = projectWith({ "audit-ci.json": '{"high":true}' });
    const notices: string[] = [];
    resolveConfig({}, dir, (m) => notices.push(m));
    expect(notices[0]).toMatch(/audit-ci compatibility mode/);
  });

  it("suggests scoping for bare allowlist entries", () => {
    const dir = projectWith({
      "audit-ci.json": '{"high":true,"allowlist":["GHSA-35jh-r3h4-6jhm"]}',
    });
    const notices: string[] = [];
    resolveConfig({}, dir, (m) => notices.push(m));
    expect(notices.join("\n")).toMatch(/Scope them as/);
  });

  it("flips audit-ci's `GHSA-id|package` scoped entries into lamassu order", () => {
    const dir = projectWith({
      "audit-ci.json": '{"high":true,"allowlist":["GHSA-35jh-r3h4-6jhm|lodash"]}',
    });
    // audit-ci puts the advisory first; lamassu's parseEntry reads
    // `package|GHSA-id`, so an unflipped entry could never match.
    expect(resolveConfig({}, dir).allowlist).toEqual(["lodash|GHSA-35jh-r3h4-6jhm"]);
  });

  it("reports audit-ci path and wildcard allowlist entries it cannot express", () => {
    const dir = projectWith({
      "audit-ci.json": JSON.stringify({
        high: true,
        allowlist: ["GHSA-35jh-r3h4-6jhm|react-scripts>svgo>nth-check", "*|@scope/pkg>*"],
      }),
    });
    const notices: string[] = [];
    const config = resolveConfig({}, dir, (m) => notices.push(m));
    // Not silently shipped as dead entries...
    expect(config.allowlist).toEqual([]);
    // ...and the user is told, by name.
    expect(notices.join("\n")).toMatch(/path or wildcard syntax/);
    expect(notices.join("\n")).toMatch(/nth-check/);
  });

  it("warns about options with no equivalent instead of failing", () => {
    const dir = projectWith({ "audit-ci.json": '{"high":true,"retry-count":5}' });
    const notices: string[] = [];
    const config = resolveConfig({}, dir, (m) => notices.push(m));
    expect(config.severity).toBe("high");
    expect(notices.join("\n")).toMatch(/retry-count/);
  });

  it("prefers a native config when both exist", () => {
    const dir = projectWith({
      "lamassu.json": '{"severity":"critical"}',
      "audit-ci.json": '{"low":true}',
    });
    expect(findConfigFile(dir)?.kind).toBe("native");
    expect(resolveConfig({}, dir).severity).toBe("critical");
  });
});
