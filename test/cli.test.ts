import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const auditOutput = vi.hoisted(() => ({ current: "" , error: null as Error | null }));

vi.mock("../src/managers/run.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/managers/run.js")>();
  return {
    ...actual,
    runAudit: vi.fn(async () => {
      if (auditOutput.error) throw auditOutput.error;
      return auditOutput.current;
    }),
  };
});

const { main } = await import("../src/cli.js");
const { AuditCommandError } = await import("../src/managers/run.js");

const fixture = (name: string) =>
  readFileSync(join(import.meta.dirname, "fixtures", name), "utf8");

function sink() {
  const chunks: string[] = [];
  return {
    stream: { write: (s: string) => (chunks.push(s), true) } as unknown as NodeJS.WritableStream,
    text: () => chunks.join(""),
  };
}

const dirs: string[] = [];
function project(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "lamassu-cli-"));
  dirs.push(dir);
  writeFileSync(join(dir, "package.json"), '{"name":"t","version":"1.0.0"}');
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

async function run(argv: string[]) {
  const out = sink();
  const err = sink();
  const code = await main(argv, { out: out.stream, err: err.stream });
  return { code, out: out.text(), err: err.text() };
}

beforeEach(() => {
  auditOutput.current = fixture("npm-clean.json");
  auditOutput.error = null;
});

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
  vi.clearAllMocks();
});

describe("exit codes", () => {
  it("0 when nothing is found at or above the threshold", async () => {
    const { code } = await run(["-d", project()]);
    expect(code).toBe(0);
  });

  it("1 when vulnerabilities are found", async () => {
    auditOutput.current = fixture("npm-v2.json");
    const { code, out } = await run(["-d", project()]);
    expect(code).toBe(1);
    expect(out).toContain("lodash");
  });

  it("0 when the threshold is raised above everything found", async () => {
    auditOutput.current = fixture("npm-v2.json");
    const { code } = await run(["-d", project(), "--severity", "critical"]);
    expect(code).toBe(0);
  });

  it("1 when the threshold is lowered to include a moderate finding", async () => {
    auditOutput.current = fixture("npm-v2.json");
    const { code } = await run(["-d", project(), "--severity", "moderate"]);
    expect(code).toBe(1);
  });

  /**
   * The most important behaviour in the package. A gate that cannot run must
   * never look like a gate that passed.
   */
  describe("2, never 0, when the audit cannot be trusted", () => {
    it("when the package manager printed an error instead of results", async () => {
      auditOutput.current = fixture("not-json.txt");
      const { code, err } = await run(["-d", project()]);
      expect(code).toBe(2);
      expect(err).toMatch(/reported an error instead of audit results/);
      // The user should see what the package manager actually said.
      expect(err).toMatch(/ENETUNREACH/);
    });

    it("on output in a genuinely unknown format", async () => {
      auditOutput.current = '{"some":"shape we do not know"}';
      const { code, err } = await run(["-d", project()]);
      expect(code).toBe(2);
      expect(err).toMatch(/could not recognise/);
    });

    it("on empty audit output", async () => {
      auditOutput.current = "";
      expect((await run(["-d", project()])).code).toBe(2);
    });

    it("when the package manager is missing", async () => {
      auditOutput.error = new AuditCommandError("`pnpm` is not installed or not on PATH", "", null);
      const { code, err } = await run(["-d", project()]);
      expect(code).toBe(2);
      expect(err).toMatch(/not installed/);
    });

    it("on a broken config file", async () => {
      const dir = project({ "lamassu.json": "{ not json" });
      const { code, err } = await run(["-d", dir]);
      expect(code).toBe(2);
      expect(err).toMatch(/config error/);
    });

    it("on an unknown command line option", async () => {
      const { code, err } = await run(["--wat"]);
      expect(code).toBe(2);
      expect(err).toMatch(/unknown option/);
    });

    it("on an invalid severity", async () => {
      const { code } = await run(["--severity", "severe"]);
      expect(code).toBe(2);
    });

    it("on a non-numeric timeout", async () => {
      const { code, err } = await run(["--timeout", "soon"]);
      expect(code).toBe(2);
      expect(err).toMatch(/positive number of seconds/);
    });

    it("on a zero or negative timeout", async () => {
      expect((await run(["--timeout", "0"])).code).toBe(2);
    });

    it("on a timeout beyond Node's timer range", async () => {
      // Larger than a 32-bit millisecond counter, which would make the timer
      // fire immediately and kill the audit the instant it started.
      const { code, err } = await run(["--timeout", "99999999999"]);
      expect(code).toBe(2);
      expect(err).toMatch(/at most/);
    });

    it("on a flag that is missing its value", async () => {
      const { code, err } = await run(["--severity"]);
      expect(code).toBe(2);
      expect(err).toMatch(/requires a value/);
    });
  });
});

describe("--fail-unused", () => {
  it("passes by default when an allowlist entry is dead", async () => {
    const dir = project({ "lamassu.json": '{"allowlist":["GHSA-vh95-rmgr-6w4m"]}' });
    const { code, out } = await run(["-d", dir]);
    expect(code).toBe(0);
    expect(out).toMatch(/matched nothing/);
  });

  it("fails when asked to enforce it", async () => {
    const dir = project({ "lamassu.json": '{"allowlist":["GHSA-vh95-rmgr-6w4m"]}' });
    expect((await run(["-d", dir, "--fail-unused"])).code).toBe(1);
  });
});

describe("output", () => {
  it("--output json writes machine-readable output to stdout", async () => {
    auditOutput.current = fixture("npm-v2.json");
    const { code, out } = await run(["-d", project(), "-o", "json"]);
    expect(code).toBe(1);
    const parsed = JSON.parse(out);
    expect(parsed.passed).toBe(false);
    expect(parsed.counts.high).toBe(1);
    expect(parsed.vulnerabilities).toHaveLength(1);
  });

  it("keeps stdout parseable when compatibility notices are printed", async () => {
    auditOutput.current = fixture("npm-v2.json");
    const dir = project({ "audit-ci.json": '{"high":true}' });
    const { out, err } = await run(["-d", dir, "-o", "json"]);
    expect(() => JSON.parse(out)).not.toThrow();
    expect(err).toMatch(/compatibility mode/);
  });

  it("prints a ready-to-paste allowlist line for each finding", async () => {
    auditOutput.current = fixture("npm-v2.json");
    const { out } = await run(["-d", project(), "--no-color"]);
    expect(out).toContain("lodash|GHSA-35JH-R3H4-6JHM");
  });

  it("emits no colour codes with --no-color", async () => {
    auditOutput.current = fixture("npm-v2.json");
    const { out } = await run(["-d", project(), "--no-color"]);
    expect(out).not.toContain("[");
  });
});

describe("help and version", () => {
  it("--help exits 0 and describes the exit codes", async () => {
    const { code, out } = await run(["--help"]);
    expect(code).toBe(0);
    expect(out).toContain("Exit codes");
  });

  it("--version exits 0", async () => {
    const { code, out } = await run(["--version"]);
    expect(code).toBe(0);
    expect(out.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
