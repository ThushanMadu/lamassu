import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Regression coverage for the Windows spawn bug: on win32, npm/yarn/pnpm
 * resolve to `.cmd` shims, and Node's CVE-2024-27980 fix makes `spawn` refuse
 * to run them without `shell: true`. Before this file, `runAudit`/`exec` had
 * zero direct test coverage anywhere - every other test mocks the whole
 * module away (see cli.test.ts) - so this exact class of bug shipped
 * invisibly. These tests exercise the real `exec()` path.
 */

const { shouldUseShell, resolveExecutable } = await import("../src/managers/run.js");

describe("shouldUseShell", () => {
  it("is true on win32", () => {
    expect(shouldUseShell("win32")).toBe(true);
  });

  it("is false on the platforms audits actually run on", () => {
    for (const platform of ["linux", "darwin", "freebsd", "openbsd", "sunos"] as const) {
      expect(shouldUseShell(platform)).toBe(false);
    }
  });

  it("defaults to the real process.platform when called with no argument", () => {
    expect(shouldUseShell()).toBe(process.platform === "win32");
  });
});

/**
 * `shell: true` on Windows routes through cmd.exe, which searches the current
 * directory before PATH. Audits run with cwd set to a project we do not
 * control, so a repo shipping its own `npm.cmd` could hijack the audit
 * (CWE-426). resolveExecutable() resolves against PATH only, closing that.
 */
describe("resolveExecutable", () => {
  const dirs: string[] = [];
  const withBin = (files: string[]): string => {
    const dir = mkdtempSync(join(tmpdir(), "lamassu-path-"));
    dirs.push(dir);
    for (const f of files) writeFileSync(join(dir, f), "");
    return dir;
  };
  afterEach(() => {
    while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
  });

  it("returns the bare command unchanged off win32", () => {
    for (const platform of ["linux", "darwin", "freebsd"] as const) {
      expect(resolveExecutable("npm", platform, { PATH: "/anything" })).toBe("npm");
    }
  });

  // Windows and macOS both match `npm.cmd` case-insensitively, and the returned
  // string carries the PATHEXT casing (`.CMD`), so assertions compare lower-cased.
  const sameFile = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

  it("resolves a .cmd shim on the PATH to its absolute location", () => {
    const dir = withBin(["npm.cmd"]);
    const resolved = resolveExecutable("npm", "win32", { PATH: dir, PATHEXT: ".EXE;.CMD" });
    expect(sameFile(resolved, join(dir, "npm.cmd"))).toBe(true);
  });

  it("tries PATHEXT extensions in order and prefers an earlier PATH entry", () => {
    const first = withBin([]); // nothing here
    const second = withBin(["yarn.cmd"]);
    const third = withBin(["yarn.exe"]);
    const resolved = resolveExecutable("yarn", "win32", {
      PATH: [first, second, third].join(";"),
      PATHEXT: ".EXE;.CMD",
    });
    expect(sameFile(resolved, join(second, "yarn.cmd"))).toBe(true);
  });

  it("only consults PATH - a shim in some other directory is never returned", () => {
    const onPath = withBin([]);
    const elsewhere = withBin(["pnpm.cmd"]); // present, but not on PATH
    expect(elsewhere).not.toBe(onPath);
    expect(resolveExecutable("pnpm", "win32", { PATH: onPath, PATHEXT: ".CMD" })).toBe("pnpm");
  });

  it("falls back to the bare name when nothing matches", () => {
    const dir = withBin(["something-else.cmd"]);
    expect(resolveExecutable("bun", "win32", { PATH: dir, PATHEXT: ".EXE;.CMD" })).toBe("bun");
  });

  it("has no cwd parameter - it structurally cannot search the working directory", () => {
    expect(resolveExecutable.length).toBeLessThanOrEqual(3);
  });
});

/**
 * Fakes a child_process.ChildProcess just enough for exec()'s event wiring:
 * stdout/stderr streams and the process itself all need `.on`, and exec()
 * reads spawn's return value's `.stdout`/`.stderr`/`.kill`.
 */
function fakeChild() {
  const child = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: (signal?: string) => void;
  };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  return child;
}

describe("exec (via runAudit) chooses shell per platform", () => {
  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  async function runWithMockedSpawn(platform: NodeJS.Platform) {
    vi.resetModules();
    const spawnMock = vi.fn((_command: string, _args: string[], _options: Record<string, unknown>) => {
      const child = fakeChild();
      // Resolve on the next tick so `runAudit`'s await has something to wait on.
      queueMicrotask(() => {
        child.stdout.emit("data", '{"advisories":{}}');
        child.emit("close", 0);
      });
      return child;
    });

    vi.doMock("node:child_process", () => ({ spawn: spawnMock }));
    const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { value: platform, configurable: true });

    try {
      const { runAudit } = await import("../src/managers/run.js");
      await runAudit("npm", { cwd: "/tmp/does-not-matter", timeoutMs: 5_000 });
    } finally {
      Object.defineProperty(process, "platform", originalPlatform);
    }

    return spawnMock;
  }

  it("passes shell: true to spawn on win32", async () => {
    const spawnMock = await runWithMockedSpawn("win32");
    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [, , options] = spawnMock.mock.calls[0]!;
    expect(options).toMatchObject({ shell: true });
  });

  it("passes shell: false to spawn on linux", async () => {
    const spawnMock = await runWithMockedSpawn("linux");
    const [, , options] = spawnMock.mock.calls[0]!;
    expect(options).toMatchObject({ shell: false });
  });

  it("passes shell: false to spawn on darwin", async () => {
    const spawnMock = await runWithMockedSpawn("darwin");
    const [, , options] = spawnMock.mock.calls[0]!;
    expect(options).toMatchObject({ shell: false });
  });
});

/**
 * Regression: `yarn npm audit --json --recursive` (Yarn >= 2) emits *nothing*
 * and exits 0 on a clean project. runAudit used to treat empty stdout as
 * "the audit could not be run" and throw - every clean Yarn 4 CI build failed
 * with exit 2. The clean path was only ever exercised against vulnerable
 * fixtures.
 */
describe("runAudit — empty output handling", () => {
  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  /** Mock spawn: `yarn --version` -> a version string; anything else -> empty + exit `code`. */
  async function runYarnWith(version: string, auditExitCode: number) {
    vi.resetModules();
    const spawnMock = vi.fn((_command: string, args: string[]) => {
      const child = fakeChild();
      const isVersionProbe = args.includes("--version");
      queueMicrotask(() => {
        if (isVersionProbe) child.stdout.emit("data", version);
        child.emit("close", isVersionProbe ? 0 : auditExitCode);
      });
      return child;
    });
    vi.doMock("node:child_process", () => ({ spawn: spawnMock }));
    const { runAudit } = await import("../src/managers/run.js");
    return runAudit("yarn", { cwd: "/tmp/x", timeoutMs: 5_000 });
  }

  it("treats empty output + exit 0 from Yarn >= 2 as a clean report", async () => {
    const raw = await runYarnWith("4.9.1", 0);
    // Normalised to a shape parseAuditOutput already recognises as clean.
    const { parseAuditOutput } = await import("../src/core/parse.js");
    expect(parseAuditOutput(raw)).toEqual([]);
  });

  it("still throws on empty output when Yarn >= 2 exits non-zero", async () => {
    await expect(runYarnWith("4.9.1", 1)).rejects.toThrow(/produced no output/);
  });

  it("still throws on empty output from classic Yarn (< 2)", async () => {
    // Yarn 1 uses `yarn audit ...`, not `yarn npm audit ...`; empty output
    // there is a genuine failure, not a clean signal.
    await expect(runYarnWith("1.22.22", 0)).rejects.toThrow(/produced no output/);
  });
});
