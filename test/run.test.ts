import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Regression coverage for the Windows spawn bug: on win32, npm/yarn/pnpm
 * resolve to `.cmd` shims, and Node's CVE-2024-27980 fix makes `spawn` refuse
 * to run them without `shell: true`. Before this file, `runAudit`/`exec` had
 * zero direct test coverage anywhere - every other test mocks the whole
 * module away (see cli.test.ts) - so this exact class of bug shipped
 * invisibly. These tests exercise the real `exec()` path.
 */

const { shouldUseShell } = await import("../src/managers/run.js");

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
