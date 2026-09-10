import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { PackageManager } from "../types.js";

export interface RunOptions {
  cwd: string;
  /** Exclude devDependencies from the audit. */
  skipDev?: boolean;
  timeoutMs?: number;
}

export class AuditCommandError extends Error {
  constructor(message: string, readonly stderr: string, readonly code: number | null) {
    super(message);
  }
}

/**
 * Whether `spawn` needs a shell to run `npm`/`yarn`/`pnpm`/`bun` on this platform.
 *
 * On Windows, npm/yarn/pnpm resolve via PATH to `.cmd` shims, not native `.exe`
 * files. Node's fix for CVE-2024-27980 makes `spawn` refuse to run a `.cmd`/
 * `.bat` target without `shell: true` - it throws EINVAL immediately, on every
 * Node version this package's `engines` field permits. Without this, lamassu
 * cannot audit an npm, Yarn, or pnpm project on Windows at all.
 *
 * This is safe to do unconditionally on win32: every element that ever reaches
 * `args` is a fixed string literal chosen by `auditArgs()`'s switch statement
 * (never user- or file-controlled), so routing through a shell adds no
 * injection surface. Do not add a dynamic argument here without re-checking
 * that reasoning.
 */
export function shouldUseShell(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32";
}

/**
 * Resolve a bare command to an absolute path, searching PATH only - never the
 * current directory.
 *
 * `shell: true` on Windows routes the spawn through `cmd.exe`, and `cmd.exe`
 * searches the *current directory before PATH*. Audits run with `cwd` set to a
 * project we do not control (a cloned repo, an untrusted PR branch), so a
 * repository that ships its own `npm.cmd` / `yarn.cmd` / `pnpm.cmd` / `bun.cmd`
 * in its root could otherwise run in place of the real tool - arbitrary code
 * execution on whoever ran `lamassu` (CWE-426, untrusted search path).
 *
 * Resolving to an absolute path here defeats that: `cmd.exe` performs no search
 * when handed one. POSIX needs nothing - `spawn` with `shell: false` there
 * resolves bare names via execvp/PATH and never consults the cwd - so this is a
 * no-op off win32. If nothing is found we return the bare name unchanged: the
 * spawn then behaves exactly as before this guard (and fails with a clear
 * ENOENT if the tool genuinely is not installed), never worse.
 */
export function resolveExecutable(
  command: string,
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (platform !== "win32") return command;

  // `;` unconditionally: this branch only runs for win32, and `path.delimiter`
  // would be `:` when the tests exercise it from a POSIX host.
  const extensions = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  const pathDirs = (env.PATH ?? "").split(";").filter(Boolean);

  for (const dir of pathDirs) {
    for (const extension of ["", ...extensions]) {
      const candidate = join(dir, command + extension);
      if (existsSync(candidate)) return candidate;
    }
  }
  return command;
}

/** Yarn changed its audit command at v2, so we need the major version. */
async function yarnMajor(cwd: string): Promise<number> {
  try {
    const { stdout } = await exec("yarn", ["--version"], { cwd, timeoutMs: 30_000 });
    return Number.parseInt(stdout.trim().split(".")[0] ?? "1", 10) || 1;
  } catch {
    return 1;
  }
}

export async function auditArgs(
  pm: PackageManager,
  options: RunOptions,
): Promise<{ command: string; args: string[] }> {
  const { skipDev } = options;
  switch (pm) {
    case "npm":
      return { command: "npm", args: ["audit", "--json", ...(skipDev ? ["--omit=dev"] : [])] };
    case "pnpm":
      return { command: "pnpm", args: ["audit", "--json", ...(skipDev ? ["--prod"] : [])] };
    case "bun":
      return { command: "bun", args: ["audit", "--json"] };
    case "yarn": {
      const major = await yarnMajor(options.cwd);
      if (major >= 2) {
        // Berry. `--recursive` walks transitive dependencies, which is the
        // whole point of an audit; Yarn 4 emits its tree report here.
        return {
          command: "yarn",
          args: [
            "npm", "audit", "--json", "--recursive",
            ...(skipDev ? ["--environment", "production"] : []),
          ],
        };
      }
      return {
        command: "yarn",
        args: ["audit", "--json", ...(skipDev ? ["--groups", "dependencies"] : [])],
      };
    }
  }
}

function exec(
  command: string,
  args: string[],
  opts: { cwd: string; timeoutMs: number },
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    const useShell = shouldUseShell();
    const resolved = resolveExecutable(command);
    // With `shell: true`, Node joins `[file, ...args]` with spaces and does not
    // quote the file, so an absolute path containing a space (the usual
    // `C:\Program Files\nodejs\npm.cmd`) would be split by cmd.exe. Quoting it
    // here survives cmd.exe's `/s` handling, which strips exactly one outer
    // pair of quotes. Harmless when the path has no space or is the bare
    // fallback name. `args` are all fixed literals from `auditArgs()` - see
    // `shouldUseShell()` - so they need no quoting.
    const file = useShell ? `"${resolved}"` : resolved;

    const child = spawn(file, args, {
      cwd: opts.cwd,
      shell: useShell,
      // Yarn applies its own 60s network timeout, which is well below ours and
      // makes it give up on a slow registry before we would. Raise Yarn's to
      // match, so one timeout governs instead of two disagreeing ones.
      env: { ...process.env, YARN_HTTP_TIMEOUT: String(opts.timeoutMs) },
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new AuditCommandError(`\`${command}\` timed out after ${opts.timeoutMs}ms`, stderr, null));
    }, opts.timeoutMs);

    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(
        err.code === "ENOENT"
          ? new AuditCommandError(`\`${command}\` is not installed or not on PATH`, stderr, null)
          : new AuditCommandError(`failed to run \`${command}\`: ${err.message}`, stderr, null),
      );
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
  });
}

/**
 * Run the audit and hand back raw stdout.
 *
 * Every package manager exits non-zero when it finds vulnerabilities, so a
 * non-zero code is expected and must not be treated as failure. We only fail
 * when there is no usable output at all.
 */
export async function runAudit(pm: PackageManager, options: RunOptions): Promise<string> {
  const { command, args } = await auditArgs(pm, options);
  const { stdout, stderr, code } = await exec(command, args, {
    cwd: options.cwd,
    timeoutMs: options.timeoutMs ?? 300_000,
  });
  if (!stdout.trim()) {
    throw new AuditCommandError(
      `\`${command} ${args.join(" ")}\` produced no output (exit code ${code}).`,
      stderr,
      code,
    );
  }
  return stdout;
}
