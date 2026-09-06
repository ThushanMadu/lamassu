import { spawn } from "node:child_process";
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
    const child = spawn(command, args, {
      cwd: opts.cwd,
      shell: false,
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
