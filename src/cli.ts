#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { audit } from "./index.js";
import { ConfigError, resolveConfig, type Config } from "./config.js";
import { AuditParseError } from "./core/parse.js";
import { AuditCommandError } from "./managers/run.js";
import { parseThreshold } from "./core/threshold.js";
import { MAX_TIMEOUT_SECONDS } from "./types.js";
import { renderJsonReport } from "./report/json.js";
import { renderTextReport, shouldUseColour } from "./report/text.js";

/**
 * Read the version from package.json rather than hard-coding it. `npm version`
 * bumps the manifest and nothing else, so a literal here silently drifts one
 * release after the first bump.
 *
 * The relative path resolves the same from `src/cli.ts` and from `dist/cli.js`,
 * since both sit one directory below the package root.
 */
const require = createRequire(import.meta.url);
export const VERSION: string = (require("../package.json") as { version: string }).version;

const HELP = `bartizan - the guardian at your gate

Fails your build when dependencies have known vulnerabilities.

Usage
  bartizan [options]

Options
  -s, --severity <level>    Lowest severity that fails the build:
                            info, low, moderate, high, critical.  (default: high)
  -p, --package-manager <m> auto, npm, yarn, pnpm, bun            (default: auto)
  -d, --directory <path>    Project directory.                    (default: cwd)
      --skip-dev            Ignore devDependencies.
      --fail-unused         Fail when an allowlist entry matched nothing.
  -o, --output <format>     text or json.                         (default: text)
      --timeout <seconds>   Seconds to wait for the audit.        (default: 300)
      --no-color            Disable colour. NO_COLOR is honoured too.
  -h, --help                Show this help.
  -v, --version             Show the version.

Config
  Reads bartizan.json / bartizan.jsonc from the project directory. An existing
  audit-ci.json / audit-ci.jsonc is read too, so migrating needs no config
  changes. Command line options win over the config file.

    {
      "severity": "high",
      "allowlist": [
        "GHSA-xxxx-xxxx-xxxx",                  // this advisory anywhere
        "lodash|GHSA-xxxx-xxxx-xxxx",           // only when it is lodash
        "lodash@4.17.15|GHSA-xxxx-xxxx-xxxx",   // only that version
        {
          "id": "GHSA-yyyy-yyyy-yyyy",
          "module": "axios",
          "expires": "2026-12-31",
          "reason": "no fix released yet; tracked in JIRA-123"
        }
      ]
    }

Exit codes
  0   passed
  1   vulnerabilities found at or above the threshold
  2   the audit could not be run - never treat this as a pass
`;

export interface ParsedArgs {
  overrides: Partial<Config>;
  directory: string;
  help: boolean;
  version: boolean;
  /** undefined means "decide from the environment". */
  colour: boolean | undefined;
}

const PACKAGE_MANAGERS = ["auto", "npm", "yarn", "pnpm", "bun"];

export function parseArgs(argv: string[]): ParsedArgs {
  const overrides: Partial<Config> = {};
  let directory = process.cwd();
  let help = false;
  let version = false;
  let colour: boolean | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("-")) {
        throw new ConfigError(`${arg} requires a value`);
      }
      return v;
    };

    switch (arg) {
      case "-h": case "--help": help = true; break;
      case "-v": case "--version": version = true; break;
      case "-s": case "--severity": overrides.severity = parseThreshold(value()); break;
      case "-d": case "--directory": directory = resolve(value()); break;
      case "--skip-dev": overrides.skipDev = true; break;
      case "--timeout": {
        const seconds = Number(value());
        if (!Number.isFinite(seconds) || seconds <= 0) {
          throw new ConfigError("--timeout must be a positive number of seconds");
        }
        if (seconds > MAX_TIMEOUT_SECONDS) {
          throw new ConfigError(`--timeout must be at most ${MAX_TIMEOUT_SECONDS} seconds`);
        }
        overrides.timeoutSeconds = seconds;
        break;
      }
      case "--fail-unused": overrides.failOnUnusedAllowlist = true; break;
      case "--no-color": case "--no-colour": colour = false; break;
      case "-o": case "--output": {
        const v = value();
        if (v !== "text" && v !== "json") {
          throw new ConfigError(`--output must be "text" or "json", got "${v}"`);
        }
        overrides.output = v;
        break;
      }
      case "-p": case "--package-manager": {
        const v = value();
        if (!PACKAGE_MANAGERS.includes(v)) {
          throw new ConfigError(
            `--package-manager must be one of: ${PACKAGE_MANAGERS.join(", ")}. Got "${v}"`,
          );
        }
        overrides.packageManager = v as Config["packageManager"];
        break;
      }
      default:
        throw new ConfigError(`unknown option "${arg}". Run \`bartizan --help\`.`);
    }
  }

  return { overrides, directory, help, version, colour };
}

export async function main(
  argv: string[] = process.argv.slice(2),
  streams: { out: NodeJS.WritableStream; err: NodeJS.WritableStream } = {
    out: process.stdout,
    err: process.stderr,
  },
): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    streams.err.write(`bartizan: ${(err as Error).message}\n`);
    return 2;
  }

  if (args.help) {
    streams.out.write(HELP);
    return 0;
  }
  if (args.version) {
    streams.out.write(`${VERSION}\n`);
    return 0;
  }

  try {
    // Notices go to stderr so that `--output json` on stdout stays parseable.
    const config = resolveConfig(args.overrides, args.directory, (message) =>
      streams.err.write(`bartizan: ${message}\n`),
    );
    const result = await audit(config);

    if (config.output === "json") {
      streams.out.write(
        renderJsonReport(result.report, {
          severity: config.severity,
          packageManager: result.packageManager,
          passed: result.passed,
        }) + "\n",
      );
    } else {
      streams.out.write(
        renderTextReport(result.report, {
          colour: args.colour ?? shouldUseColour(),
          severity: config.severity,
          packageManager: result.packageManager,
          failOnUnusedAllowlist: config.failOnUnusedAllowlist,
        }) + "\n",
      );
    }
    return result.passed ? 0 : 1;
  } catch (err) {
    // Exit 2, never 0. A gate that could not run must not look like a pass -
    // that is the failure mode that lets a vulnerable build through unnoticed.
    if (err instanceof ConfigError) {
      streams.err.write(`bartizan: config error: ${err.message}\n`);
    } else if (err instanceof AuditCommandError) {
      streams.err.write(`bartizan: ${err.message}\n`);
      if (err.stderr.trim()) streams.err.write(`${err.stderr.trim()}\n`);
    } else if (err instanceof AuditParseError) {
      streams.err.write(`bartizan: ${err.message}\n`);
    } else {
      streams.err.write(`bartizan: unexpected error: ${(err as Error).message}\n`);
    }
    return 2;
  }
}

/**
 * Only auto-run when this file is the process entry point, so that tests can
 * import `main` without it executing on import.
 *
 * npm installs the `bartizan` bin as a symlink (`node_modules/.bin/bartizan`), so
 * `process.argv[1]` and `import.meta.url` name the same file by different paths.
 * Comparing the raw strings would skip `main()` for every real install - the
 * CLI would exit 0 having audited nothing. Compare resolved real paths instead.
 */
export function isEntryPoint(entry: string, self: string = import.meta.url): boolean {
  try {
    return realpathSync(fileURLToPath(self)) === realpathSync(entry);
  } catch {
    return false;
  }
}

const entry = process.argv[1];
if (entry && isEntryPoint(entry)) {
  main().then((code) => {
    process.exitCode = code;
  });
}
