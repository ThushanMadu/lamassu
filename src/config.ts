import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { translateAuditCiConfig } from "./compat/audit-ci.js";
import type { AllowlistEntry } from "./core/allowlist.js";
import { parseEntry } from "./core/allowlist.js";
import { parseThreshold, type Threshold } from "./core/threshold.js";
import { MAX_TIMEOUT_SECONDS, SEVERITIES, type PackageManager } from "./types.js";

export interface Config {
  /** Lowest severity that fails the build. Default: "high". */
  severity: Threshold;
  allowlist: AllowlistEntry[];
  packageManager: PackageManager | "auto";
  skipDev: boolean;
  /** Fail when an allowlist entry matched nothing. Keeps allowlists honest. */
  failOnUnusedAllowlist: boolean;
  output: "text" | "json";
  /** How long to wait for the package manager's audit before giving up. */
  timeoutSeconds: number;
  directory: string;
}

export const DEFAULT_CONFIG: Config = {
  severity: "high",
  allowlist: [],
  packageManager: "auto",
  skipDev: false,
  failOnUnusedAllowlist: false,
  output: "text",
  // Registry audit endpoints can be very slow on some networks; a single small
  // project has been observed taking over two minutes.
  timeoutSeconds: 300,
  directory: process.cwd(),
};

const CONFIG_FILES = ["lamassu.json", "lamassu.jsonc", ".lamassurc", ".lamassurc.json"];
const AUDIT_CI_FILES = ["audit-ci.json", "audit-ci.jsonc", ".audit-ci.json", ".audit-ci.jsonc"];

/** Strip // and /* *\/ comments so .jsonc files parse, without a dependency. */
export function stripJsonComments(input: string): string {
  let out = "";
  let inString = false;
  let inLine = false;
  let inBlock = false;
  // Drop a trailing comma before `}` / `]`. VS Code's jsonc parser and
  // audit-ci's config loader both accept them, so a config that worked before
  // migrating must not fail JSON.parse here.
  const dropTrailingComma = () => {
    const trimmed = out.replace(/\s+$/, "");
    if (trimmed.endsWith(",")) out = trimmed.slice(0, -1);
  };
  for (let i = 0; i < input.length; i++) {
    const c = input[i]!;
    const next = input[i + 1];
    if (inLine) {
      if (c === "\n") { inLine = false; out += c; }
      continue;
    }
    if (inBlock) {
      if (c === "*" && next === "/") { inBlock = false; i++; }
      continue;
    }
    if (inString) {
      out += c;
      if (c === "\\") { out += input[++i] ?? ""; continue; }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === "/" && next === "/") { inLine = true; i++; continue; }
    if (c === "/" && next === "*") { inBlock = true; i++; continue; }
    if (c === "}" || c === "]") dropTrailingComma();
    out += c;
  }
  return out;
}

export class ConfigError extends Error {}

export interface ConfigSource {
  path: string;
  kind: "native" | "audit-ci";
}

export interface LoadedConfig {
  config: Partial<Config>;
  /** Non-fatal notices for the user, e.g. compatibility-mode remarks. */
  warnings: string[];
}

/**
 * Native config wins. Falling back to an audit-ci file means a team blocked on
 * audit-ci can switch by changing the command they run and nothing else.
 */
export function findConfigFile(dir: string): ConfigSource | undefined {
  for (const name of CONFIG_FILES) {
    const p = join(dir, name);
    if (existsSync(p)) return { path: p, kind: "native" };
  }
  for (const name of AUDIT_CI_FILES) {
    const p = join(dir, name);
    if (existsSync(p)) return { path: p, kind: "audit-ci" };
  }
  return undefined;
}

function readJsonc(path: string): Record<string, unknown> {
  let raw: unknown;
  try {
    raw = JSON.parse(stripJsonComments(readFileSync(path, "utf8")));
  } catch (err) {
    throw new ConfigError(`could not parse ${path}: ${(err as Error).message}`);
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${path} must contain a JSON object`);
  }
  return raw as Record<string, unknown>;
}

export function loadConfigFile(source: ConfigSource): LoadedConfig {
  const raw = readJsonc(source.path);

  if (source.kind === "audit-ci") {
    let translated;
    try {
      translated = translateAuditCiConfig(raw, source.path);
    } catch (err) {
      throw new ConfigError((err as Error).message);
    }
    return {
      config: translated.config,
      warnings: [
        `using ${basename(source.path)} in audit-ci compatibility mode`,
        ...translated.warnings,
      ],
    };
  }

  return { config: validate(raw, source.path), warnings: [] };
}

function validate(raw: Record<string, unknown>, source: string): Partial<Config> {
  const out: Partial<Config> = {};

  if (raw.severity !== undefined) {
    // parseThreshold throws a plain Error; rethrow as ConfigError so a typo in
    // the file is reported as a config error, not "unexpected error".
    try {
      out.severity = parseThreshold(String(raw.severity));
    } catch (err) {
      throw new ConfigError(`${source}: ${(err as Error).message}`);
    }
  }

  if (raw.allowlist !== undefined) {
    if (!Array.isArray(raw.allowlist)) throw new ConfigError(`${source}: "allowlist" must be an array`);
    out.allowlist = raw.allowlist.map((entry, i) => {
      if (typeof entry === "string") return entry;
      if (typeof entry === "object" && entry !== null && typeof (entry as any).id === "string") {
        const e = entry as any;
        // Catch a mistyped date now rather than silently never expiring.
        if (e.expires !== undefined && Number.isNaN(Date.parse(String(e.expires)))) {
          throw new ConfigError(
            `${source}: allowlist[${i}].expires is not a valid date: ${JSON.stringify(e.expires)}`,
          );
        }
        return e;
      }
      throw new ConfigError(
        `${source}: allowlist[${i}] must be a string or an object with an "id"`,
      );
    });
  }

  if (raw.packageManager !== undefined) {
    const pm = String(raw.packageManager);
    if (!["auto", "npm", "yarn", "pnpm", "bun"].includes(pm)) {
      throw new ConfigError(`${source}: unknown packageManager "${pm}"`);
    }
    out.packageManager = pm as Config["packageManager"];
  }

  if (raw.skipDev !== undefined) out.skipDev = Boolean(raw.skipDev);
  if (raw.failOnUnusedAllowlist !== undefined) {
    out.failOnUnusedAllowlist = Boolean(raw.failOnUnusedAllowlist);
  }
  if (raw.timeoutSeconds !== undefined) {
    // Number(true) is 1, so a boolean would otherwise be accepted as a
    // one-second timeout. Require an actual number.
    const t = raw.timeoutSeconds;
    if (typeof t !== "number" || !Number.isFinite(t) || t <= 0) {
      throw new ConfigError(
        `${source}: timeoutSeconds must be a positive number, got ${JSON.stringify(t)}`,
      );
    }
    if (t > MAX_TIMEOUT_SECONDS) {
      throw new ConfigError(`${source}: timeoutSeconds must be at most ${MAX_TIMEOUT_SECONDS}`);
    }
    out.timeoutSeconds = t;
  }

  if (raw.output !== undefined) {
    const o = String(raw.output);
    if (o !== "text" && o !== "json") throw new ConfigError(`${source}: output must be "text" or "json"`);
    out.output = o;
  }

  for (const key of Object.keys(raw)) {
    const known = ["severity", "allowlist", "packageManager", "skipDev", "failOnUnusedAllowlist", "output", "timeoutSeconds"];
    if (!known.includes(key)) {
      // Unknown keys are usually typos. Say so rather than ignoring silently.
      throw new ConfigError(
        `${source}: unknown option "${key}". Valid options: ${known.join(", ")}`,
      );
    }
  }
  return out;
}

/**
 * Merge defaults, the config file and command line options.
 *
 * `notify` receives compatibility-mode notices. The CLI sends them to stderr so
 * that `--output json` on stdout stays machine-readable.
 */
export function resolveConfig(
  overrides: Partial<Config>,
  dir: string,
  notify?: (message: string) => void,
): Config {
  const source = findConfigFile(dir);
  const loaded = source ? loadConfigFile(source) : { config: {}, warnings: [] };
  if (notify) for (const w of loaded.warnings) notify(w);
  return { ...DEFAULT_CONFIG, directory: dir, ...loaded.config, ...overrides };
}

export { SEVERITIES, parseEntry };
