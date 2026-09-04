import type { AllowlistEntry } from "../core/allowlist.js";
import { SEVERITIES, type Severity } from "../types.js";

/**
 * Reads an existing `audit-ci` configuration file.
 *
 * The people most likely to want lamassu are the ones currently blocked on
 * audit-ci - so switching should cost one line in a CI script and nothing
 * else. This translates their config rather than asking them to rewrite it.
 */

export interface CompatConfig {
  severity?: Severity;
  allowlist?: AllowlistEntry[];
  packageManager?: "auto" | "npm" | "yarn" | "pnpm" | "bun";
  skipDev?: boolean;
  output?: "text" | "json";
}

export interface CompatResult {
  config: CompatConfig;
  /** Non-fatal notes to show the user, e.g. options with no equivalent here. */
  warnings: string[];
}

/** audit-ci options that have no lamassu equivalent, and why that is fine. */
const IGNORED: Record<string, string> = {
  $schema: "",
  "report-type": "lamassu always reports the findings that fail the build",
  "retry-count": "not implemented; rerun the step if your registry is flaky",
  "pass-enoaudit": "lamassu exits 2 when the audit cannot run, which CI should treat as a failure",
  registry: "lamassu uses the registry your package manager is already configured with",
  "extra-args": "not supported; open an issue if you need it",
  "show-found": "",
  "show-not-found": "",
  "summary-text": "",
};

/**
 * audit-ci expresses the threshold as a set of booleans - `{"moderate": true}`
 * means "fail on moderate and above". When several are set, the lowest wins,
 * because that is the one that actually gates.
 */
function severityFromBooleans(raw: Record<string, unknown>): Severity | undefined {
  for (const level of SEVERITIES) {
    if (raw[level] === true) return level;
  }
  return undefined;
}

export function translateAuditCiConfig(raw: unknown, source: string): CompatResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${source} must contain a JSON object`);
  }
  const input = raw as Record<string, unknown>;
  const warnings: string[] = [];
  const config: CompatConfig = {};

  const severity = severityFromBooleans(input);
  if (severity) config.severity = severity;

  if (Array.isArray(input.allowlist)) {
    config.allowlist = input.allowlist as AllowlistEntry[];
    // audit-ci matches a bare advisory id anywhere in the tree. We keep that
    // behaviour so results do not change on migration, but say how to narrow it.
    const bare = input.allowlist.filter((e) => typeof e === "string" && !e.includes("|")).length;
    if (bare > 0) {
      warnings.push(
        `${bare} allowlist entr${bare === 1 ? "y" : "ies"} match any package. ` +
          `Scope them as "package|GHSA-..." to avoid suppressing unrelated findings.`,
      );
    }
  }

  const pm = input["package-manager"];
  if (typeof pm === "string") {
    if (["auto", "npm", "yarn", "pnpm", "bun"].includes(pm)) {
      config.packageManager = pm as CompatConfig["packageManager"];
    } else {
      warnings.push(`ignoring unknown package-manager "${pm}"`);
    }
  }

  if (input["skip-dev"] !== undefined) config.skipDev = Boolean(input["skip-dev"]);

  const outputFormat = input["output-format"];
  if (outputFormat === "json" || outputFormat === "text") config.output = outputFormat;

  const known = new Set([
    ...SEVERITIES,
    "allowlist",
    "package-manager",
    "skip-dev",
    "output-format",
    ...Object.keys(IGNORED),
  ]);
  for (const key of Object.keys(input)) {
    if (known.has(key)) {
      const note = IGNORED[key];
      if (note) warnings.push(`"${key}" has no effect: ${note}`);
      continue;
    }
    warnings.push(`ignoring unrecognised option "${key}"`);
  }

  return { config, warnings };
}
