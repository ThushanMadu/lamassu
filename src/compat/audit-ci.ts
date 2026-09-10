import type { AllowlistEntry } from "../core/allowlist.js";
import { SEVERITIES, type Severity } from "../types.js";

/**
 * Reads an existing `audit-ci` configuration file.
 *
 * The people most likely to want bartizan are the ones currently blocked on
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

/** audit-ci options that have no bartizan equivalent, and why that is fine. */
const IGNORED: Record<string, string> = {
  $schema: "",
  "report-type": "bartizan always reports the findings that fail the build",
  "retry-count": "not implemented; rerun the step if your registry is flaky",
  "pass-enoaudit": "bartizan exits 2 when the audit cannot run, which CI should treat as a failure",
  registry: "bartizan uses the registry your package manager is already configured with",
  "extra-args": "not supported; open an issue if you need it",
  "show-found": "",
  "show-not-found": "",
  "summary-text": "",
};

const GHSA_RE = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;

/**
 * audit-ci and bartizan both write a scoped allowlist entry as `left|right`, but
 * with the sides swapped: audit-ci uses `GHSA-id|dependency>path`, bartizan uses
 * `package|GHSA-id`. Flip the entries that map cleanly; collect the ones that
 * do not (dependency paths, `*` wildcards, bare module names) so the caller can
 * warn about them rather than silently shipping an entry that can never match.
 */
function translateAllowlist(list: unknown[]): {
  entries: AllowlistEntry[];
  unsupported: string[];
  bare: number;
} {
  const entries: AllowlistEntry[] = [];
  const unsupported: string[] = [];
  let bare = 0;

  for (const raw of list) {
    if (typeof raw !== "string") {
      entries.push(raw as AllowlistEntry);
      continue;
    }
    const entry = raw.trim();
    const pipe = entry.indexOf("|");

    if (pipe === -1) {
      if (GHSA_RE.test(entry)) {
        entries.push(entry); // advisory anywhere - identical meaning in bartizan
        bare++;
      } else {
        unsupported.push(entry); // bare module name - no bartizan equivalent
      }
      continue;
    }

    const left = entry.slice(0, pipe).trim();
    const right = entry.slice(pipe + 1).trim();
    const leftIsGhsa = GHSA_RE.test(left);
    const rightIsGhsa = GHSA_RE.test(right);

    if (rightIsGhsa && !leftIsGhsa) {
      entries.push(entry); // already bartizan's `package|GHSA-id` order
    } else if (leftIsGhsa && !rightIsGhsa && !/[>*]/.test(right)) {
      entries.push(`${right}|${left}`); // audit-ci `GHSA-id|package` -> flip
    } else {
      unsupported.push(entry); // dependency path, wildcard, or ambiguous
    }
  }

  return { entries, unsupported, bare };
}

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
    const { entries, unsupported, bare } = translateAllowlist(input.allowlist);
    config.allowlist = entries;

    // A bare advisory id matches that advisory in any package - audit-ci's
    // behaviour, kept so results do not change on migration, but worth narrowing.
    if (bare > 0) {
      warnings.push(
        `${bare} allowlist entr${bare === 1 ? "y matches" : "ies match"} the advisory in any ` +
          `package. Scope them as "package|GHSA-..." to avoid suppressing an unrelated finding later.`,
      );
    }

    // Dependency-path and wildcard entries have no bartizan equivalent. Say so
    // loudly: a silently-dropped suppression turns into a failing build, and a
    // silently-kept-but-dead entry is a suppression the user thinks they have.
    if (unsupported.length > 0) {
      warnings.push(
        `${unsupported.length} allowlist entr${unsupported.length === 1 ? "y uses" : "ies use"} ` +
          `audit-ci path or wildcard syntax bartizan cannot express ` +
          `(${unsupported.slice(0, 3).join(", ")}${unsupported.length > 3 ? ", ..." : ""}). ` +
          `Re-add them as "package|GHSA-..." or "package@version|GHSA-..." - see the ` +
          `"Replacing audit-ci" section of the README.`,
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
