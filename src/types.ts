/** Severity levels, ordered from least to most severe. */
export const SEVERITIES = ["info", "low", "moderate", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

/** Normalise the many spellings package managers use into our scale. */
export function toSeverity(raw: unknown): Severity {
  const s = String(raw ?? "").toLowerCase().trim();
  if (s === "moderate" || s === "medium") return "moderate";
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "low") return "low";
  return "info";
}

export type PackageManager = "npm" | "yarn" | "pnpm" | "bun";

/**
 * One vulnerability, normalised across every package manager.
 * `id` is the GHSA identifier when we can find one, since that is the only
 * identifier that is stable across ecosystems and over time.
 */
export interface Vulnerability {
  /** GHSA id when known, else the advisory's numeric id as a string. */
  id: string;
  /** Numeric advisory id, when the source provided one. */
  source?: number;
  /** The vulnerable package. */
  module: string;
  severity: Severity;
  title: string;
  url?: string;
  /** Semver range that is affected, e.g. "<4.17.21". */
  vulnerableVersions?: string;
  /** Installed versions we actually found, when reported. */
  foundVersions: string[];
  /** True when the package manager says an upgrade fixes it. */
  fixAvailable?: boolean;
  /** True when it is reachable only through devDependencies, when known. */
  dev?: boolean;
}


/**
 * Node's timers are backed by a 32-bit signed integer of milliseconds. A larger
 * delay silently fires immediately, which would kill an audit the instant it
 * started - so reject it rather than accepting a value that does the opposite
 * of what was asked.
 */
export const MAX_TIMEOUT_SECONDS = Math.floor((2 ** 31 - 1) / 1000);
