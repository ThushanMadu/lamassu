import type { AllowlistReport } from "../core/allowlist.js";
import { countBySeverity } from "../core/threshold.js";
import { SEVERITIES, type Severity, type Vulnerability } from "../types.js";

const COLOURS: Record<Severity, string> = {
  info: "\x1b[90m",
  low: "\x1b[36m",
  moderate: "\x1b[33m",
  high: "\x1b[31m",
  critical: "\x1b[35m",
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";

/**
 * CI logs are not terminals, and colour codes there become noise that ends up
 * in build output and pasted bug reports. Honour NO_COLOR and FORCE_COLOR,
 * then fall back to whether stdout is a TTY.
 */
export function shouldUseColour(
  env: NodeJS.ProcessEnv = process.env,
  isTTY: boolean | undefined = process.stdout.isTTY,
): boolean {
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") return false;
  if (env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== "0") return true;
  return Boolean(isTTY);
}

export interface TextReportOptions {
  colour: boolean;
  severity: Severity;
  packageManager: string;
  failOnUnusedAllowlist: boolean;
}

export function renderTextReport(report: AllowlistReport, options: TextReportOptions): string {
  const { remaining, suppressed, unused, expired } = report;
  const c = (s: string, colour: string) => (options.colour ? `${colour}${s}${RESET}` : s);
  const b = (s: string) => (options.colour ? `${BOLD}${s}${RESET}` : s);
  const lines: string[] = [];

  lines.push(b(`lamassu - ${options.packageManager}, failing at ${options.severity} and above`));
  lines.push("");

  if (remaining.length === 0) {
    lines.push(`PASS  No vulnerabilities at or above ${options.severity}.`);
  } else {
    for (const v of remaining) lines.push(...renderVulnerability(v, c));
    const counts = countBySeverity(remaining);
    const summary = SEVERITIES.filter((s) => counts[s] > 0)
      .reverse()
      .map((s) => `${counts[s]} ${s}`)
      .join(", ");
    lines.push(b(`FAIL  ${remaining.length} finding${remaining.length === 1 ? "" : "s"}: ${summary}`));
  }

  if (suppressed.length) {
    lines.push("");
    lines.push(`      ${suppressed.length} finding(s) suppressed by the allowlist.`);
  }
  if (expired.length) {
    lines.push("");
    lines.push(
      c(
        `WARN  ${expired.length} allowlist entr${expired.length === 1 ? "y has" : "ies have"} expired and no longer suppress anything:`,
        COLOURS.moderate,
      ),
    );
    for (const r of expired) {
      lines.push(`        ${r.id}${r.module ? ` (${r.module})` : ""} - expired ${r.expires}`);
    }
  }
  if (unused.length) {
    lines.push("");
    const label = options.failOnUnusedAllowlist ? "FAIL" : "WARN";
    lines.push(
      c(
        `${label}  ${unused.length} allowlist entr${unused.length === 1 ? "y" : "ies"} matched nothing (likely fixed - safe to delete):`,
        COLOURS.moderate,
      ),
    );
    for (const r of unused) lines.push(`        ${r.id}${r.module ? ` (${r.module})` : ""}`);
  }
  return lines.join("\n");
}

function renderVulnerability(v: Vulnerability, c: (s: string, colour: string) => string): string[] {
  const tag = c(v.severity.toUpperCase().padEnd(8), COLOURS[v.severity]);
  const out = [`  ${tag} ${v.module}  ${v.title}`];
  const detail: string[] = [];
  if (v.vulnerableVersions) detail.push(`affects ${v.vulnerableVersions}`);
  if (v.foundVersions.length) detail.push(`found ${v.foundVersions.join(", ")}`);
  if (v.fixAvailable) detail.push("fix available");
  if (detail.length) out.push(`           ${detail.join(" - ")}`);
  if (v.url) out.push(`           ${v.url}`);
  // Printing the exact allowlist line removes the guesswork that makes people
  // write over-broad bare-id entries.
  out.push(`           allowlist as: ${v.module}|${v.id}`);
  out.push("");
  return out;
}
