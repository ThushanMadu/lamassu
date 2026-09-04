import { SEVERITIES, severityRank, type Severity, type Vulnerability } from "../types.js";

/** The lowest severity that should fail the build. */
export type Threshold = Severity;

export function parseThreshold(input: string | undefined): Threshold {
  const s = String(input ?? "high").toLowerCase().trim();
  if ((SEVERITIES as readonly string[]).includes(s)) return s as Threshold;
  throw new Error(`unknown severity "${input}". Expected one of: ${SEVERITIES.join(", ")}`);
}

export function atOrAbove(vulnerabilities: Vulnerability[], threshold: Threshold): Vulnerability[] {
  const min = severityRank(threshold);
  return vulnerabilities.filter((v) => severityRank(v.severity) >= min);
}

export function countBySeverity(vulnerabilities: Vulnerability[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const v of vulnerabilities) counts[v.severity] += 1;
  return counts;
}
