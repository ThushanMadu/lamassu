import type { AllowlistReport } from "../core/allowlist.js";
import { countBySeverity } from "../core/threshold.js";
import type { Severity } from "../types.js";

export function renderJsonReport(
  report: AllowlistReport,
  meta: { severity: Severity; packageManager: string; passed: boolean },
): string {
  return JSON.stringify(
    {
      passed: meta.passed,
      severityThreshold: meta.severity,
      packageManager: meta.packageManager,
      counts: countBySeverity(report.remaining),
      vulnerabilities: report.remaining,
      suppressed: report.suppressed.map((s) => ({
        id: s.vulnerability.id,
        module: s.vulnerability.module,
        reason: s.rule.reason,
      })),
      unusedAllowlistEntries: report.unused,
      expiredAllowlistEntries: report.expired,
    },
    null,
    2,
  );
}
