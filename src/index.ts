import { applyAllowlist, type AllowlistReport } from "./core/allowlist.js";
import { parseAuditOutput } from "./core/parse.js";
import { atOrAbove } from "./core/threshold.js";
import { detectPackageManager } from "./managers/detect.js";
import { runAudit } from "./managers/run.js";
import type { Config } from "./config.js";
import type { PackageManager, Vulnerability } from "./types.js";

export interface AuditResult {
  passed: boolean;
  packageManager: PackageManager;
  report: AllowlistReport;
  /** Everything found, before the threshold and allowlist were applied. */
  all: Vulnerability[];
}

/**
 * Run an audit and decide whether it passes.
 *
 * The order matters: filter by severity first, then apply the allowlist. That
 * way an allowlist entry for a low-severity finding is not reported as unused
 * merely because the threshold already excluded it.
 */
export async function audit(config: Config): Promise<AuditResult> {
  const packageManager =
    config.packageManager === "auto"
      ? detectPackageManager(config.directory)
      : config.packageManager;

  const raw = await runAudit(packageManager, {
    cwd: config.directory,
    skipDev: config.skipDev,
  });

  const all = parseAuditOutput(raw);
  const relevant = atOrAbove(all, config.severity);
  const report = applyAllowlist(relevant, config.allowlist);

  const failed =
    report.remaining.length > 0 ||
    (config.failOnUnusedAllowlist && report.unused.length > 0);

  return { passed: !failed, packageManager, report, all };
}

export { parseAuditOutput, AuditParseError } from "./core/parse.js";
export { applyAllowlist, parseEntry } from "./core/allowlist.js";
export { atOrAbove, countBySeverity, parseThreshold } from "./core/threshold.js";
export { detectPackageManager } from "./managers/detect.js";
export { resolveConfig, loadConfigFile, DEFAULT_CONFIG, ConfigError } from "./config.js";
export { renderTextReport, shouldUseColour } from "./report/text.js";
export { renderJsonReport } from "./report/json.js";
export type { Config } from "./config.js";
export type { AllowlistEntry, AllowlistRule, AllowlistReport } from "./core/allowlist.js";
export type { Severity, Vulnerability, PackageManager } from "./types.js";
