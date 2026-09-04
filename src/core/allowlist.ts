import type { Vulnerability } from "../types.js";

/**
 * An allowlist entry, either as a shorthand string or the full object form.
 *
 * Shorthand grammar, in increasing order of precision:
 *   "GHSA-xxxx-xxxx-xxxx"                  any occurrence of this advisory
 *   "lodash|GHSA-xxxx-xxxx-xxxx"           only when it is lodash
 *   "lodash@4.17.15|GHSA-xxxx-xxxx-xxxx"   only that installed version
 */
export type AllowlistEntry = string | AllowlistRule;

export interface AllowlistRule {
  id: string;
  module?: string;
  version?: string;
  /** ISO date. After this day the entry stops suppressing and starts failing. */
  expires?: string;
  reason?: string;
}

export interface AllowlistReport {
  /** Vulnerabilities that survived the allowlist and still count. */
  remaining: Vulnerability[];
  /** Vulnerabilities that an entry suppressed. */
  suppressed: { vulnerability: Vulnerability; rule: AllowlistRule }[];
  /** Entries that matched nothing - usually a fixed vuln whose entry is now dead. */
  unused: AllowlistRule[];
  /** Entries past their expiry date. These no longer suppress anything. */
  expired: AllowlistRule[];
}

export function parseEntry(entry: AllowlistEntry): AllowlistRule {
  if (typeof entry !== "string") return entry;
  const [left, right] = entry.includes("|") ? splitOnce(entry, "|") : [undefined, entry];
  const rule: AllowlistRule = { id: right.trim() };
  if (left) {
    const at = left.lastIndexOf("@");
    // Guard against scoped names, where the leading @ is part of the package.
    if (at > 0) {
      rule.module = left.slice(0, at);
      rule.version = left.slice(at + 1);
    } else {
      rule.module = left;
    }
  }
  return rule;
}

function splitOnce(s: string, sep: string): [string, string] {
  const i = s.indexOf(sep);
  return [s.slice(0, i), s.slice(i + sep.length)];
}

function idMatches(rule: AllowlistRule, v: Vulnerability): boolean {
  const a = rule.id.trim().toUpperCase();
  return a === v.id.toUpperCase() || a === String(v.source ?? "");
}

function matches(rule: AllowlistRule, v: Vulnerability): boolean {
  if (!idMatches(rule, v)) return false;
  // A bare advisory id suppresses that advisory wherever it appears. Adding a
  // module - and optionally a version - narrows it, so that an entry written
  // for one package cannot silently absorb the same advisory surfacing
  // somewhere else in the tree.
  if (rule.module && rule.module !== v.module) return false;
  if (rule.version && !v.foundVersions.includes(rule.version)) return false;
  return true;
}

export function isExpired(rule: AllowlistRule, now: Date): boolean {
  if (!rule.expires) return false;
  const at = Date.parse(rule.expires);
  if (Number.isNaN(at)) return false; // validated separately; never silently drop
  return now.getTime() > at;
}

export function applyAllowlist(
  vulnerabilities: Vulnerability[],
  entries: AllowlistEntry[],
  now: Date = new Date(),
): AllowlistReport {
  const rules = entries.map(parseEntry);
  const expired = rules.filter((r) => isExpired(r, now));
  const active = rules.filter((r) => !isExpired(r, now));

  const remaining: Vulnerability[] = [];
  const suppressed: AllowlistReport["suppressed"] = [];
  const used = new Set<AllowlistRule>();

  for (const v of vulnerabilities) {
    const rule = active.find((r) => matches(r, v));
    if (rule) {
      used.add(rule);
      suppressed.push({ vulnerability: v, rule });
    } else {
      remaining.push(v);
    }
  }

  const unused = active.filter((r) => !used.has(r));
  return { remaining, suppressed, unused, expired };
}
