import { severityRank, toSeverity, type Vulnerability } from "../types.js";

/**
 * Package managers emit at least four different JSON shapes for the same data,
 * and they change between major versions. Rather than hard-coding
 * "npm produces shape A", we detect the shape. That way a new Yarn or Bun
 * release that switches formats keeps working as long as the shape is one we
 * already understand.
 */

const GHSA_RE = /GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}/i;

function ghsaFrom(...candidates: unknown[]): string | undefined {
  for (const c of candidates) {
    const m = GHSA_RE.exec(String(c ?? ""));
    if (m) return m[0].toUpperCase();
  }
  return undefined;
}

/** npm v7+ / `npm audit --json` with auditReportVersion: 2. */
function parseNpmV2(doc: any): Vulnerability[] | null {
  if (doc?.auditReportVersion !== 2 || typeof doc.vulnerabilities !== "object") return null;
  const out = new Map<string, Vulnerability>();

  for (const entry of Object.values<any>(doc.vulnerabilities ?? {})) {
    // `via` holds either advisory objects (a real finding) or plain strings
    // (a "metavulnerability" - this package is only affected because a
    // dependency of it is). Strings carry no advisory of their own, so we
    // record only the objects and let the dependency's own entry cover it.
    for (const via of entry?.via ?? []) {
      if (typeof via !== "object" || via === null) continue;
      const id = ghsaFrom(via.url, via.source) ?? String(via.source ?? `${via.name}:${via.title}`);
      // The same advisory can surface under several packages; keep the first.
      if (out.has(id)) continue;
      out.set(id, {
        id,
        source: typeof via.source === "number" ? via.source : undefined,
        module: String(via.name ?? entry.name),
        severity: toSeverity(via.severity ?? entry.severity),
        title: String(via.title ?? "Unknown advisory"),
        url: via.url ? String(via.url) : undefined,
        vulnerableVersions: via.range ? String(via.range) : undefined,
        // npm v2 reports affected ranges and install paths, never the resolved
        // version, so there is nothing honest to put here.
        foundVersions: [],
        fixAvailable: Boolean(entry.fixAvailable),
      });
    }
  }
  return [...out.values()];
}

/** npm v6 "advisories" map. pnpm, Yarn 2/3 and Bun all emit this shape too. */
function parseAdvisoriesMap(doc: any): Vulnerability[] | null {
  const advisories = doc?.advisories;
  if (!advisories || typeof advisories !== "object" || Array.isArray(advisories)) return null;
  const out: Vulnerability[] = [];

  for (const a of Object.values<any>(advisories)) {
    if (typeof a !== "object" || a === null) continue;
    const findings: any[] = Array.isArray(a.findings) ? a.findings : [];
    const id = ghsaFrom(a.github_advisory_id, a.url, ...(a.cves ?? [])) ?? String(a.id ?? a.module_name);
    out.push({
      id,
      source: typeof a.id === "number" ? a.id : undefined,
      module: String(a.module_name ?? "unknown"),
      severity: toSeverity(a.severity),
      title: String(a.title ?? "Unknown advisory"),
      url: a.url ? String(a.url) : undefined,
      vulnerableVersions: a.vulnerable_versions ? String(a.vulnerable_versions) : undefined,
      foundVersions: [
        ...new Set(findings.map((f) => String(f.version)).filter((v) => v && v !== "undefined")),
      ],
      dev: findings.length ? findings.every((f) => f.dev === true) : undefined,
    });
  }
  return out;
}

/** Yarn 1 `yarn audit --json`: newline-delimited, one advisory per line. */
function parseYarnClassic(lines: any[]): Vulnerability[] | null {
  const advisories = lines.filter((l) => l?.type === "auditAdvisory" && l?.data?.advisory);
  if (!advisories.length) return null;
  const out = new Map<string, Vulnerability>();

  for (const line of advisories) {
    const a = line.data.advisory;
    const id = ghsaFrom(a.github_advisory_id, a.url, ...(a.cves ?? [])) ?? String(a.id ?? a.module_name);
    const prev = out.get(id);
    const versions = new Set(prev?.foundVersions ?? []);
    // resolution.path is "a>b>c"; the installed version lives in findings, so
    // that is the only place we read it from.
    for (const f of a.findings ?? []) if (f?.version) versions.add(String(f.version));
    out.set(id, {
      id,
      source: typeof a.id === "number" ? a.id : undefined,
      module: String(a.module_name ?? "unknown"),
      severity: toSeverity(a.severity),
      title: String(a.title ?? "Unknown advisory"),
      url: a.url ? String(a.url) : undefined,
      vulnerableVersions: a.vulnerable_versions ? String(a.vulnerable_versions) : undefined,
      foundVersions: [...versions],
      dev: line.data.resolution?.dev === true ? true : prev?.dev,
    });
  }
  return [...out.values()];
}

/**
 * Yarn 4 `yarn npm audit --json` emits Yarn's generic "tree report": one line
 * per finding, with the package in `value` and the advisory fields in
 * `children` under human-readable Capitalised keys.
 *
 * This is the format audit-ci never shipped support for, which is why Yarn 4
 * users are stuck running `npx yarn@1.22.19` just to audit.
 */
function parseYarnTreeReport(lines: any[]): Vulnerability[] | null {
  const rows = lines.filter((l) => l && typeof l === "object" && "value" in l && l.children);
  if (!rows.length) return null;
  const out = new Map<string, Vulnerability>();

  for (const row of rows) {
    const c = row.children;
    const severity = c.Severity ?? c.severity;
    if (severity === undefined) continue;
    const url = c.URL ?? c.url;
    const id = ghsaFrom(url, c.ID, c.id) ?? String(c.ID ?? c.id ?? row.value);
    const versions: string[] = []
      .concat(c["Tree Versions"] ?? c.treeVersions ?? [])
      .map((v: unknown) => String(v));
    out.set(id, {
      id,
      source: typeof c.ID === "number" ? c.ID : undefined,
      module: String(row.value ?? c.Package ?? "unknown"),
      severity: toSeverity(severity),
      title: String(c.Issue ?? c.issue ?? "Unknown advisory"),
      url: url ? String(url) : undefined,
      vulnerableVersions: c["Vulnerable Versions"] ? String(c["Vulnerable Versions"]) : undefined,
      foundVersions: versions,
    });
  }
  return [...out.values()];
}

/**
 * Yarn 4 with `--recursive` has been observed emitting a third shape: a single
 * object keyed by package name, whose values are arrays of advisory objects
 * with lower-case keys, and with no summary metadata at all.
 *
 * See https://github.com/yarnpkg/berry/issues/5781 - the missing metadata is
 * exactly what breaks tools that expect the Yarn 3 `advisories` document.
 */
function parseYarnRecursiveMap(doc: any): Vulnerability[] | null {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  // These keys identify the other documented shapes - but only when they hold
  // their documented (non-array) types. Here every value is an array of
  // advisories keyed by package name, and packages named `metadata` /
  // `advisories` exist, so an array under one of these keys is a real entry.
  const claimsOtherShape =
    (doc.advisories !== undefined && !Array.isArray(doc.advisories)) ||
    (doc.auditReportVersion !== undefined && !Array.isArray(doc.auditReportVersion)) ||
    (doc.metadata !== undefined && !Array.isArray(doc.metadata));
  if (claimsOtherShape) return null;

  const entries = Object.entries<any>(doc);
  if (!entries.length) return null;

  // Every value must be a non-empty array of advisory-looking objects, or this
  // is some other document that merely happens to be an object.
  const looksRight = entries.every(
    ([, list]) =>
      Array.isArray(list) &&
      list.length > 0 &&
      list.every((a) => a && typeof a === "object" && ("id" in a || "ID" in a)),
  );
  if (!looksRight) return null;

  const out: Vulnerability[] = [];
  for (const [moduleName, list] of entries) {
    for (const a of list as any[]) {
      const url = a.url ?? a.URL;
      const rawId = a.id ?? a.ID;
      const id = ghsaFrom(url, rawId, ...(a.cves ?? [])) ?? String(rawId ?? moduleName);
      out.push({
        id,
        source: typeof rawId === "number" ? rawId : undefined,
        module: String(a.module_name ?? moduleName),
        severity: toSeverity(a.severity ?? a.Severity),
        title: String(a.title ?? a.Issue ?? "Unknown advisory"),
        url: url ? String(url) : undefined,
        vulnerableVersions: String(
          a.vulnerable_versions ?? a["Vulnerable Versions"] ?? "",
        ) || undefined,
        foundVersions: ([] as unknown[])
          .concat(a.tree_versions ?? a["Tree Versions"] ?? [])
          .map((v) => String(v)),
      });
    }
  }
  return out;
}

/** Split raw stdout into JSON documents: either one object, or NDJSON. */
function readDocuments(raw: string): { single: any; lines: any[] } {
  const trimmed = raw.trim();
  let single: any = null;
  try {
    single = JSON.parse(trimmed);
  } catch {
    /* not a single document - fall through to NDJSON */
  }
  const lines: any[] = [];
  if (single === null) {
    for (const line of trimmed.split(/\r?\n/)) {
      const s = line.trim();
      if (!s) continue;
      try { lines.push(JSON.parse(s)); } catch { /* ignore non-JSON noise */ }
    }
  }
  return { single, lines };
}

export class AuditParseError extends Error {}

/**
 * Turn any supported package manager's audit output into our own model.
 * Throws AuditParseError when the output matches no known shape, because
 * silently reporting "no vulnerabilities" would be the worst possible failure
 * for a security gate.
 */
export function parseAuditOutput(raw: string): Vulnerability[] {
  if (!raw.trim()) throw new AuditParseError("audit command produced no output");
  const { single, lines } = readDocuments(raw);

  // Most specific shape first, most permissive last.
  const attempts = single
    ? [parseNpmV2(single), parseAdvisoriesMap(single), parseYarnRecursiveMap(single)]
    : [parseYarnClassic(lines), parseYarnTreeReport(lines)];

  for (const result of attempts) if (result !== null) return dedupe(result);

  // A clean report is only a clean report when the output SAYS it is clean.
  // Treating "we parsed nothing" as "nothing is wrong" is the one failure this
  // package exists to prevent, so every branch below requires positive evidence
  // of zero findings rather than merely an absence of recognised ones.
  if (single && typeof single === "object" && !Array.isArray(single)) {
    const meta = single.metadata?.vulnerabilities;
    if (meta && typeof meta === "object" && countsAreZero(meta)) return [];
    if (single.advisories && !Object.keys(single.advisories).length) return [];

    // Bun emits a bare `{}` on a clean audit. An object with no keys at all is
    // positive evidence of zero findings, not an absence of recognised ones:
    // npm always carries `auditReportVersion` or `error`, pnpm always carries
    // `advisories` / `metadata`, so nothing else produces an empty object - it
    // cannot be a truncated or failed run misread as clean.
    if (Object.keys(single).length === 0) return [];
  }

  // Yarn 1 reports a clean project as a summary with no advisories. That can
  // arrive as several NDJSON lines or, when nothing else is emitted, as a
  // single JSON document - so look in both places.
  const documents = single ? [single] : lines;
  const summary = documents.find((d) => d?.type === "auditSummary");
  if (summary && countsAreZero(summary.data?.vulnerabilities)) return [];

  // Showing what actually arrived turns an opaque failure into a diagnosable
  // one. In practice the commonest cause is not an unknown format at all - it
  // is the package manager printing a network error where JSON was expected.
  const snippet = raw.trim().slice(0, 400);
  const looksLikeError =
    /error|ERR!|timeout|timed out|ECONN|ENOTFOUND|ENETUNREACH|ETIMEDOUT|EAI_AGAIN|YN\d{4}/i.test(
      snippet,
    );

  throw new AuditParseError(
    looksLikeError
      ? `the package manager reported an error instead of audit results:\n\n${indent(snippet)}\n\n` +
        `This is usually a network or registry problem rather than a bartizan bug. ` +
        `Retry, and if your connection is slow raise the limit with --timeout.`
      : `could not recognise the audit output format. Please open an issue with the raw ` +
        `output (BARTIZAN_DUMP_RAW=/tmp/raw.txt bartizan). What we received began:\n\n${indent(snippet)}`,
  );
}

/**
 * True when a severity-count summary positively reports zero findings.
 * A summary claiming vulnerabilities we could not parse is a parse failure,
 * not a clean result.
 */
function countsAreZero(counts: unknown): boolean {
  if (!counts || typeof counts !== "object") return false;
  const values = Object.entries(counts as Record<string, unknown>)
    .filter(([key]) => key !== "total")
    .map(([, value]) => Number(value));
  if (!values.length || values.some((v) => !Number.isFinite(v))) return false;
  return values.every((v) => v === 0);
}

function indent(text: string): string {
  return text
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\n");
}

function dedupe(list: Vulnerability[]): Vulnerability[] {
  const byId = new Map<string, Vulnerability>();
  for (const v of list) {
    const prev = byId.get(v.id);
    if (!prev) { byId.set(v.id, v); continue; }
    prev.foundVersions = [...new Set([...prev.foundVersions, ...v.foundVersions])];
  }
  return [...byId.values()].sort(
    // Most severe first. Comparing the severity *strings* would sort them
    // alphabetically - moderate, low, high, critical - which puts the most
    // dangerous finding last, where it is easiest to miss.
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.module.localeCompare(b.module),
  );
}
