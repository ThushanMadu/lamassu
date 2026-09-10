#!/usr/bin/env node
/**
 * Compares the normalised output every package manager produced for the same
 * vulnerable project.
 *
 * The point of bartizan is that the answer should not depend on which package
 * manager asked the question. This asserts that.
 *
 * It deliberately does not demand byte-identical results. Package managers
 * query different advisory endpoints and resolve transitive dependencies
 * slightly differently, so extra findings in one of them are normal and not a
 * bug. What must never happen is a package manager *missing* a vulnerability
 * the others found in a direct dependency.
 *
 *   node scripts/cross-check.mjs outputs/
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Direct dependencies of the fixture: every package manager must flag these. */
const REQUIRED_MODULES = ["lodash", "minimist", "axios"];

const dir = process.argv[2];
if (!dir) {
  console.error("usage: cross-check.mjs <directory of *.json outputs>");
  process.exit(2);
}

const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
if (files.length === 0) {
  console.error(`✗ no verification output found in ${dir}/ - the verify jobs did not produce results`);
  process.exit(1);
}

const results = new Map();
for (const file of files) {
  const name = file.replace(/\.json$/, "");
  try {
    const parsed = JSON.parse(readFileSync(join(dir, file), "utf8"));
    results.set(name, parsed.vulnerabilities ?? []);
  } catch (err) {
    console.error(`✗ ${name}: unreadable output (${err.message})`);
    process.exit(1);
  }
}

console.log(`Comparing ${results.size} package manager(s): ${[...results.keys()].join(", ")}\n`);

let failed = false;

// 1. Every package manager must flag every direct dependency.
for (const [pm, vulns] of results) {
  const modules = new Set(vulns.map((v) => v.module));
  const missing = REQUIRED_MODULES.filter((m) => !modules.has(m));
  if (missing.length) {
    console.error(`✗ ${pm} did not report: ${missing.join(", ")}`);
    failed = true;
  } else {
    console.log(`✓ ${pm} reported all ${REQUIRED_MODULES.length} direct dependencies`);
  }
}

// 2. Report how the advisory sets differ, for visibility rather than as a gate.
const allIds = new Set([...results.values()].flat().map((v) => v.id));
const shared = [...allIds].filter((id) =>
  [...results.values()].every((vulns) => vulns.some((v) => v.id === id)),
);

console.log(`\n${shared.length} of ${allIds.size} advisories found by every package manager.`);

for (const [pm, vulns] of results) {
  const ids = new Set(vulns.map((v) => v.id));
  const unique = [...allIds].filter((id) => !ids.has(id));
  if (unique.length) {
    console.log(`  ${pm} did not see: ${unique.join(", ")}`);
  }
}

// 3. The same advisory must normalise to the same severity everywhere.
// Disagreement here means the normalisation layer, not the registry, is wrong.
for (const id of shared) {
  const severities = new Map();
  for (const [pm, vulns] of results) {
    const found = vulns.find((v) => v.id === id);
    if (found) severities.set(pm, found.severity);
  }
  const distinct = new Set(severities.values());
  if (distinct.size > 1) {
    console.error(
      `✗ ${id} normalised to different severities: ` +
        [...severities].map(([pm, s]) => `${pm}=${s}`).join(", "),
    );
    failed = true;
  }
}

console.log(failed ? "\n✗ package managers disagree\n" : "\n✓ all package managers agree\n");
process.exit(failed ? 1 : 0);
