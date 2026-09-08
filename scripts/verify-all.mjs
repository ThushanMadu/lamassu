#!/usr/bin/env node
/**
 * Runs the end-to-end verification for every package manager, one at a time,
 * and prints a summary.
 *
 *   node scripts/verify-all.mjs            # every package manager available here
 *   node scripts/verify-all.mjs npm yarn4  # only these
 *
 * Each package manager makes exactly one registry audit call. Registry audit
 * endpoints throttle repeated requests, so this runs them sequentially with a
 * pause in between rather than in parallel - parallel is faster on CI and
 * counter-productive on a home connection.
 *
 *   LAMASSU_VERIFY_GAP_MS=30000   seconds to wait between package managers
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ALL = ["npm", "pnpm", "yarn1", "yarn4", "bun"];

/** Corepack provides yarn and pnpm on demand; bun has to be installed. */
const REQUIRES = {
  npm: { cmd: "npm", hint: "ships with Node" },
  pnpm: { cmd: "corepack", hint: "needs Corepack (ships with Node)" },
  yarn1: { cmd: "corepack", hint: "needs Corepack (ships with Node)" },
  yarn4: { cmd: "corepack", hint: "needs Corepack (ships with Node)" },
  bun: { cmd: "bun", hint: "install with: curl -fsSL https://bun.sh/install | bash" },
};

/**
 * Tools installed outside the system prefix add themselves to an interactive
 * shell profile, which a non-interactive shell never reads - so `which bun`
 * fails on a machine where bun is perfectly well installed. Check the usual
 * install directories too before declaring a package manager missing.
 */
const EXTRA_BIN_DIRS = [
  join(homedir(), ".bun", "bin"),
  join(homedir(), ".volta", "bin"),
  "/opt/homebrew/bin",
  "/usr/local/bin",
];

function have(cmd) {
  if (spawnSync("which", [cmd], { encoding: "utf8" }).status === 0) return true;
  return EXTRA_BIN_DIRS.some((dir) => existsSync(join(dir, cmd)));
}

const requested = process.argv.slice(2).filter((a) => !a.startsWith("-"));
const targets = requested.length ? requested : ALL;

for (const t of targets) {
  if (!ALL.includes(t)) {
    console.error(`unknown package manager "${t}". Choose from: ${ALL.join(", ")}`);
    process.exit(2);
  }
}

if (!existsSync(join(ROOT, "dist", "cli.js"))) {
  console.error("dist/cli.js is missing - run `npm run build` first.");
  process.exit(2);
}

const gapMs = Number(process.env.LAMASSU_VERIFY_GAP_MS ?? 15_000);
const results = [];

console.log(`\nVerifying ${targets.length} package manager(s), one at a time.`);
console.log("Each makes one registry audit call; a slow registry can take minutes.\n");

for (const [i, target] of targets.entries()) {
  const need = REQUIRES[target];
  if (!have(need.cmd)) {
    console.log(`\n${"─".repeat(60)}\n  ${target}: SKIPPED - ${need.cmd} not found (${need.hint})`);
    results.push({ target, status: "skipped", note: `${need.cmd} not installed` });
    continue;
  }

  console.log(`\n${"─".repeat(60)}\n  ${target}  (${i + 1}/${targets.length})\n${"─".repeat(60)}`);
  const started = Date.now();
  const run = spawnSync(process.execPath, [join(ROOT, "scripts", "verify-package-manager.mjs"), target], {
    stdio: "inherit",
    cwd: ROOT,
  });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  results.push({ target, status: run.status === 0 ? "pass" : "fail", seconds });

  // Space out the registry calls, but not after the last one.
  const isLast = i === targets.length - 1;
  if (!isLast && gapMs > 0) {
    console.log(`\n  pausing ${gapMs / 1000}s before the next one (registry throttling)...`);
    // Busy-wait free sleep without pulling in a dependency.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, gapMs);
  }
}

console.log(`\n${"=".repeat(60)}\n  SUMMARY\n${"=".repeat(60)}`);
for (const r of results) {
  const mark = r.status === "pass" ? "✓" : r.status === "skipped" ? "-" : "✗";
  const detail = r.status === "skipped" ? r.note : `${r.seconds}s`;
  console.log(`  ${mark} ${r.target.padEnd(8)} ${r.status.padEnd(8)} ${detail}`);
}

const failed = results.filter((r) => r.status === "fail");
const passed = results.filter((r) => r.status === "pass");
const skipped = results.filter((r) => r.status === "skipped");

console.log(
  `\n  ${passed.length} passed, ${failed.length} failed, ${skipped.length} skipped\n`,
);

if (failed.length) {
  console.log("  A failure here is often the registry throttling rather than a bug.");
  console.log("  Re-run the failing one on its own, or replay a captured run offline:");
  console.log("    LAMASSU_VERIFY_RAW=test/fixtures/yarn4-real-4.9.1.ndjson \\");
  console.log("      node scripts/verify-package-manager.mjs yarn4\n");
}

process.exit(failed.length ? 1 : 0);
