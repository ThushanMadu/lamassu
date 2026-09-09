#!/usr/bin/env node
/**
 * Verifies one package manager end to end against a deliberately vulnerable
 * project.
 *
 * This is what earns the "works with npm, Yarn 1-4, pnpm and Bun" claim. Unit
 * tests prove we parse *recorded* output correctly; this proves we still parse
 * what these tools emit *today*, which is the thing that broke audit-ci.
 *
 *   node scripts/verify-package-manager.mjs npm
 *   node scripts/verify-package-manager.mjs yarn4
 *
 * Offline replay, for when the registry is throttling or you are iterating on
 * the parser:
 *
 *   LAMASSU_VERIFY_RAW=test/fixtures/yarn4-real-4.9.1.ndjson \
 *     node scripts/verify-package-manager.mjs yarn4
 */
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/**
 * On Windows, npm/yarn/pnpm/corepack resolve to `.cmd` shims, and Node's fix
 * for CVE-2024-27980 refuses to spawn those without `shell: true` (throws
 * EINVAL). Mirrors `shouldUseShell()` in src/managers/run.ts - this script
 * drives the same tools from outside the product, so it needs the same fix.
 */
const IS_WINDOWS = process.platform === "win32";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(ROOT, "test", "fixtures", "vulnerable-project");
const CLI = join(ROOT, "dist", "cli.js");

// The library itself, so policy behaviour can be checked against the captured
// output without paying for another network round trip.
//
// import() requires a file:// URL for an absolute path on Windows - a raw
// "D:\..." string trips ERR_UNSUPPORTED_ESM_URL_SCHEME because the loader
// reads the "D:" as a protocol. pathToFileURL() is the correct conversion on
// every platform, so it is used here even though POSIX never needed it.
const { parseAuditOutput, atOrAbove, applyAllowlist, renderTextReport } = await import(
  pathToFileURL(join(ROOT, "dist", "index.js")).href
);

/** Direct dependencies of the fixture: every package manager must find these. */
const EXPECTED_MODULES = ["lodash", "minimist", "axios"];

const SETUPS = {
  npm: {
    corepack: null,
    install: ["npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts"]],
  },
  pnpm: {
    // Pinned, like the Yarns. `pnpm@latest` is not reproducible: pnpm 11+ ships
    // bin/pnpm.mjs where older Corepack expects bin/pnpm.cjs, so "latest" fails
    // on any machine whose Corepack has not been updated. A pinned version means
    // CI and a contributor's laptop run the same thing.
    corepack: "pnpm@10.34.5",
    install: ["pnpm", ["install", "--ignore-scripts", "--no-frozen-lockfile"]],
  },
  yarn1: {
    corepack: "yarn@1.22.22",
    install: ["yarn", ["install", "--ignore-scripts"]],
    packageManager: "yarn",
  },
  yarn4: {
    corepack: "yarn@4.9.1",
    install: ["yarn", ["install", "--mode=skip-build"]],
    packageManager: "yarn",
    // Yarn 4 defaults to PnP; node-modules keeps the fixture closest to what
    // most projects actually use.
    yarnrc: "nodeLinker: node-modules\nenableImmutableInstalls: false\n",
  },
  bun: {
    corepack: null,
    install: ["bun", ["install", "--ignore-scripts"]],
  },
};

const target = process.argv[2];
/**
 * Offline mode. Registry audit endpoints throttle repeated requests hard - 29s
 * for one call and a 300s timeout on the next has been observed. Replaying
 * captured output lets parser and policy changes be checked without paying that
 * cost, and lets CI re-verify an archived format with no network at all.
 */
const offlineRaw = process.env.LAMASSU_VERIFY_RAW;
const setup = SETUPS[target];
if (!setup) {
  console.error(`usage: verify-package-manager.mjs <${Object.keys(SETUPS).join("|")}>`);
  process.exit(2);
}

const workdir = mkdtempSync(join(tmpdir(), `lamassu-verify-${target}-`));
let failed = false;

/**
 * `corepack enable` writes symlinks into the Node bin directory, which usually
 * needs root. `corepack <pm>` works without that, so we put a tiny shim on PATH
 * instead. lamassu spawns `yarn`/`pnpm` directly - exactly as it would on a
 * developer machine - so this stays a faithful test rather than a special case.
 */
const shimDir = mkdtempSync(join(tmpdir(), `lamassu-shims-${target}-`));

function createShim(name) {
  const file = join(shimDir, name);
  writeFileSync(file, `#!/bin/sh\nexec corepack ${name} "$@"\n`);
  chmodSync(file, 0o755);
  return file;
}

/**
 * Install locations that tools add to an interactive shell profile but which a
 * non-interactive shell never sees. bun's installer writes ~/.bun/bin into
 * .zshrc, so `which bun` fails here even on a machine where bun is installed.
 */
const EXTRA_BIN_DIRS = [
  join(homedir(), ".bun", "bin"),
  join(homedir(), ".volta", "bin"),
  "/opt/homebrew/bin",
  "/usr/local/bin",
].filter((d) => existsSync(d));

/** PATH with our shims first, so `yarn` and `pnpm` resolve through corepack. */
function pathWithShims() {
  return {
    ...process.env,
    // `:` on POSIX, `;` on Windows - joining with the wrong one corrupts the
    // real PATH's own delimiters rather than merely adding an unused entry.
    PATH: [shimDir, ...EXTRA_BIN_DIRS, process.env.PATH].filter(Boolean).join(delimiter),
  };
}

function step(name, fn) {
  process.stdout.write(`\n── ${name}\n`);
  return fn();
}

function assert(condition, message) {
  if (condition) {
    console.log(`   ✓ ${message}`);
  } else {
    console.error(`   ✗ ${message}`);
    failed = true;
  }
}

/** Registry audit calls can stall. Fail loudly rather than hanging in silence. */
const CLI_TIMEOUT_MS = Number(process.env.LAMASSU_VERIFY_TIMEOUT_MS ?? 360_000);

function runCli(args, extraEnv = {}) {
  process.stdout.write(`   running: lamassu ${args.join(" ")} ... `);
  const started = Date.now();
  const result = spawnSync(process.execPath, [CLI, "-d", workdir, "--no-color", ...args], {
    encoding: "utf8",
    env: { ...pathWithShims(), NO_COLOR: "1", ...extraEnv },
    timeout: CLI_TIMEOUT_MS,
  });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);

  if (result.error?.code === "ETIMEDOUT" || result.signal === "SIGTERM") {
    console.log(`timed out after ${seconds}s`);
    throw new Error(
      `\`lamassu ${args.join(" ")}\` did not finish within ${CLI_TIMEOUT_MS / 1000}s.\n` +
        `  This is almost always the registry audit endpoint stalling, not lamassu.\n` +
        `  Retry later, or replay a captured run offline:\n` +
        `    LAMASSU_VERIFY_RAW=<captured file> node scripts/verify-package-manager.mjs ${target}`,
    );
  }
  console.log(`exit ${result.status} in ${seconds}s`);
  return { code: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

// Exactly ONE audit call. Registry audit endpoints are slow and throttle
// repeated requests, so everything after this runs against the captured bytes.
const rawFile = join(workdir, "raw-audit-output.txt");
let raw;
let findings;

try {
  if (offlineRaw) console.log(`\n(offline: replaying ${offlineRaw}, no network)`);

  step("prepare fixture", () => {
    cpSync(FIXTURE, workdir, { recursive: true });
    if (setup.packageManager) {
      // Corepack reads this, and so does our own package manager detection.
      const manifest = join(workdir, "package.json");
      const pkg = JSON.parse(readFileSync(manifest, "utf8"));
      pkg.packageManager = setup.corepack;
      writeFileSync(manifest, JSON.stringify(pkg, null, 2));
    }
    if (setup.yarnrc) writeFileSync(join(workdir, ".yarnrc.yml"), setup.yarnrc);
    console.log(`   workdir: ${workdir}`);
  });

  step(`install with ${target}`, () => {
    if (offlineRaw) {
      console.log("   skipped (offline)");
      return;
    }
    const [cmd, args] = setup.install;
    if (setup.corepack) {
      // Download the pinned version, then expose it on PATH via a shim.
      execFileSync("corepack", ["prepare", setup.corepack, "--activate"], {
        stdio: "inherit",
        shell: IS_WINDOWS,
      });
      createShim(cmd);
      console.log(`   shim: ${join(shimDir, cmd)} -> corepack ${cmd}`);
    }
    execFileSync(cmd, args, {
      cwd: workdir,
      stdio: "inherit",
      env: pathWithShims(),
      // Resolve through the extended PATH rather than the parent's. `cmd` here
      // is npm/yarn/pnpm - a `.cmd` shim on Windows - so it needs a shell there.
      shell: IS_WINDOWS,
    });
  });

  step("audit real output from this package manager (expect exit 1)", () => {
    if (offlineRaw) {
      console.log("   skipped (offline)");
      return;
    }
    const { code, stdout, stderr } = runCli(["--severity", "low", "--output", "json"], {
      LAMASSU_DUMP_RAW: rawFile,
    });
    if (stderr.trim()) console.log(`   stderr: ${stderr.trim().split("\n")[0]}`);

    if (code === 2 && /timed out|timeout/i.test(stderr)) {
      console.log(
        `\n   The registry did not answer in time. This is throttling, not a bug.\n` +
          `   Wait a while before retrying, or replay a captured run offline.\n`,
      );
    }
    assert(code === 1, `exit code is 1, got ${code}`);

    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      assert(false, "stdout is valid JSON");
      return;
    }
    assert(parsed.passed === false, "reports passed: false");
    for (const mod of EXPECTED_MODULES) {
      assert(
        parsed.vulnerabilities.some((v) => v.module === mod),
        `reported ${mod}`,
      );
    }

    console.log(
      `   ${parsed.vulnerabilities.length} findings: ` +
        Object.entries(parsed.counts)
          .filter(([, n]) => n > 0)
          .map(([s, n]) => `${n} ${s}`)
          .join(", "),
    );

    // Archive for the cross-check job, which compares package managers.
    const outDir = join(ROOT, "verify-output");
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, `${target}.json`), stdout);
  });

  step("raw output is captured and parses", () => {
    try {
      raw = readFileSync(offlineRaw ?? rawFile, "utf8");
    } catch {
      assert(false, `raw output was written to ${offlineRaw ?? rawFile}`);
      return;
    }
    assert(raw.length > 0, `captured ${raw.length} bytes of raw audit output`);

    // Archive the untouched bytes: if this package manager changes format, this
    // is the artifact that shows exactly what changed.
    const outDir = join(ROOT, "verify-output");
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, `${target}.raw.txt`), raw);

    try {
      findings = parseAuditOutput(raw);
      assert(findings.length > 0, `parser reads ${findings.length} findings from the raw bytes`);
    } catch (err) {
      assert(false, `parser accepts the raw output (${err.message.split("\n")[0]})`);
    }
  });

  // From here on: no network. These exercise policy logic against the real
  // findings this package manager produced.
  step("findings are ordered most severe first (offline)", () => {
    if (!findings) {
      assert(false, "skipped: nothing parsed");
      return;
    }
    // Regression: comparing severity strings sorts them alphabetically
    // (moderate, low, high, critical), burying the worst finding at the bottom.
    const ranks = ["info", "low", "moderate", "high", "critical"];
    const order = findings.map((v) => ranks.indexOf(v.severity));
    assert(
      order.every((r, i) => i === 0 || order[i - 1] >= r),
      `ordered most severe first (${findings[0].severity} first)`,
    );
    assert(
      findings.every((v) => /^GHSA-/i.test(v.id)),
      "every finding is keyed on a GHSA id",
    );
  });

  step("severity threshold filters correctly (offline)", () => {
    if (!findings) {
      assert(false, "skipped: nothing parsed to filter");
      return;
    }
    // Do not assume any level is absent from the fixture: advisories accumulate
    // against pinned versions over time, and an assertion like "nothing here is
    // critical" quietly rots into a false failure.
    const low = atOrAbove(findings, "low");
    const critical = atOrAbove(findings, "critical");
    assert(critical.length <= low.length, `critical (${critical.length}) <= low (${low.length})`);
    assert(
      critical.every((v) => v.severity === "critical"),
      "everything at the critical threshold is actually critical",
    );
  });

  step("allowlist suppresses, and scoping does not over-match (offline)", () => {
    if (!findings) {
      assert(false, "skipped: nothing parsed to allowlist");
      return;
    }
    const first = findings[0];
    const scoped = applyAllowlist(findings, [`${first.module}|${first.id}`]);
    assert(scoped.suppressed.length === 1, "a scoped entry suppresses exactly its own finding");
    assert(scoped.unused.length === 0, "a matching entry is not reported as unused");

    // The same advisory id attributed to a different package must not match.
    const wrongModule = applyAllowlist(findings, [`definitely-not-a-real-package|${first.id}`]);
    assert(
      wrongModule.suppressed.length === 0,
      "an entry scoped to another package suppresses nothing",
    );
    assert(wrongModule.unused.length === 1, "and is reported as unused");

    const everything = applyAllowlist(
      findings,
      findings.map((v) => `${v.module}|${v.id}`),
    );
    assert(everything.remaining.length === 0, "allowlisting every finding leaves nothing");
  });

  step("text report renders a pastable allowlist line (offline)", () => {
    if (!findings) {
      assert(false, "skipped: nothing parsed to render");
      return;
    }
    const text = renderTextReport(applyAllowlist(findings, []), {
      colour: false,
      severity: "low",
      packageManager: target,
      failOnUnusedAllowlist: false,
    });
    assert(text.includes("allowlist as:"), "prints a ready-to-paste allowlist line");
    assert(text.includes(findings[0].module), `names ${findings[0].module}`);
  });
} catch (err) {
  console.error(`\n✗ ${target}: ${err.message}`);
  failed = true;
} finally {
  // Keep the workdir when something went wrong so it can be inspected by hand.
  if (failed) {
    console.error(`\n  Fixture left in place for debugging:\n    cd ${workdir}`);
  } else {
    rmSync(workdir, { recursive: true, force: true });
  }
  rmSync(shimDir, { recursive: true, force: true });
}

console.log(failed ? `\n✗ ${target} FAILED\n` : `\n✓ ${target} verified\n`);
process.exit(failed ? 1 : 0);
