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
 */
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(ROOT, "test", "fixtures", "vulnerable-project");
const CLI = join(ROOT, "dist", "cli.js");

/** Advisories every package manager must find in the fixture. */
const EXPECTED_MODULES = ["lodash", "minimist", "axios"];

const SETUPS = {
  npm: {
    corepack: null,
    install: ["npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts"]],
  },
  pnpm: {
    corepack: "pnpm@latest",
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
const setup = SETUPS[target];
if (!setup) {
  console.error(`usage: verify-package-manager.mjs <${Object.keys(SETUPS).join("|")}>`);
  process.exit(2);
}

const workdir = mkdtempSync(join(tmpdir(), `lamassu-verify-${target}-`));
let failed = false;

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

function runCli(args) {
  const result = spawnSync(process.execPath, [CLI, "-d", workdir, "--no-color", ...args], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  return { code: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

try {
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
    if (setup.corepack) {
      execFileSync("corepack", ["prepare", setup.corepack, "--activate"], { stdio: "inherit" });
    }
    const [cmd, args] = setup.install;
    execFileSync(cmd, args, { cwd: workdir, stdio: "inherit" });
  });

  step("audit finds the known vulnerabilities (expect exit 1)", () => {
    const { code, stdout, stderr } = runCli(["--severity", "low"]);
    if (stderr.trim()) console.log(stderr.trim());
    console.log(stdout);
    assert(code === 1, `exit code is 1, got ${code}`);
    for (const mod of EXPECTED_MODULES) {
      assert(stdout.includes(mod), `reported ${mod}`);
    }
  });

  step("machine-readable output is parseable and consistent", () => {
    const { stdout } = runCli(["--severity", "low", "--output", "json"]);
    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      assert(false, "stdout is valid JSON");
      return;
    }
    assert(parsed.passed === false, "reports passed: false");
    assert(parsed.vulnerabilities.length > 0, "lists at least one vulnerability");
    assert(
      parsed.vulnerabilities.every((v) => /^GHSA-/i.test(v.id)),
      "every finding is keyed on a GHSA id",
    );

    // Archive the normalised result so format drift shows up as a CI diff.
    const outDir = join(ROOT, "verify-output");
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, `${target}.json`), stdout);
  });

  step("raising the threshold above everything found passes (expect exit 0)", () => {
    // Nothing in the fixture is critical, so this must pass.
    const { code } = runCli(["--severity", "critical"]);
    assert(code === 0, `exit code is 0, got ${code}`);
  });

  step("an allowlist suppresses a finding", () => {
    writeFileSync(
      join(workdir, "lamassu.json"),
      JSON.stringify({ severity: "low", allowlist: ["lodash|GHSA-35jh-r3h4-6jhm"] }, null, 2),
    );
    const { stdout } = runCli(["--output", "json"]);
    try {
      const parsed = JSON.parse(stdout);
      assert(parsed.suppressed.length > 0, "at least one finding was suppressed");
    } catch {
      assert(false, "stdout is valid JSON with an allowlist in play");
    }
    rmSync(join(workdir, "lamassu.json"));
  });
} catch (err) {
  console.error(`\n✗ ${target}: ${err.message}`);
  failed = true;
} finally {
  rmSync(workdir, { recursive: true, force: true });
}

console.log(failed ? `\n✗ ${target} FAILED\n` : `\n✓ ${target} verified\n`);
process.exit(failed ? 1 : 0);
