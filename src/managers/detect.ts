import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { PackageManager } from "../types.js";

const LOCKFILES: [string, PackageManager][] = [
  ["package-lock.json", "npm"],
  ["npm-shrinkwrap.json", "npm"],
  ["yarn.lock", "yarn"],
  ["pnpm-lock.yaml", "pnpm"],
  ["bun.lock", "bun"],
  ["bun.lockb", "bun"],
];

/**
 * `packageManager` in package.json is the most reliable signal because Corepack
 * enforces it, so we prefer it over guessing from lockfiles.
 */
function fromPackageJson(dir: string): PackageManager | undefined {
  const file = join(dir, "package.json");
  if (!existsSync(file)) return undefined;
  try {
    const pkg = JSON.parse(readFileSync(file, "utf8"));
    const name = String(pkg.packageManager ?? "").split("@")[0];
    if (name === "npm" || name === "yarn" || name === "pnpm" || name === "bun") return name;
  } catch {
    /* a malformed package.json is not our problem to report here */
  }
  return undefined;
}

export function detectPackageManager(dir: string): PackageManager {
  const declared = fromPackageJson(dir);
  if (declared) return declared;
  for (const [file, pm] of LOCKFILES) if (existsSync(join(dir, file))) return pm;
  return "npm";
}
