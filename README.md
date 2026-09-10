<div align="center">

# lamassu

**Fail your CI build when a dependency has a known vulnerability.**
Works with npm, Yarn 1–4, pnpm and Bun. Zero runtime dependencies.

[![CI](https://github.com/ThushanMadu/lamassu/actions/workflows/ci.yml/badge.svg)](https://github.com/ThushanMadu/lamassu/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/lamassu?color=cb3837&logo=npm&logoColor=white)](https://www.npmjs.com/package/lamassu)
[![downloads](https://img.shields.io/npm/dm/lamassu?color=cb3837)](https://www.npmjs.com/package/lamassu)
[![node](https://img.shields.io/node/v/lamassu?color=339933&logo=node.js&logoColor=white)](https://www.npmjs.com/package/lamassu)
[![types](https://img.shields.io/npm/types/lamassu?color=3178c6&logo=typescript&logoColor=white)](https://www.npmjs.com/package/lamassu)
[![license](https://img.shields.io/npm/l/lamassu?color=blue)](./LICENSE)

</div>

---

`lamassu` is a maintained, from-scratch replacement for
[`audit-ci`](https://github.com/IBM/audit-ci) — a security gate for CI that reads
your package manager's audit output and stops the build if anything crosses a
severity threshold you set.

- **Every current package manager** — npm, Yarn 1, Yarn 2–4, pnpm, Bun. It
  detects yours automatically.
- **Format-agnostic parser** — package managers emit five different JSON shapes
  for the same data and change them between majors. lamassu detects the shape
  rather than trusting a documented one, so an upstream change is one small
  parser, not a broken tool.
- **Scoped allowlist** — suppress an advisory globally, per package, or per exact
  installed version. Entries can carry an `expires` date, and dead entries are
  reported instead of rotting silently.
- **`audit-ci` compatible** — reads your existing `audit-ci.json` / `.jsonc`:
  severity, package manager, skip-dev and bare-advisory allowlist entries carry
  over, so migrating is a one-line change to your CI script. Path and wildcard
  allowlist entries are reported on load (see [Migrating](#migrating-from-audit-ci)).
- **Fails loud, never silent** — exit `2` for "couldn't audit" (missing package
  manager, unreachable registry, unrecognised output). A gate that can't run must
  not look like one that passed.
- **Zero runtime dependencies** — a security tool you install is one you have to
  trust, so `dependencies` stays empty.
- **CI-verified per package manager** — every push runs a real audit through
  npm, Yarn 1, Yarn 4, pnpm and Bun on Linux, and through npm on Windows,
  against both a vulnerable project and a clean one. The compatibility claims
  are re-earned, not assumed.

```console
$ npx lamassu

  lamassu - npm, failing at high and above

  CRITICAL minimist  Prototype Pollution
           affects <1.2.6 - fix available
           https://github.com/advisories/GHSA-xvch-5gv4-984h
           allowlist as: minimist|GHSA-xvch-5gv4-984h

  HIGH     lodash  Command Injection in lodash
           affects <4.17.21 - fix available
           https://github.com/advisories/GHSA-35jh-r3h4-6jhm
           allowlist as: lodash|GHSA-35jh-r3h4-6jhm

  FAIL  2 findings: 1 critical, 1 high

$ echo $?
1
```

Findings are ordered worst-first, and each prints the exact line to allowlist it.

## Contents

- [Install](#install)
- [Usage](#usage)
- [Comparison with `audit-ci`](#comparison-with-audit-ci)
- [Migrating from `audit-ci`](#migrating-from-audit-ci)
- [Exit codes](#exit-codes)
- [Allowlist](#allowlist)
- [Configuration](#configuration)
- [Programmatic API](#programmatic-api)
- [How the parser works](#how-the-parser-works)
- [Limitations](#limitations)
- [Contributing](#contributing)

## Install

```bash
npm install --save-dev lamassu
```

Or run it without installing:

```bash
npx lamassu
```

Requires Node.js 20 or later. The package is ESM-only.

## Usage

```bash
lamassu                       # fail on high and critical (default)
lamassu --severity moderate   # stricter
lamassu --skip-dev            # ignore devDependencies
lamassu --output json         # machine-readable
lamassu --timeout 600         # give a slow registry more time
```

In CI — the same line works for GitHub Actions, GitLab CI and CircleCI:

```yaml
- run: npx lamassu --severity high
```

The package manager is detected from `packageManager` in `package.json`, then
from the lockfile. Override it with `--package-manager` if needed.

## Comparison with `audit-ci`

`audit-ci` was last published in **July 2024**. Its maintainer has
[stated](https://github.com/IBM/audit-ci/issues/354) he no longer has access to
the repository, and Yarn 4's move to NDJSON audit output
[remains unsupported](https://github.com/IBM/audit-ci/issues/332) — teams work
around it by running an eight-year-old Yarn just to audit.

|  | `audit-ci` | `lamassu` |
|---|:---:|:---:|
| Yarn 4 audit output | not supported ([#332](https://github.com/IBM/audit-ci/issues/332)) | supported |
| Bun | via `bun.lockb` → `yarn.lock`, needs Yarn 1 installed | native `bun audit` |
| Windows | not covered in CI | npm audit CI-verified |
| Runtime dependencies | 9 | 0 |
| Allowlist scoping | advisory id, or dependency path with `*` wildcards | advisory id, package, or installed version |
| Unused allowlist entries | reported (`show-not-found`) | reported, and `--fail-unused` fails the build |
| Allowlist expiry | metadata field, not enforced | `expires` — the entry fails the build once the date passes |
| Clean-build case tested | — | per package manager, in CI |
| Actively maintained | no ([#354](https://github.com/IBM/audit-ci/issues/354)) | yes |

## Migrating from `audit-ci`

Your existing config is read as-is — `audit-ci.json` or `.jsonc`, with or
without a leading dot. Change one line in your CI script:

```diff
- "audit": "audit-ci --config ./audit-ci.jsonc"
+ "audit": "lamassu"
```

```console
lamassu: using audit-ci.jsonc in audit-ci compatibility mode
```

Options with no lamassu equivalent (`retry-count`, `report-type`, `registry`)
produce a note rather than an error.

**Allowlist.** Bare advisory ids (`GHSA-…`) carry over unchanged. audit-ci
writes a scoped entry as `GHSA-…|package`; lamassu writes it the other way
round, as `package|GHSA-…`, and flips yours automatically on load. audit-ci's
dependency-path entries (`GHSA-…|a>b>c`) and `*` wildcards have no lamassu
equivalent — they are reported on load and must be re-written as
`package|GHSA-…` or `package@version|GHSA-…`.

## Exit codes

| Code | Meaning |
|:---:|---|
| `0` | Clean — nothing at or above the threshold |
| `1` | Vulnerabilities found — the build should stop |
| `2` | The audit could not be run |

Exit `2` is never collapsed to `0`. If the package manager is missing, the
registry is unreachable, or the output is in a shape lamassu doesn't recognise,
it fails loudly — the failure this tool exists to prevent is a broken gate that
reports a pass.

## Allowlist

Suppress a finding you have consciously accepted. Scopes go from broad to narrow:

```jsonc
{
  "allowlist": [
    "GHSA-xxxx-xxxx-xxxx",                 // this advisory, anywhere
    "lodash|GHSA-xxxx-xxxx-xxxx",          // only in lodash
    "lodash@4.17.15|GHSA-xxxx-xxxx-xxxx"   // only that installed version
  ]
}
```

Prefer the scoped forms. A bare advisory id suppresses that advisory everywhere,
including in a package added months later —
[a known problem in audit-ci](https://github.com/IBM/audit-ci/issues/356). Every
finding lamassu prints includes the exact line to paste.

> **npm and version scoping:** `package@version|GHSA-…` needs the *installed*
> version. npm's `npm audit --json` (v7+) reports affected ranges but not
> resolved versions, so use the `package|GHSA-…` form under npm. Yarn, pnpm and
> Bun report versions and match fully.

An accepted risk should be revisited, not forgotten:

```jsonc
{
  "allowlist": [
    {
      "id": "GHSA-yyyy-yyyy-yyyy",
      "module": "axios",
      "expires": "2027-06-30",
      "reason": "no upstream fix yet — tracked in JIRA-123"
    }
  ]
}
```

After `expires`, the entry stops suppressing and the build fails again.

An entry that matches nothing usually means the vulnerability was fixed:

```console
WARN  1 allowlist entry matched nothing (likely fixed — safe to delete):
        GHSA-vh95-rmgr-6w4m (minimist)
```

`--fail-unused` turns that into a build failure.

## Configuration

`lamassu.json` or `lamassu.jsonc` in the project root (also `.lamassurc` /
`.lamassurc.json`). Comments are allowed:

```jsonc
{
  "severity": "high",          // info | low | moderate | high | critical
  "allowlist": [],
  "packageManager": "auto",    // auto | npm | yarn | pnpm | bun
  "skipDev": false,
  "failOnUnusedAllowlist": false,
  "output": "text",            // text | json
  "timeoutSeconds": 300
}
```

CLI flags override the file. Unknown keys are rejected rather than ignored — a
typo in a security policy should not fail quietly.

## Programmatic API

```ts
import { audit, DEFAULT_CONFIG } from "lamassu";

const result = await audit({
  ...DEFAULT_CONFIG,
  severity: "moderate",
  directory: process.cwd(),
});

if (!result.passed) {
  for (const v of result.report.remaining) {
    console.log(`${v.severity}  ${v.module}  ${v.id}`);
  }
}
```

Or parse audit output you already have, with no package manager involved:

```ts
import { parseAuditOutput } from "lamassu";

const vulnerabilities = parseAuditOutput(rawJsonFromAnyPackageManager);
```

## How the parser works

Package managers emit at least five JSON structures for the same information, and
change them between major versions — which is how `audit-ci` broke. lamassu
detects the structure rather than trusting a documented format:

| Output shape | Emitted by |
|---|---|
| `{ auditReportVersion: 2, … }` | npm 7+ |
| `{ advisories: { … } }` | npm 6, pnpm, Yarn 2–3, Bun |
| NDJSON `{ type: "auditAdvisory" }` | Yarn 1 |
| NDJSON `{ value, children }` | Yarn 4 |
| `{ "<pkg>": [ { id, … } ] }` | Yarn 4 `--recursive` |

Everything normalises to one record per advisory, keyed on the **GHSA id** — the
only identifier stable across ecosystems. A format change upstream is one more
small parser. If lamassu receives output it cannot place, it exits `2`; it never
guesses "clean."

## Limitations

- **One directory per run.** No monorepo workspace walking — run it per package,
  or in each workspace's CI job.
- **No auto-fix.** It reports the fixed version when the package manager provides
  one; applying it is your decision.
- **No SARIF output yet** — findings don't appear in GitHub's Security tab as
  native alerts. `--output json` is the interim path.
- **Only as accurate as the registry it queries.** If the advisory endpoint is
  down or unaware of a vulnerability, lamassu is too — but a network failure
  exits `2`, not `0`.
- **Yarn Plug'n'Play is untested.** CI verifies Yarn 4 with the `node-modules`
  linker. PnP should work but isn't in the matrix yet.

Found a gap that isn't listed?
[Open an issue.](https://github.com/ThushanMadu/lamassu/issues/new/choose)

## Contributing

See **[CONTRIBUTING.md](./CONTRIBUTING.md)** for development setup, how to add
support for a new audit format, and what a good PR looks like.

```bash
npm install
npm run typecheck
npm test
npm run build
```

If `lamassu` exits `2` with "could not recognise the audit output," that is the
single most useful bug report this project can receive —
[use this template](https://github.com/ThushanMadu/lamassu/issues/new?template=unparsed-output.md)
and include the raw output.

## License

[MIT](./LICENSE)

<sub>Named for the lamassu — the human-headed winged bulls that stood guard at the gates of Assyrian cities.</sub>
