<div align="center">

# bartizan

**Fail your CI build when a dependency has a known vulnerability.**
Works with npm, Yarn 1–4, pnpm and Bun. Zero runtime dependencies.

[![CI](https://github.com/ThushanMadu/bartizan/actions/workflows/ci.yml/badge.svg)](https://github.com/ThushanMadu/bartizan/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/bartizan?color=cb3837&logo=npm&logoColor=white)](https://www.npmjs.com/package/bartizan)
[![downloads](https://img.shields.io/npm/dm/bartizan?color=cb3837)](https://www.npmjs.com/package/bartizan)
[![node](https://img.shields.io/node/v/bartizan?color=339933&logo=node.js&logoColor=white)](https://www.npmjs.com/package/bartizan)
[![types](https://img.shields.io/npm/types/bartizan?color=3178c6&logo=typescript&logoColor=white)](https://www.npmjs.com/package/bartizan)
[![license](https://img.shields.io/npm/l/bartizan?color=blue)](./LICENSE)

</div>

---

`bartizan` is a security gate for CI. It runs your package manager's audit, reads
whatever output it produces, and fails the build when a dependency has a known
vulnerability at or above a severity you choose. One command, one clear
pass/fail — nothing to configure to get started.

- **Every current package manager** — npm, Yarn 1, Yarn 2–4, pnpm, Bun. It
  detects yours automatically.
- **Format-agnostic parser** — package managers emit five different JSON shapes
  for the same data and change them between majors. bartizan detects the shape
  rather than trusting a documented one, so an upstream change is one small
  parser, not a broken tool.
- **Scoped allowlist** — suppress an advisory globally, per package, or per exact
  installed version. Entries can carry an `expires` date, and dead entries are
  reported instead of rotting silently.
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
$ npx bartizan

  bartizan - npm, failing at high and above

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

> **New to this?** The [**user guide**](docs/guide.md) walks through install,
> first run, wiring it into CI, and what to do when it finds something. The
> sections below are the reference.

## Contents

- [Install](#install)
- [Usage](#usage)
- [Exit codes](#exit-codes)
- [Allowlist](#allowlist)
- [Configuration](#configuration)
- [Programmatic API](#programmatic-api)
- [How the parser works](#how-the-parser-works)
- [Limitations](#limitations)
- [FAQ](#faq)
- [Replacing `audit-ci`](#replacing-audit-ci)
- [Contributing](#contributing)

## Install

Run it once without installing:

```bash
npx bartizan
```

Or add it as a dev dependency:

```bash
npm install --save-dev bartizan
```

Requires Node.js 20 or later. The package is ESM-only.

## Usage

```bash
npx bartizan                       # fail on high and critical (default)
npx bartizan --severity moderate   # stricter
npx bartizan --skip-dev            # ignore devDependencies
npx bartizan --output json         # machine-readable
npx bartizan --timeout 600         # give a slow registry more time
```

Installed as a dependency, the bare `bartizan` command works **inside an npm
script** — `"audit": "bartizan --severity high"`, then `npm run audit` — or via
`npx bartizan`. It is not on your shell PATH unless you install it globally
(`npm i -g bartizan`).

In CI — the same line works for GitHub Actions, GitLab CI and CircleCI:

```yaml
- run: npx bartizan --severity high
```

The package manager is detected from `packageManager` in `package.json`, then
from the lockfile. Override it with `--package-manager` if needed.

## Exit codes

| Code | Meaning |
|:---:|---|
| `0` | Clean — nothing at or above the threshold |
| `1` | Vulnerabilities found — the build should stop |
| `2` | The audit could not be run |

Exit `2` is never collapsed to `0`. If the package manager is missing, the
registry is unreachable, or the output is in a shape bartizan doesn't recognise,
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
finding bartizan prints includes the exact line to paste.

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

`bartizan.json` or `bartizan.jsonc` in the project root (also `.bartizanrc` /
`.bartizanrc.json`). Comments are allowed:

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
import { audit, DEFAULT_CONFIG } from "bartizan";

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
import { parseAuditOutput } from "bartizan";

const vulnerabilities = parseAuditOutput(rawJsonFromAnyPackageManager);
```

## How the parser works

Package managers emit at least five JSON structures for the same information, and
change them between major versions — which is how `audit-ci` broke. bartizan
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
small parser. If bartizan receives output it cannot place, it exits `2`; it never
guesses "clean."

## Limitations

- **One directory per run.** No monorepo workspace walking — run it per package,
  or in each workspace's CI job.
- **No auto-fix.** It reports the fixed version when the package manager provides
  one; applying it is your decision.
- **No SARIF output yet** — findings don't appear in GitHub's Security tab as
  native alerts. `--output json` is the interim path.
- **Only as accurate as the registry it queries.** If the advisory endpoint is
  down or unaware of a vulnerability, bartizan is too — but a network failure
  exits `2`, not `0`.
- **Yarn Plug'n'Play is untested.** CI verifies Yarn 4 with the `node-modules`
  linker. PnP should work but isn't in the matrix yet.

Found a gap that isn't listed?
[Open an issue.](https://github.com/ThushanMadu/bartizan/issues/new/choose)

## FAQ

**How do I fail a CI build when a dependency has a known vulnerability?**
Add `npx bartizan --severity high` as a step in your pipeline. It exits non-zero
when anything at or above your threshold is found, which fails the build. See
[Usage](#usage).

**How is this different from `npm audit`?**
`npm audit` exits non-zero for vulnerabilities *and* for network errors, so a
flaky registry looks like a finding. It also has no severity gate, no allowlist
with expiry, and its JSON differs from Yarn's, pnpm's and Bun's. bartizan gives
one clear pass / fail / could-not-run signal across all of them.

**Does it work with Yarn 4, pnpm, and Bun?**
Yes — Yarn 1 through 4, pnpm, and Bun, plus npm. It detects which one your
project uses. Each is checked against a real audit in CI on every commit.

**Is this an `audit-ci` replacement?**
Yes. `audit-ci` is unmaintained and doesn't support Yarn 4. bartizan reads your
existing `audit-ci.json` unchanged — see [Replacing `audit-ci`](#replacing-audit-ci).

**Does it phone home or send my data anywhere?**
No. It only calls your package manager's audit command, which talks to the
registry *you* have configured. bartizan has zero runtime dependencies and never
writes to your project.

**Can I use it in a monorepo?**
One directory per run — invoke it in each workspace's CI job, or per package.
Workspace walking isn't built in yet.

**What Node version does it need?**
Node.js 20 or newer. The package is ESM-only.

## Replacing `audit-ci`

[`audit-ci`](https://github.com/IBM/audit-ci) is the tool most projects have used
for this. It was last published in **July 2024**; its maintainer has
[said](https://github.com/IBM/audit-ci/issues/354) he no longer has access to the
repository, and Yarn 4's NDJSON audit output
[remains unsupported](https://github.com/IBM/audit-ci/issues/332). bartizan works
as a drop-in replacement: it reads your existing `audit-ci.json` / `.jsonc`
(with or without a leading dot), so switching is one line in your CI script.

```diff
- "audit": "audit-ci --config ./audit-ci.jsonc"
+ "audit": "bartizan"
```

```console
bartizan: using audit-ci.jsonc in audit-ci compatibility mode
```

Options with no bartizan equivalent (`retry-count`, `report-type`, `registry`)
produce a note rather than an error.

**Allowlist entries.** Bare advisory ids (`GHSA-…`) carry over unchanged.
audit-ci writes a scoped entry as `GHSA-…|package`; bartizan writes it the other
way round, as `package|GHSA-…`, and flips yours automatically on load. audit-ci's
dependency-path entries (`GHSA-…|a>b>c`) and `*` wildcards have no bartizan
equivalent — they are reported on load and must be re-written as `package|GHSA-…`
or `package@version|GHSA-…`.

### What differs

|  | `audit-ci` | `bartizan` |
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

## Contributing

See **[CONTRIBUTING.md](./CONTRIBUTING.md)** for development setup, how to add
support for a new audit format, and what a good PR looks like.

```bash
npm install
npm run typecheck
npm test
npm run build
```

If `bartizan` exits `2` with "could not recognise the audit output," that is the
single most useful bug report this project can receive —
[use this template](https://github.com/ThushanMadu/bartizan/issues/new?template=unparsed-output.md)
and include the raw output.

## License

[MIT](./LICENSE)

<sub>A bartizan is the small overhanging turret on a castle wall — the position a defender watches the approach from.</sub>
