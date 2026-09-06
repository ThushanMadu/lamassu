# lamassu

**Fail your CI build on vulnerable dependencies.** Works with npm, Yarn 1–4, pnpm and Bun.

> In Assyria, colossal winged guardians stood at every city gate.
> Nothing harmful passed.

[![CI](https://github.com/ThushanMadu/lamassu/actions/workflows/ci.yml/badge.svg)](https://github.com/ThushanMadu/lamassu/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/lamassu.svg)](https://www.npmjs.com/package/lamassu)
[![license](https://img.shields.io/npm/l/lamassu.svg)](./LICENSE)

```bash
npx lamassu
```

```
lamassu - npm, failing at high and above

  HIGH     lodash  Command Injection in lodash
           affects <4.17.21 - found 4.17.15 - fix available
           https://github.com/advisories/GHSA-35jh-r3h4-6jhm
           allowlist as: lodash|GHSA-35JH-R3H4-6JHM

FAIL  1 finding: 1 high
```

Exit code `1`. Your pipeline stops.

---

## Why this exists

[`audit-ci`](https://github.com/IBM/audit-ci) has done this job for years, but it was last published in **July 2024** and its maintainer has [publicly confirmed](https://github.com/IBM/audit-ci/issues/354) he lost access to the repository.

Meanwhile Yarn 4 changed its audit output to NDJSON. `audit-ci` never adapted, so teams are [running an eight-year-old Yarn](https://github.com/IBM/audit-ci/issues/332) just to audit their dependencies:

```bash
# what people are doing today
npx yarn@1.22.19 audit-ci --config ./audit-ci.jsonc
```

`lamassu` is a from-scratch replacement that speaks every current audit format.

## Install

```bash
npm install --save-dev lamassu
```

Or run it without installing:

```bash
npx lamassu
```

## Usage

```bash
lamassu                          # fail on high and critical (default)
lamassu --severity moderate      # be stricter
lamassu --skip-dev               # ignore devDependencies
lamassu --output json            # machine-readable
lamassu --timeout 600            # slow registry? give it longer
```

Registry audit endpoints can be slow — a three-dependency project has been
observed taking over two minutes. The default wait is 300 seconds; raise it with
`--timeout` if your network or CI runner needs more.

It detects your package manager from `packageManager` in `package.json`, then from your lockfile. Override it with `--package-manager` if you need to.

## Migrating from audit-ci

**Change one line.** Your existing `audit-ci.jsonc` is read as-is.

```diff
- "audit": "audit-ci --config ./audit-ci.jsonc"
+ "audit": "lamassu"
```

lamassu finds `audit-ci.json`, `audit-ci.jsonc` or `.audit-ci.jsonc`, translates it, and tells you what it did:

```
lamassu: using audit-ci.jsonc in audit-ci compatibility mode
```

Options with no equivalent (`retry-count`, `report-type`, `registry`) produce a note rather than an error, so nothing breaks on the way in.

### What is different

| | audit-ci | lamassu |
|---|---|---|
| Yarn 4 | ❌ [unsupported since 2024](https://github.com/IBM/audit-ci/issues/332) | ✅ |
| Bun | ❌ | ✅ |
| Runtime dependencies | 9 | **0** |
| Allowlist scoping | advisory id only | advisory, package, or exact version |
| Dead allowlist entries | silently kept | reported, and `--fail-unused` enforces |
| Allowlist expiry | — | `expires` with a real date |
| Maintained | last publish July 2024 | yes |

## Allowlist

Suppress a finding you have consciously accepted. Entries are ordered here from broadest to narrowest:

```jsonc
{
  "allowlist": [
    "GHSA-xxxx-xxxx-xxxx",                  // this advisory, anywhere
    "lodash|GHSA-xxxx-xxxx-xxxx",           // only when it is lodash
    "lodash@4.17.15|GHSA-xxxx-xxxx-xxxx"    // only that installed version
  ]
}
```

**Prefer the scoped forms.** A bare advisory id suppresses that advisory wherever it appears — including somewhere you never intended, in a package added months later. This is a [real defect in audit-ci](https://github.com/IBM/audit-ci/issues/356), and scoping is how you avoid it. Every finding lamassu prints includes the exact line to paste.

### Expiring an exception

An accepted risk should be revisited, not forgotten:

```jsonc
{
  "allowlist": [
    {
      "id": "GHSA-yyyy-yyyy-yyyy",
      "module": "axios",
      "expires": "2026-12-31",
      "reason": "no fix released upstream; tracked in JIRA-123"
    }
  ]
}
```

After that date the entry stops suppressing and the build fails again.

### Finding dead entries

Entries that match nothing usually mean the vulnerability was fixed and the exception can go:

```
WARN  1 allowlist entry matched nothing (likely fixed - safe to delete):
        GHSA-vh95-rmgr-6w4m (minimist)
```

Add `--fail-unused` to make that an error and keep allowlists from rotting.

## Configuration

`lamassu.json` or `lamassu.jsonc` in your project root. Comments are allowed.

```jsonc
{
  // Lowest severity that fails the build.
  // info | low | moderate | high | critical
  "severity": "high",

  "allowlist": [],

  // auto | npm | yarn | pnpm | bun
  "packageManager": "auto",

  "skipDev": false,
  "failOnUnusedAllowlist": false,

  // text | json
  "output": "text",

  // Seconds to wait for the package manager's audit before giving up.
  "timeoutSeconds": 300
}
```

Command line options override the file. Unknown options are rejected rather than ignored, because a typo in a security policy should not fail quietly.

## Exit codes

```
0   passed
1   vulnerabilities found at or above the threshold
2   the audit could not be run
```

**`2` is never `0`.** If the package manager is missing, the network is unreachable, or the audit output is unrecognisable, lamassu fails loudly. A gate that cannot run must not look like a gate that passed — that is the failure that lets a vulnerable build through unnoticed.

## CI recipes

### GitHub Actions

```yaml
- run: npx lamassu --severity high
```

### GitLab CI

```yaml
audit:
  script:
    - npx lamassu --severity high
```

### CircleCI

```yaml
- run:
    name: Audit dependencies
    command: npx lamassu --severity high
```

## Programmatic use

```ts
import { audit, DEFAULT_CONFIG } from "lamassu";

const result = await audit({ ...DEFAULT_CONFIG, severity: "moderate", directory: process.cwd() });

if (!result.passed) {
  for (const v of result.report.remaining) {
    console.log(`${v.severity} ${v.module} ${v.id}`);
  }
}
```

You can also parse audit output you already have, without running anything:

```ts
import { parseAuditOutput } from "lamassu";

const vulnerabilities = parseAuditOutput(rawJsonFromAnyPackageManager);
```

## How it works

Package managers emit at least five different JSON shapes for the same data, and they change between major versions — which is exactly how `audit-ci` broke.

So lamassu **detects the shape** rather than trusting a package manager to emit a documented one:

| Shape | Emitted by |
|---|---|
| `{auditReportVersion: 2, ...}` | npm 7+ |
| `{advisories: {...}}` | npm 6, pnpm, Yarn 2–3, Bun |
| NDJSON `{type: "auditAdvisory"}` | Yarn 1 |
| NDJSON `{value, children}` | Yarn 4 |
| `{"pkg": [{id, ...}]}` | Yarn 4 `--recursive` |

Everything normalises to a single record keyed on the **GHSA id** — the only identifier stable across ecosystems.

When a format changes upstream, that is one more small parser, not a rewrite. And CI audits a deliberately vulnerable project with every package manager on every run, so drift shows up as a failing build here rather than a bug report from you.

## Contributing

```bash
npm install
npm run typecheck
npm test
npm run build
```

To check a package manager end to end:

```bash
node scripts/verify-package-manager.mjs npm
```

Found output we do not parse? Open an issue with the raw JSON — that is the most useful bug report you can file.

## License

MIT
