# bartizan — user guide

A walkthrough from zero to a working CI security gate.

## What bartizan does

Your package manager already checks dependencies against a database of known
vulnerabilities — `npm audit`, `yarn npm audit`, `pnpm audit`, `bun audit`. What
it doesn't do well is give a CI build a clean pass/fail signal: the output
formats differ per tool and change between versions, `npm audit` exits non-zero
for findings *and* for network errors, and there's no built-in way to say "fail
on high and above, but I've accepted this one advisory until it's fixed."

bartizan is that layer. It runs your package manager's audit, understands the
known audit output formats, and turns the result into one decision:

| Exit code | Meaning |
|:---:|---|
| `0` | Nothing at or above your threshold — build continues |
| `1` | Vulnerabilities found — build stops |
| `2` | The audit itself could not run (offline, missing tool, unreadable output) — build stops |

Exit `2` is never collapsed to `0`: a gate that can't check must not look like
one that passed.

bartizan changes nothing — no writes to `package.json`, the lockfile, or
`node_modules`.

## 1. Try it, no install

In any project with a lockfile:

```bash
npx bartizan
```

`npx` downloads bartizan into a cache, runs it once, and doesn't touch your
project. Good for a first look. You'll see something like:

```
bartizan - npm, failing at high and above

  HIGH     postcss  PostCSS: Path Traversal in Previous Source Map Auto-Loading
           affects <=8.5.17 - fix available
           https://github.com/advisories/GHSA-r28c-9q8g-f849
           allowlist as: postcss|GHSA-r28c-9q8g-f849

FAIL  1 finding: 1 high
```

Each finding shows the package, the advisory, the affected range, whether a fix
exists, a link, and **the exact line to allowlist it** if you decide to accept
it.

Check the exit code:

```bash
npx bartizan; echo "exit: $?"
```

`1` means it found something — that's the number CI reads.

## 2. Install it into the project

For anything beyond a first look, add it as a dev dependency:

```bash
npm i -D bartizan
```

Now — and this is the part that trips people up — the bare command `bartizan`
still won't work in your shell:

```
$ bartizan
zsh: command not found: bartizan
```

That's expected. A locally-installed package's command lives in
`node_modules/.bin/`, which is not on your PATH. Run it one of three ways:

```bash
npx bartizan
```

```bash
./node_modules/.bin/bartizan
```

Or, most commonly, from an npm script — inside a script, `bartizan` resolves
automatically:

```jsonc
// package.json
"scripts": {
  "audit": "bartizan --severity high"
}
```

```bash
npm run audit
```

That script form is what you'll use in CI. (If you want `bartizan` on your PATH
everywhere for poking at other repos: `npm i -g bartizan`. Not needed for CI.)

## 3. Choose a threshold

The default is `high` — fail on `high` and `critical`. Levels, lowest to
highest: `info`, `low`, `moderate`, `high`, `critical`.

```bash
npx bartizan --severity moderate
```

Start at `high`. Tighten to `moderate` once you're consistently clean.

## 4. Wire it into CI

**GitHub Actions:**

```yaml
name: audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci
      - run: npx bartizan --severity high
```

**GitLab CI:**

```yaml
audit:
  image: node:22
  script:
    - npm ci
    - npx bartizan --severity high
```

**CircleCI and others** — same command, `npx bartizan --severity high`, as a
build step.

Then open a pull request that adds a vulnerable dependency (for example
`npm i lodash@4.17.15`) and confirm the check goes red. That proves the gate is
actually connected, not just present.

## 5. Handle a finding

When bartizan fails, you have three options per advisory.

### a. Fix it

Most findings say "fix available":

```bash
npm audit fix
```

If that doesn't clear it, the vulnerable package is pinned by something else.
Find out what:

```bash
npm why postcss
```

Then bump whatever is holding it back.

### b. Accept it, with a deadline

No upstream fix yet? Allowlist it. Create `bartizan.jsonc` in the project root:

```jsonc
{
  "severity": "high",
  "allowlist": [
    {
      "id": "GHSA-r28c-9q8g-f849",
      "module": "postcss",
      "expires": "2027-06-30",
      "reason": "transitive via build tool, waiting on upstream — TICKET-123"
    }
  ]
}
```

After `expires`, the entry stops suppressing and the build fails again — so an
accepted risk gets revisited instead of forgotten silently.

The short form works too, and bartizan prints it for you in the report:

```jsonc
{ "allowlist": ["postcss|GHSA-r28c-9q8g-f849"] }
```

Scopes, broad to narrow:

| Form | Matches |
|---|---|
| `GHSA-xxxx-xxxx-xxxx` | this advisory in any package |
| `postcss\|GHSA-xxxx-xxxx-xxxx` | only when it's `postcss` |
| `postcss@8.4.0\|GHSA-xxxx-xxxx-xxxx` | only that installed version |

Prefer the scoped forms — a bare advisory id also suppresses the same advisory
in a package added months later.

### c. Ignore devDependencies

If the finding is only in build tooling and you've decided that's acceptable:

```bash
npx bartizan --skip-dev
```

## 6. Keep the allowlist honest

When an allowlisted advisory is fixed upstream, its entry now matches nothing.
bartizan reports that:

```
WARN  1 allowlist entry matched nothing (likely fixed — safe to delete):
        postcss|GHSA-r28c-9q8g-f849
```

Turn that into a build failure so dead entries don't accumulate:

```bash
npx bartizan --fail-unused
```

## How it works

Six steps, every run:

1. **Detect** the package manager — `packageManager` in `package.json`, then the
   lockfile, then default to npm. Override with `--package-manager`.
2. **Run the audit** — `npm audit --json`, `yarn npm audit --json --recursive`,
   `pnpm audit --json`, or `bun audit --json`, in your project directory.
3. **Parse** — these tools emit five different JSON shapes for the same data and
   change them between major versions. bartizan detects the shape and normalises
   everything to one record per advisory, keyed on the GHSA id (the only
   identifier stable across ecosystems). If the output matches no known shape,
   bartizan **exits 2** rather than guessing "clean."
4. **Filter** by the severity threshold.
5. **Apply the allowlist** — advisory-wide, per-package, or
   per-installed-version, with `expires` dates.
6. **Report** — human-readable text, or `--output json` for machines. Notices go
   to stderr so the JSON on stdout stays valid.

The audit call needs network — it queries your registry's advisory endpoint. If
that's slow, raise the limit: `--timeout 600`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `command not found: bartizan` | Local install — use `npx bartizan`, `./node_modules/.bin/bartizan`, or an npm script. |
| `exit 2`, "could not recognise the audit output" | Your package manager emitted a format bartizan doesn't know yet. This is the single most useful bug report the project can get — run `BARTIZAN_DUMP_RAW=/tmp/raw.txt npx bartizan` and [open an issue](https://github.com/ThushanMadu/bartizan/issues/new?template=unparsed-output.md) with `/tmp/raw.txt`. |
| `exit 2`, timeout | Registry is slow or throttling. Retry, or raise `--timeout`. |
| Finds different vulnerabilities than `npm audit` | bartizan audits everything, including devDependencies, by default; `npm install`'s summary line sometimes filters. Compare against `npm audit --json`. |
| `--skip-dev` looks ignored under Bun | `bun audit` has no production-only mode. bartizan prints a notice; the flag genuinely cannot be honoured there. |

## Coming from audit-ci?

bartizan reads an existing `audit-ci.json` / `.jsonc` as-is, so switching is a
one-line change in your CI script:

```diff
- npx audit-ci --config ./audit-ci.jsonc
+ npx bartizan
```

It announces compatibility mode and flags anything that doesn't translate
cleanly (audit-ci's dependency-path and wildcard allowlist entries have no
equivalent). The [Replacing `audit-ci`](../README.md#replacing-audit-ci) section
of the README has the full comparison and migration detail.

## Reference

Full option list, every config-file key, and the programmatic API are in the
[README](../README.md).
