# Contributing to lamassu

Thanks for looking at this. lamassu is small on purpose — the guide below is too.

## Ground rules

- **No runtime dependencies.** This is a security tool; every dependency is something a user has to trust. If a change seems to need one, that's a sign to reconsider the approach, not to add it.
- **Never report a clean audit when the input is unrecognised.** This is the one rule the whole project exists to enforce. See [Core invariant](#core-invariant) before touching `src/core/parse.ts`.
- **Every fix earns a regression test.** Ideally a test that reproduces the real failure, not a synthetic shape of it — see [Adding support for a new audit format](#adding-support-for-a-new-audit-format).

## Dev setup

```bash
git clone https://github.com/ThushanMadu/lamassu.git
cd lamassu
npm install
npm run typecheck
npm test
npm run build
```

That's the whole loop. No build step is required to run the tests (`vitest` runs against `src/` directly via `ts-node`-free type stripping), but `npm run build` is what produces the `dist/cli.js` the verification scripts actually execute.

## Project layout

```
src/
  cli.ts              argument parsing, exit codes, --help
  index.ts            public API: audit(), parseAuditOutput(), types
  config.ts           lamassu.json / audit-ci.jsonc loading and validation
  compat/audit-ci.ts  translates an existing audit-ci config
  core/
    parse.ts          the audit-format detectors — see below
    threshold.ts       severity filtering
    allowlist.ts        scoping, expiry, unused-entry detection
  managers/
    detect.ts          which package manager is this project using
    run.ts              spawns npm/yarn/pnpm/bun and captures stdout
  report/
    text.ts / json.ts  the two output renderers

test/
  fixtures/            recorded and real audit output, one file per shape
  *.test.ts            one suite per src/ module, named the same

scripts/
  verify-package-manager.mjs   runs one package manager's audit for real
  verify-all.mjs                runs all of them, with a pause for slow registries
  cross-check.mjs               asserts every package manager reaches the same verdict
```

## Core invariant

`parseAuditOutput()` in `src/core/parse.ts` must **throw** on anything it does not recognise. It must never fall through to returning `[]` (no vulnerabilities) for input it couldn't actually parse.

This is not a style preference — it is the property that makes lamassu trustworthy as a gate. A parser that silently returns "clean" on unrecognised input is worse than no gate at all, because it looks like a pass. If you're adding a new shape, the last thing you add is the specific, narrow condition that says "this is a genuinely empty, well-formed report" — everything else falls through to the "I don't understand this" error.

## Adding support for a new audit format

Package managers change their audit output between major versions without much warning — that's the whole reason `audit-ci` (lamassu's predecessor) stopped working for Yarn 4 users. When you hit a format lamassu doesn't parse:

1. **Capture the raw bytes.** Either from an issue someone filed (see [Reporting an unparsed audit format](#reporting-an-unparsed-audit-format)), or your own machine:
   ```bash
   LAMASSU_DUMP_RAW=/tmp/raw.txt lamassu
   ```
2. **Save it as a fixture.** Real captured output beats a hand-written approximation — put it in `test/fixtures/` with a name that says what produced it, e.g. `yarn4-real-4.9.1.ndjson`.
3. **Write the failing test first**, in `test/parse.test.ts`, asserting the fixture parses to the advisories you know it should contain.
4. **Add the detector** in `src/core/parse.ts`. Look at the existing detectors for the shape of the pattern — each one checks a small number of structural markers (a top-level key, a field only that format has) before committing to parsing the rest.
5. **Confirm it against the real tool**, not just the fixture:
   ```bash
   npm run build
   node scripts/verify-package-manager.mjs <npm|pnpm|yarn1|yarn4|bun>
   ```
   This installs a deliberately vulnerable fixture project and runs a real audit — the same thing CI does — so you're checking against what the tool emits today, not just what you captured once.
6. Run the full suite before opening a PR:
   ```bash
   npm run typecheck && npm test && npm run build
   ```

## Verifying against real package managers

Unit tests check that lamassu still parses *recorded* output correctly. They can't tell you whether a package manager changed its output *today*. `scripts/verify-package-manager.mjs` closes that gap — it builds a small project with known-vulnerable pinned dependencies, runs a real audit through the actual package manager, and checks the result against what's expected.

```bash
node scripts/verify-package-manager.mjs npm     # one package manager
npm run verify                                   # all of them, sequentially
```

Registry audit endpoints throttle repeated requests — expect the full run to take a few minutes, more on a slow connection. If a run times out rather than fails, that's very likely the registry, not a bug; retry after a pause, or replay a previously captured run offline:

```bash
LAMASSU_VERIFY_RAW=test/fixtures/yarn4-real-4.9.1.ndjson \
  node scripts/verify-package-manager.mjs yarn4
```

CI runs the same script across npm, Yarn 1, Yarn 4, pnpm and Bun on Linux, plus npm on Windows (see [Limitations](./README.md#limitations) for why Windows coverage is npm-only today), then asserts every package manager reached the identical set of advisories for the same project (`scripts/cross-check.mjs`). That's what backs the "works with npm, Yarn 1–4, pnpm and Bun" claim — it's re-earned on every push, not assumed.

## Reporting an unparsed audit format

If `lamassu` exits `2` saying it could not recognise the output, that's the single most useful bug report this project can receive — please [open an issue with the template for it](https://github.com/ThushanMadu/lamassu/issues/new?template=unparsed-output.md). Include:

- The package manager and exact version (`yarn --version`, etc.)
- The raw output, ideally captured with `LAMASSU_DUMP_RAW=/tmp/raw.txt lamassu`

Raw output is what turns into a fixture and a fix — a description of the problem alone usually isn't enough to reproduce it.

## Style notes

- TypeScript, strict mode, no `any` beyond the narrow cases already in `core/parse.ts` where the input is genuinely untyped JSON from an external tool.
- Comments explain **why**, not what the code already says. If you're explaining what a line does, the code should probably say that more clearly instead.
- Keep the zero-dependency policy in mind for `package.json` — devDependencies are fine, `dependencies` should stay empty.

## Before opening a PR

- [ ] `npm run typecheck` passes
- [ ] `npm test` passes
- [ ] `npm run build` succeeds
- [ ] New behaviour has a test; a bug fix has a regression test
- [ ] If you touched `src/core/parse.ts`, you ran `scripts/verify-package-manager.mjs` for the relevant package manager against a real audit, not just the fixture

That's it. Small, focused PRs are easiest to review and merge quickly.
