# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial implementation.
- Audit gate for **npm, Yarn 1–4, pnpm and Bun**, with shape detection across
  the five JSON formats these tools emit, so a format change upstream is one
  more parser rather than a rewrite.
- **Yarn 4 support**, including its NDJSON tree report and the alternative
  shape emitted under `--recursive`. This is the gap that leaves `audit-ci`
  users running an eight-year-old Yarn.
- Severity threshold (`info` … `critical`), defaulting to `high`.
- Allowlist with three levels of scoping — advisory, package, exact version —
  so an exception cannot silently absorb the same advisory elsewhere.
- Allowlist entry `expires` dates and `reason` notes.
- Reporting of unused and expired allowlist entries, with `--fail-unused`.
- **audit-ci compatibility mode**: an existing `audit-ci.json` / `.jsonc` is
  read and translated, so migrating is a one-line change.
- Text and JSON reporters. Notices go to stderr so JSON on stdout stays valid.
- `--timeout` / `timeoutSeconds` for slow registries. Also raises Yarn's own
  60s network timeout to match, so one setting governs instead of two
  disagreeing ones.
- `LAMASSU_DUMP_RAW=<file>` writes the package manager's raw audit output, so a
  new format can be reported without reconstructing the command by hand.
- `LAMASSU_VERIFY_RAW=<file>` replays a captured run offline, for iterating on
  the parser without hitting a throttling registry.
- Parse failures now show what actually arrived, and distinguish "the package
  manager errored" from "we do not know this format". A network timeout used to
  be reported as an unrecognised format, sending people after a parser bug that
  did not exist.
- Findings are ordered most severe first. They were sorted by comparing severity
  *strings*, which is alphabetical - moderate, low, high, critical - burying the
  most dangerous finding at the bottom of the report.
- A clean report now requires positive evidence of zero findings. Unrecognised
  NDJSON was previously reported as a clean audit, which could hide every
  vulnerability in a project while exiting 0.
- Real Yarn 4.9.1 audit output committed as a test fixture (33 advisories).
- Zero runtime dependencies.
- CI matrix that audits a deliberately vulnerable project with every supported
  package manager, and cross-checks that they all reach the same verdict.
- Fixed: on Windows, auditing an npm, Yarn, or pnpm project failed every time.
  Those tools resolve to `.cmd` shims there, and Node's fix for CVE-2024-27980
  refuses to spawn a `.cmd`/`.bat` file without a shell. No CI job had ever
  exercised the real code path on Windows to catch it — the Windows unit-test
  job mocked the audit call entirely, and the job that runs real audits was
  Ubuntu-only. Fixed by using a shell only on `win32`, which is safe here since
  every spawned argument is a fixed string literal, never user- or
  file-controlled — no new dependency, no injection surface. CI now also runs
  a real npm audit on `windows-latest` on every push and every release, so
  this class of bug cannot hide again.
- Fixed (Windows, CWE-426): the shell spawn above runs through `cmd.exe`, which
  searches the current directory before `PATH`. Audits run with the working
  directory set to a project lamassu does not control, so a repository shipping
  its own `npm.cmd` / `yarn.cmd` / `pnpm.cmd` / `bun.cmd` in its root could run
  in place of the real tool. The package manager is now resolved to an absolute
  path against `PATH` only — never the working directory — before the spawn.

### Notes

- Exit codes: `0` passed, `1` vulnerabilities found, `2` the audit could not
  run. `2` is never `0` — a gate that cannot run must not look like a pass.
