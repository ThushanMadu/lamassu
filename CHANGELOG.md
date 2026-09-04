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
- Zero runtime dependencies.
- CI matrix that audits a deliberately vulnerable project with every supported
  package manager, and cross-checks that they all reach the same verdict.

### Notes

- Exit codes: `0` passed, `1` vulnerabilities found, `2` the audit could not
  run. `2` is never `0` — a gate that cannot run must not look like a pass.
