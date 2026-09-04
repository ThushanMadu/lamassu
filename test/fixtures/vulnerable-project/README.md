# Vulnerable fixture

These dependencies are pinned to versions with known published advisories.
**Never install this outside CI, and never depend on it.**

CI installs it with each package manager in turn, runs lamassu against it, and
asserts that every package manager path reports the same advisories. That is
how the "works with npm, Yarn 1-4, pnpm and Bun" claim is verified rather than
assumed.
