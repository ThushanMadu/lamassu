---
name: Audit output was not recognised
about: bartizan exited 2 saying it could not recognise the audit output
title: "Unrecognised audit output: <package manager> <version>"
labels: parser
---

**This is the most useful bug report you can file.** Package managers change
their audit formats between versions, and raw output is what lets us add a
parser for it.

### Environment

- Package manager and version: <!-- e.g. yarn 4.9.1 -->
- bartizan version:
- Node version:
- OS:

### Raw audit output

Easiest way to capture exactly what bartizan received:

```bash
# bash / zsh
BARTIZAN_DUMP_RAW=/tmp/raw.txt bartizan

# PowerShell
$env:BARTIZAN_DUMP_RAW = "$env:TEMP\raw.txt"; bartizan
```

Or run the audit command directly and paste the result. Redact private package
names if you need to, but please keep the structure intact.

```bash
npm audit --json
# or: yarn npm audit --json --recursive
# or: pnpm audit --json
# or: bun audit --json
```

<details>
<summary>Raw output</summary>

```json

```

</details>
