### What this changes

### Why

<!-- Link the issue if there is one. If this fixes an unrecognised-format bug,
     name the package manager and version. -->

### Checklist

- [ ] `npm run typecheck` passes
- [ ] `npm test` passes
- [ ] `npm run build` succeeds
- [ ] New behaviour has a test; a bug fix has a regression test
- [ ] If `src/core/parse.ts` changed, I ran `node scripts/verify-package-manager.mjs <pm>` against a real audit, not just a fixture
- [ ] No new runtime dependency was added (`dependencies` in package.json stays empty — devDependencies are fine)
