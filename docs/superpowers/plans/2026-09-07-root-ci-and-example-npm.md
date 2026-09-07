# Root CI and Example npm Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the independent example app from pnpm to npm and add GitHub Actions jobs for the library checks and example lint.

**Architecture:** Keep the root library and `example/` as separate npm projects with separate lockfiles and installs. A single GitHub Actions workflow runs the root library checker and example ESLint in isolated jobs so their ESLint configurations and dependencies do not mix.

**Tech Stack:** npm, Node.js 20, GitHub Actions, ESLint, Prettier

## Global Constraints

- Do not convert the repository to an npm workspace.
- Preserve existing staged changes in example source and documentation files.
- Root Prettier and ESLint continue to ignore `example/`.
- The example uses `example/package-lock.json` and contains no pnpm metadata.
- The workflow runs on pull requests and pushes to `main` with `contents: read` only.
- Pin actions to the verified full SHAs `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2` and `actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0`.
- Do not build, test, or deploy the example app; run only its linter.

---

### Task 1: Convert the example to independent npm

**Files:**
- Modify: `example/package.json`
- Create: `example/package-lock.json`
- Delete: `example/pnpm-lock.yaml`
- Delete: `example/pnpm-workspace.yaml`

**Interfaces:**
- Consumes: The dependencies and scripts already declared in `example/package.json`.
- Produces: An independently installable npm project whose `npm run lint` uses the example's ESLint 9 and Next.js configuration.

- [x] **Step 1: Record the pnpm-based failure mode**

Run from the repository root:

```sh
test -f example/pnpm-lock.yaml
test -f example/pnpm-workspace.yaml
node -e 'const p=require("./example/package.json"); if (!p.packageManager?.startsWith("pnpm@")) process.exit(1)'
```

Expected: all commands exit successfully, proving pnpm metadata is currently present.

- [x] **Step 2: Remove pnpm metadata from the manifest and filesystem**

Remove this property from `example/package.json`:

```json
"packageManager": "pnpm@11.20.0"
```

Delete `example/pnpm-lock.yaml` and `example/pnpm-workspace.yaml`. Remove the generated root `.pnpm-store/` directory created during local pnpm verification; it is not project source.

- [x] **Step 3: Generate and validate the npm lockfile**

Run:

```sh
cd example
npm install --package-lock-only --ignore-scripts
npm ci
npm run lint
```

Expected: npm produces `example/package-lock.json`, a clean npm install succeeds, and ESLint exits successfully.

- [x] **Step 4: Verify pnpm metadata is gone**

Run from the repository root:

```sh
test ! -e example/pnpm-lock.yaml
test ! -e example/pnpm-workspace.yaml
node -e 'const p=require("./example/package.json"); if ("packageManager" in p) process.exit(1)'
```

Expected: all commands exit successfully.

- [x] **Step 5: Commit only package-manager migration files**

```sh
git add example/package.json example/package-lock.json example/pnpm-lock.yaml example/pnpm-workspace.yaml
git commit --only example/package.json example/package-lock.json example/pnpm-lock.yaml example/pnpm-workspace.yaml -m "chore(example): migrate from pnpm to npm"
```

Do not include the separately staged example source or documentation changes.

### Task 2: Add isolated GitHub Actions checks

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Root `package-lock.json` and `npm run check`; `example/package-lock.json` and `npm run lint`.
- Produces: Required CI signals named `Library checks` and `Example lint`.

- [x] **Step 1: Add the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches:
      - main
  pull_request:

permissions:
  contents: read

jobs:
  library:
    name: Library checks
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - name: Set up Node.js
        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: package-lock.json
      - name: Install dependencies
        run: npm ci
      - name: Run checks
        run: npm run check

  example-lint:
    name: Example lint
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: example
    steps:
      - name: Check out repository
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - name: Set up Node.js
        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: example/package-lock.json
      - name: Install dependencies
        run: npm ci
      - name: Run lint
        run: npm run lint
```

- [x] **Step 2: Verify workflow formatting and contents**

Run:

```sh
npx prettier --check .github/workflows/ci.yml
git diff --check
rg -n "actions/(checkout|setup-node)@[0-9a-f]{40}" .github/workflows/ci.yml
```

Expected: formatting and whitespace checks pass, and four SHA-pinned action references are found.

- [x] **Step 3: Re-run both CI command paths locally**

Run:

```sh
npm ci
npm run check
npm ci --prefix example
npm run lint --prefix example
```

Expected: the root checker passes all formatting, type, lint, build, and library tests; the example linter exits successfully.

- [x] **Step 4: Commit the workflow and plan**

```sh
git add .github/workflows/ci.yml docs/superpowers/plans/2026-09-07-root-ci-and-example-npm.md
git commit --only .github/workflows/ci.yml docs/superpowers/plans/2026-09-07-root-ci-and-example-npm.md -m "ci: check library and example"
```

Do not include the separately staged example source or documentation changes.
