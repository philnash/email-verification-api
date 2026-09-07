# Root CI and Example npm Migration Design

## Goal

Add GitHub Actions checks for the library and example app while converting the example from pnpm to an independent npm project.

## Package-manager boundary

The root library and `example/` remain separate npm projects rather than becoming an npm workspace. The example keeps its own `package.json`, `package-lock.json`, installation directory, and scripts.

The migration removes `example/pnpm-lock.yaml`, `example/pnpm-workspace.yaml`, and the pnpm `packageManager` declaration from `example/package.json`. The example README continues to document `npm install` and `npm run dev`. Existing staged example formatting changes are preserved.

The root Prettier and ESLint configurations continue to ignore `example/`, because the example is checked with its own dependencies and ESLint configuration.

## GitHub Actions workflow

Create `.github/workflows/ci.yml`, triggered by pull requests and pushes to `main`. The workflow has read-only `contents` permission and two independent jobs on `ubuntu-latest`, both using Node.js 20:

1. **Library checks** checks out the repository, configures Node with npm caching based on the root `package-lock.json`, runs root `npm ci`, and runs `npm run check`. The existing `check` script covers formatting, type-checking, lint, build, and all library tests.
2. **Example lint** checks out the repository, configures Node with npm caching based on `example/package-lock.json`, runs `npm ci` from `example/`, and runs `npm run lint` from `example/`.

Use the current official action majors verified during implementation: `actions/checkout@v6` and `actions/setup-node@v7`.

The workflow does not build, test, or deploy the example app.

## Verification

- Run root `npm ci` and `npm run check`.
- Run `npm ci` and `npm run lint` from `example/`.
- Inspect the workflow YAML and run whitespace/format checks.
- Confirm no pnpm metadata remains under `example/`.
- Confirm existing staged example source and formatting changes remain intact.
