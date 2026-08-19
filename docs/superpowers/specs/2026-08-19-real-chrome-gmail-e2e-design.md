# Real Chrome Gmail End-to-End Test Design

## Goal

Add an opt-in, local end-to-end test to the `email-verification` package that
exercises the built library against the current desktop Chrome Email
Verification Protocol implementation and a real Gmail account.

The test is a debugging tool for protocol interoperability. It must make the
library's complete verification result easy to inspect when Chrome or Gmail
produces a presentation that the library does not accept.

## Scope

The end-to-end test will live entirely in this repository. The sibling
`email-verification-impl` application may inform the fixture's form and route
shape, but the test will not import, run, or modify that project.

The first version will cover the successful real-account flow. It will not:

- run as part of `npm test`, `npm run check`, or CI;
- automate Google authentication or Chrome-owned permission UI;
- use an origin-trial token or a public tunnel;
- store the raw presentation token by default;
- replace the existing deterministic unit coverage; or
- add negative tampering scenarios that need freshly signed browser tokens.

## Test Shape

The test will use Playwright Test as a guided local runner. Playwright will
automate setup and assertions while leaving browser-owned and privacy-sensitive
steps under human control.

A dedicated command, `npm run test:e2e:gmail`, will:

1. build the package so the fixture consumes the same `dist/` entry point as a
   package user;
2. start a minimal verifier server on a fixed loopback origin;
3. launch the installed desktop Google Chrome channel in headed mode with
   `--enable-features=EmailVerificationProtocol`;
4. reuse an ignored persistent profile at `.e2e/chrome-profile`;
5. open the verifier form and wait for the guided user interaction;
6. capture the structured verification result and browser diagnostics;
7. assert that `verifyEmailToken()` returned success; and
8. close the server and browser context cleanly.

The Playwright project will run one test with one worker. Its timeout will be
long enough for a first-run Google sign-in and Chrome permission prompt.

## Verifier Fixture

The fixture will use Node's HTTP APIs rather than a web framework. Keeping the
server small avoids adding application dependencies to a verification library.

On `GET /`, the server will:

- create a random session identifier and nonce;
- bind the nonce to the session in memory;
- set an HTTP-only, same-site session cookie; and
- render a form containing an email input with `autocomplete="email"` and a
  hidden input with the nonce and
  `autocomplete="email-verification-token"`.

The page will include brief instructions for opening Gmail in another tab when
the dedicated profile is not signed in, returning to the form, entering the
address, waiting for Chrome's completion indicator, and submitting.

On `POST /verify`, the server will:

- parse the form submission;
- recover the session-bound nonce;
- derive the exact loopback audience from the configured fixture origin;
- call `verifyEmailToken()` from `dist/index.js`; and
- render the complete structured result in a machine-readable element and a
  readable diagnostic view.

The fixture will not log or render the submitted presentation token.

## Human Interaction

Chrome will use the dedicated persistent profile rather than the user's normal
browser profile. On the first run, the user can open Gmail in another tab and
sign in to the account manually. That authentication state remains only in the
ignored test profile and is available to later runs.

The user will enter the Gmail address, handle any Chrome permission prompt,
wait for the browser's verification indicator, and submit the form. Playwright
will not attempt to inspect or control Chrome's browser chrome. This boundary
keeps the flow faithful to current user-facing behavior and avoids brittle
automation of UI that is outside the web page.

## Result Capture and Diagnostics

Every run will write `.e2e/results/latest.json`, which is ignored by Git. The
record will include:

- start and completion timestamps;
- the fixture origin;
- the detected Chrome version or user agent;
- the complete `verifyEmailToken()` result;
- on success, the verified email, issuer, audience, issue times, and
  authenticated claims;
- on failure, the verification stage, stable code, message, and normalized
  cause;
- browser console errors;
- uncaught page errors; and
- failed browser requests observed during the run.

On failure, Playwright will also save a screenshot of the diagnostic result
page beneath `.e2e/results/`. The JSON artifact will be written before the test
assertion so a failed assertion cannot discard the useful evidence.

The raw presentation token will not be included in output, logs, screenshots,
or JSON artifacts by default. If structured diagnostics prove insufficient,
raw-token capture can be added later behind a separate explicit opt-in.

## Success Criteria

The guided test passes only when the real browser submission causes the built
library to return `{ ok: true }`. The assertion will also confirm that the
verified email matches the submitted email case-insensitively, the issuer is
Google's delegated Gmail issuer, and the verified audience matches the local
fixture origin.

Missing tokens, lost session state, server exceptions, browser closure, and all
library verification failures will fail the test after recording diagnostics.
The result page and artifact must distinguish harness failures from structured
library failures.

## Repository Changes

The implementation is expected to add:

- a Playwright development dependency and lockfile update;
- an explicit `test:e2e:gmail` package script;
- a Playwright configuration scoped to the Gmail E2E;
- the guided test and minimal verifier fixture under `e2e/`; and
- ignore rules for `.e2e/` profile, result, and browser data.

Existing unit-test configuration and commands will remain unchanged.

## Verification

Implementation verification will include:

1. a failing first run before the fixture/test support is complete;
2. formatting, type checking, linting, unit tests, and package build;
3. confirmation that ordinary test and check commands do not invoke the Gmail
   E2E; and
4. one guided run using installed desktop Chrome and a real Gmail session.

The work will not be described as end-to-end verified until the guided run has
returned a successful structured library result.
