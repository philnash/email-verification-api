# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-07

### Added

- Added optional caller cancellation, an overall verification timeout, and per-operation timeouts for DNS, hostname, metadata, and JWKS requests.
- Added `REQUEST_ABORTED` and `REQUEST_TIMEOUT` verification errors, plus exported schemas and types for request timeout configuration.
- Added a complete Next.js example application and hosted demo showing the browser-to-server verification flow.

## [0.1.0] - 2026-08-20

### Added

- Initial release with end-to-end EVT and KB-JWT verification, including expected-value checks, DNS delegation, issuer signatures, and key binding.
- Added structured verification results, injectable network and clock dependencies, and safeguards for issuer requests.

[Unreleased]: https://github.com/philnash/email-verification-api/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/philnash/email-verification-api/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/philnash/email-verification-api/releases/tag/v0.1.0
