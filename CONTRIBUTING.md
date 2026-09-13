# Contributing

Open an issue to discuss a substantial feature or public API change before implementing it.
For vulnerabilities, use the private reporting process in [SECURITY.md](SECURITY.md).

## Local Setup

Use PHP 8.5, Composer, and PostgreSQL 16 with the PHP `pdo_pgsql` extension.
Follow the [README development setup](README.md#development) to install dependencies and
start a dedicated PostgreSQL test database. The test role needs `CREATEDB` for parallel runs.
Tests rebuild their database schema, so never point them at an application database.

This repository is a Composer package developed with Orchestra Testbench. Runtime code
belongs in `src/`; `workbench/` is a consumer fixture. Run commands from the repository root.

## Changes and Tests

Follow the surrounding code conventions and keep each pull request focused on one change.
Add feature coverage for package behavior through HTTP, commands, events, or database effects.
Use unit tests for pure logic that does not need Laravel or a database. Tests use immutable
Carbon dates. New dependencies and public API changes should be discussed in the issue.

Run focused tests while developing, then run the full gate before opening a pull request:

```bash
composer test:feature
composer test:unit
composer check
```

`composer check` runs Pint, both PHPStan configurations, Rector, and the full parallel Pest
suite. CI runs PHP 8.5 and PostgreSQL 16 with both the lowest and highest installable dependency
versions. Keep these checks passing; do not add static-analysis suppressions to hide failures.

Use a conventional commit subject such as `fix: preserve authorization parameters`.
Describe what changed, why, and how you verified it in the pull request. Include screenshots
or concrete before-and-after examples for visual changes. Keep generated planning artifacts
and unrelated formatting changes out of the diff.

During `0.x`, minor releases may change public APIs. Document compatibility changes in the
pull request so they can be included in release notes.
