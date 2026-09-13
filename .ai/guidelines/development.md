# Local Development

- This repository is the standalone `use-lock/server` Composer package. Runtime code lives in `src/`,
  with configuration, migrations, routes, and assets in `config/`, `database/`, `routes/`, and `resources/`.
  Setup and consumer testing helpers live under `src/Support/`.
- The root `composer.json` contains the package dependencies, PSR-4 autoloading, and development tooling.
- The package is developed with Orchestra Testbench, not a full Laravel app. `artisan` at the repo root is a thin
  shim requiring `vendor/bin/testbench`, so `php artisan <command>` boots the Testbench skeleton with the providers from
  `testbench.yaml` and the `workbench/` app.
- `bambamboole/extended-testbench` rebases `base_path()` (and storage/config/database/bootstrap/lang/public paths) to
  the repo root for `boost:*`/`mcp:*` commands specifically, so Laravel Boost's package-guideline and skill discovery —
  which reads `base_path('composer.json')` — sees this package instead of the Testbench skeleton.
- The Boost overrides live in `workbench/app/Support/` and are wired in
  `Workbench\App\Providers\WorkbenchServiceProvider`. They point `boost.json`, `.ai/guidelines/` and `.ai/skills/` at
  the repo root instead of the Testbench skeleton.
- Regenerate `CLAUDE.md` and `AGENTS.md` after editing files in `.ai/guidelines/` or `.ai/skills/` with
  `composer boost:refresh`.
- Tests live in `tests/Feature` and `tests/Unit`. Prefer Feature for package behavior. `tests/Pest.php` assigns
  `FeatureTestCase` only to Feature; Unit uses Pest's default PHPUnit test case without Laravel or a database.
- `tests/FeatureTestCase.php` disables package discovery, registers the required providers, refreshes the database,
  installs fixture signing keys, and prevents stray HTTP requests. Shared support lives in `tests/Support`.
- Pest automatically loads `tests/Helpers.php` before `tests/Pest.php`; keep shared helpers there and test configuration
  in `Pest.php`. There is no Browser suite until real browser tests exist.
- Implement and verify package behavior in this repository's Testbench harness before checking consuming apps.

## Verification

- Git hooks enforce the gate automatically. `composer install` points `core.hooksPath` at `.githooks/`; if the hooks are
  not active, run `composer install` (or `git config core.hooksPath .githooks`) once.
  - **pre-commit** auto-fixes staged PHP with Pint and Rector, re-stages the fixes, then runs PHPStan (both configs)
    over the whole project and blocks on any error. PHPStan's result cache is pinned to `.phpstan-cache/` (gitignored,
    `parameters.tmpDir` in `phpstan.neon.dist`/`phpstan-tests.neon.dist`) so it persists across commits — after the
    first run, only files that actually changed get re-analysed.
  - **pre-push** runs Pint and PHPStan when the push touches PHP files. The full Pest suite and Rector are too slow
    for every push, so they run in CI and via explicit local runs (`composer check`).
- Before opening a PR, run the full local gate:
  ```bash
  composer check
  ```
- The test suite always uses `Date::use(CarbonImmutable::class)` in `tests/FeatureTestCase.php`.
  All local and CI test runs use this setup; there is no separate date-mode matrix.
  Type Carbon values as `Carbon\CarbonInterface` and create them through Laravel's `Date` facade or `now()`.
  Native `DateTimeInterface` / `DateTimeImmutable` types remain appropriate at library boundaries such as JWT APIs.
- For narrower loops while developing:
  ```bash
  composer test:feature    # package behavior
  composer test:unit       # isolated units
  composer test            # or composer test:parallel
  composer test:lint
  composer analyse
  composer rector:test
  ```
- Never push on red. Use `git commit`/`git push --no-verify` only in emergencies.
- Do not add PHPStan suppressions or baselines unless the user explicitly approves them.
- Worktrees live as siblings of the checkout. Nested worktrees inside the repo make the
  Pest PHPStan plugin pick up their `Pest.php` files and misresolve `$this` in the test suites.

## Comments

- Code must be self-explanatory: reach for clear names, small functions, and types before a comment.
- Do not add comments. A comment is a last resort and explains only *why* something is done, never *what* the code does.
- When you encounter an obsolete, redundant, or "what" comment, delete it.
- Delete section banners and navigation comments unless they explain a non-obvious boundary.
- Delete comments that narrate the next line, assertion, or obvious test setup; prefer clearer test names and variable
  names.
- Keep PHPDoc/JSDoc only when it carries type information, public API intent, static-analysis value, generated-file
  context, a Spec reference or a non-obvious constraint.
- Keep comments that explain framework quirks, ordering requirements, browser/test timing, cache/build behavior,
  performance traps, or other constraints that are hard to infer from the code alone.

## Testing

- Prefer feature tests for package behavior. Test through HTTP routes, controllers, events, commands, token flows, and
  database effects rather than isolating internals by default.
- Use unit tests only for deterministic value objects, claim bags, policies, or similarly small pure units that do not
  need Laravel or a database. Repositories and token builders that exercise persistence or framework integration stay
  in Feature.
- For auth-engine work, bind package seams inside Testbench tests; do not depend on a consuming app to prove
  package behavior.
- Use the workbench app only as a Testbench consumer. Do not move reusable auth logic into `workbench/`.

## Package Architecture

- The package namespace is `Lock\Server`; factories use `Lock\Server\Database\Factories` and test code uses
  `Lock\Server\Tests`. Runtime code is grouped by domain under `src/`.
- Follow the allowed domain dependencies in `tests/Unit/ArchitectureTest.php`. Domains may depend on Shared;
  Shared must not depend on domains. Keep cross-domain dependencies explicit and acyclic.
- OIDC and authentication behavior stays package-owned, exposed through configuration plus view/action seams
  that a consuming app binds. UI definitions live in each domain's `Ui/` directory.
- Keep route names and response shapes compatible with Laravel/Fortify conventions when replacing Fortify-equivalent
  behavior.
- Keep dependencies explicit and package-owned. Do not add dependencies without approval.
- Prefer Laravel primitives and existing local abstractions over new framework layers.
