# Use Lock Server

An OpenID Connect provider and Lattice authentication UI for Laravel, shipped as one Composer package.

## What you get

**OIDC provider**

- Signed RS256 `id_token`s, a `/.well-known/openid-configuration` discovery document, and a
  JWKS endpoint (RFC 7638 `kid`s).
- `userinfo`, RP-initiated logout, OIDC **back-channel logout**, RFC 7662 introspection, and
  RFC 7009 revocation.
- **RFC 9068** structured `at+jwt` access tokens.
- **RFC 8693** token exchange, with a self-contained `CheckAudience` resource-server middleware.
- Capability-scoped token triggers and a swappable `ClaimsResolver` / `ScopeRepository` / `ExchangePolicy`.
- Database-backed RS256 signing keys with a built-in rotation command and JWKS overlap.

**Auth engine** (optional)

- Package-owned login, registration, password reset, email verification, and password
  confirmation, driven by view and action *seams* your app fills.
- Multi-factor authentication: TOTP, recovery codes, and passkeys (WebAuthn).
- A post-login pipeline with a single decision hook (`requireMfa` / `deny` / add claims) and
  `acr` / `amr` emission.

## Requirements

- PHP `^8.5`
- Laravel 13
- PostgreSQL 16 with the PHP `pdo_pgsql` extension
- A UUID primary key on the application’s users table
- PHP `curl` extension for back-channel logout delivery

Back-channel logout destinations must use HTTPS and resolve to public IP addresses.
Private and internal destinations are rejected, and delivery requires cURL to pin the
validated address for the request.

## Installation

Before publishing or running migrations, the configured user model must use UUID identifiers.
The package’s `user_id` foreign keys are UUID columns and reference the users table configured
in `oidc.migrations.users.table`. In a new application, declare the user primary key with
`$table->uuid('id')->primary()` and add Laravel’s `HasUuids` trait to the user model.
For an existing application with integer user IDs, migrate its users and referencing columns
to UUIDs before installing this package; integer IDs are not supported.

```bash
composer require use-lock/server

# Publish and run the migrations
php artisan vendor:publish --tag=oidc-migrations
php artisan vendor:publish --tag=passkeys-migrations
php artisan migrate

# Generate the first RSA signing key (stored in oidc_signing_keys)
php artisan oidc:rotate-keys --if-missing

# Optional: publish the config
php artisan vendor:publish --tag=oidc-config
```

The service provider is auto-discovered. Set `OIDC_ISSUER` to your provider's public origin —
every URL advertised in discovery is derived from it.

The package includes login, registration, password reset, verification, consent, and MFA screens.
Configure authentication in `config/oidc.php` and UI options in `config/oidc-ui.php`.
PHP classes use the `Lock\Server` namespace;
UI classes live under each domain, such as `Lock\Server\Authentication\Ui`.

The consuming application's Lattice Vite plugin discovers the bundled frontend components.
Publish UI customization files with:

```bash
php artisan vendor:publish --tag=oidc-ui-config
php artisan vendor:publish --tag=oidc-ui-lang
```

Bind the authentication action contracts in your application and override view contracts
in your service provider when you need custom screens.

## A package-owned OAuth2 core

The package implements the OAuth 2.1 / OpenID Connect core itself: client authentication, the
authorization request, authorization codes with PKCE, refresh-token rotation, and the token
endpoint's grants live in the `Protocol` domain on top of the package's own tables and models.
This means:

- The authorization, token and approve/deny routes are registered by this package using its own
  controllers, so `max_age`, `prompt`, OIDC scopes and the `id_token` are wired in.
- **PKCE with `S256` is required on every authorization request**, per OAuth 2.1 §4.1.1/§7.6 —
  for confidential clients as well as public ones. A request missing it is answered with an
  `invalid_request` error on the client's redirect URI.
- Authorization codes and refresh tokens are opaque, single-use database records. A replayed code
  or a reused refresh token revokes every token that descends from it.
- The signing key is read on every request, so a key rotation takes effect without restarting
  the workers.
- No client-management JSON API ships with the package. Provision clients with
  `oidc:client`, or through dynamic client registration.

## Development

Run all commands from this repository's root:

```bash
composer install

# Start an isolated test database (Docker required)
docker run --detach --rm --name use-lock-server-tests \
  -e POSTGRES_DB=use_lock_test -e POSTGRES_USER=use_lock -e POSTGRES_PASSWORD=use_lock \
  -p 127.0.0.1:55432:5432 postgres:16

composer check
```

The defaults in `phpunit.xml.dist` connect to this PostgreSQL instance. Wait for
`docker exec use-lock-server-tests pg_isready -U use_lock -d use_lock_test` to succeed
before testing. Override `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USERNAME`, and
`DB_PASSWORD` to use another dedicated test database. The database user needs `CREATEDB`
for parallel tests, which create databases suffixed with `_test_N`. Test runs rebuild
the database schema; always use a dedicated test database. Stop the container with
`docker stop use-lock-server-tests` when finished.

Tests are split into two suites, with domain directories inside each suite:

- `tests/Unit`: isolated component and architecture tests without a Laravel application or database.
  These cover JWK conversion and the exchange allowlist.
- `tests/Feature`: HTTP endpoints, authentication flows, UI responses, persistence, filesystem operations, and framework integration.

Pest assigns `tests/FeatureTestCase.php` to Feature. It boots Testbench,
refreshes the database, installs fixture signing keys, and prevents stray HTTP requests.
Unit tests use Pest's default PHPUnit test case. Shared test support lives in `tests/Support`; Pest automatically loads shared helpers from `tests/Helpers.php`.
UI response and component assertions belong in Feature.

Run a suite with `composer test:unit` or `composer test:feature`.
`composer test` runs all suites.
`composer check` runs Pint, PHPStan, Rector, and the full Pest suite with immutable
dates (`CarbonImmutable`). `php artisan` boots the local Testbench workbench.

Runtime code lives in `src/`, UI definitions in each domain's `Ui/` directory, and package assets
in `config/`, `database/`, `resources/`, and `routes/`. Setup and consumer testing helpers
live under `src/Support/`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and verification requirements,
and [SECURITY.md](SECURITY.md) for private vulnerability reporting and supported versions.

## License

MIT. See [LICENSE](LICENSE).
