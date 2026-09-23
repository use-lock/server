<?php
declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lock\Server\Audit\Contracts\AuditSink;
use Lock\Server\Authentication\Contracts\CreateUser;
use Lock\Server\Authentication\Contracts\ResetUserPassword;
use Lock\Server\Authentication\PasswordResetTokens;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Brokering\CreateUserFromSocialAccount;
use Lock\Server\Shared\Brokering\SocialUser;
use Lock\Server\Shared\Consents\ConsentPrompt;
use Lock\Server\Shared\Consents\ConsentView;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\SigningKeys\Jwk;
use Lock\Server\SigningKeys\SigningKeyGenerator;
use Lock\Server\SigningKeys\SigningKeyStore;
use Lock\Server\Support\Testing\FakeAuditSink;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\RefreshToken;
use Symfony\Component\HttpFoundation\Response;

function createUsersUsing(Closure $action): void
{
    app()->bind(CreateUser::class, fn (): CreateUser => new readonly class($action) implements CreateUser
    {
        public function __construct(private Closure $action) {}

        public function __invoke(array $input): Authenticatable
        {
            return ($this->action)($input);
        }
    });
}

function passwordResetToken(CanResetPassword $user): string
{
    return app(PasswordResetTokens::class)->create($user);
}

function resetUserPasswordsUsing(Closure $action): void
{
    app()->bind(ResetUserPassword::class, fn (): ResetUserPassword => new readonly class($action) implements ResetUserPassword
    {
        public function __construct(private Closure $action) {}

        public function __invoke(CanResetPassword $user, array $input): void
        {
            ($this->action)($user, $input);
        }
    });
}

function createUsersFromSocialUsing(Closure $action): void
{
    app()->bind(CreateUserFromSocialAccount::class, fn (): CreateUserFromSocialAccount => new readonly class($action) implements CreateUserFromSocialAccount
    {
        public function __construct(private Closure $action) {}

        public function __invoke(SocialUser $socialUser, string $provider): Authenticatable
        {
            return ($this->action)($socialUser, $provider);
        }
    });
}

/**
 * Re-runs the package's route file. Endpoints whose registration depends on
 * config (`oidc.clients.registration.enabled`) are bound at boot, so a test that flips the flag
 * afterwards has to rebuild the table to see the change.
 */
function reloadOidcRoutes(): void
{
    require __DIR__.'/../routes/oidc.php';

    Route::getRoutes()->refreshNameLookups();
}

/**
 * Per-run root for filesystem fixtures. Everything created through this helper
 * lands under one pid-scoped directory that the shutdown hook below removes.
 */
function temporaryTestDirectory(string $prefix): string
{
    $directory = sys_get_temp_dir().'/use-lock-server-tests-'.getmypid().'/'.$prefix.'-'.uniqid();
    mkdir($directory, 0755, true);

    return $directory;
}

// Plain PHP only: the Laravel app (and its facades) may already be torn down
// by the time the shutdown hook runs.
register_shutdown_function(function (): void {
    $delete = function (string $path) use (&$delete): void {
        if (! is_dir($path) || is_link($path)) {
            return;
        }

        foreach (array_diff(scandir($path) ?: [], ['.', '..']) as $entry) {
            $child = $path.'/'.$entry;
            is_dir($child) && ! is_link($child) ? $delete($child) : unlink($child);
        }

        rmdir($path);
    };

    $delete(sys_get_temp_dir().'/use-lock-server-tests-'.getmypid());
});

function fakeAudit(): FakeAuditSink
{
    $sink = new FakeAuditSink;
    app()->instance(AuditSink::class, $sink);

    return $sink;
}

/** Parses any JWS the package issues (access, id or logout token) without validating it. */
function parseAccessToken(string $jwt): UnencryptedToken
{
    $token = new Parser(new JoseEncoder)->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $token;
}

function parseIdToken(string $jwt): UnencryptedToken
{
    return parseAccessToken($jwt);
}

function expectExchangeDenied(Closure $callback, string $error): void
{
    $thrown = null;

    try {
        $callback();
    } catch (OAuthServerException $thrown) {
    }

    expect($thrown)->toBeInstanceOf(OAuthServerException::class)
        ->and($thrown?->error)->toBe($error);
}

/**
 * @return array{0: string, 1: RefreshToken, 2: AccessToken}
 */
function issueRefreshToken(mixed $test, ?string $clientId = null, bool $expired = false): array
{
    $accessToken = AccessToken::factory()->forUser($test->user)->create(['client_id' => $clientId ?? $test->client->id]);
    $refreshToken = RefreshToken::factory()
        ->forAccessToken($accessToken)
        ->create($expired ? ['expires_at' => now()->subDay()] : []);

    return [$refreshToken->id, $refreshToken, $accessToken];
}

/**
 * Mints an RFC 9068 access token addressed to $clientId and persists the
 * matching token row so TokenInspector::accessToken() resolves it.
 *
 * @param  string[]  $scopeIds
 */
function mintExchangeSubjectToken(
    string $clientId,
    string $userId,
    array $scopeIds,
    ?DateTimeImmutable $expiresAt = null,
    bool $revoked = false,
    bool $userless = false,
): string {
    $minted = app(AccessTokenMinter::class)->mint(
        $userless ? null : $userId,
        $clientId,
        $scopeIds,
        ttlUntil($expiresAt ?? new DateTimeImmutable('+1 hour')),
        [$clientId],
    );

    if ($revoked) {
        AccessToken::query()->whereKey($minted->jti)->update(['revoked_at' => now()]);
    }

    return $minted->jwt;
}

/**
 * Mints an RFC 9068 at+jwt access token addressed to the given resource audiences (the realm's
 * own when none are given) and persists a matching token row. The guard is a self-contained
 * resource-server validator: revocation and expiry are read from the persisted row.
 *
 * @param  string[]  $audience
 */
function resourceServerBearer(
    mixed $test,
    array $audience = [],
    bool $revoked = false,
    bool $expired = false,
    ?string $subjectId = null,
): string {
    $minted = app(AccessTokenMinter::class)->mint(
        $subjectId ?? (string) $test->user->id,
        (string) $test->client->client_id,
        ['openid'],
        ttlUntil($expired ? new DateTimeImmutable('-1 hour') : new DateTimeImmutable('+1 hour')),
        $audience,
    );

    if ($revoked) {
        AccessToken::query()->whereKey($minted->jti)->update(['revoked_at' => now()]);
    }

    return $minted->jwt;
}

/**
 * Mints the userless at+jwt the client_credentials grant issues — no subject, addressed to the
 * given resource audiences (the realm's own when none are given) — and persists a matching row.
 *
 * @param  string[]  $scopes
 * @param  string[]  $audience
 */
function clientCredentialsBearer(
    Client $client,
    array $scopes = ['orders.read'],
    array $audience = [],
    bool $revoked = false,
): string {
    $minted = app(AccessTokenMinter::class)->mint(
        null,
        $client->client_id,
        $scopes,
        ttlUntil(new DateTimeImmutable('+1 hour')),
        $audience,
    );

    if ($revoked) {
        AccessToken::query()->whereKey($minted->jti)->update(['revoked_at' => now()]);
    }

    return $minted->jwt;
}

/** A TTL that lands on the given instant; negative when it lies in the past. */
function ttlUntil(DateTimeImmutable $expiresAt): DateInterval
{
    return (new DateTimeImmutable)->diff($expiresAt);
}

function fakeConsentViewUsing(Closure $callback): void
{
    app()->instance(ConsentView::class, new readonly class($callback) implements ConsentView
    {
        public function __construct(private Closure $callback) {}

        public function respond(ConsentPrompt $prompt, Request $request): Responsable|Response
        {
            return ($this->callback)([
                'client' => $prompt->client,
                'user' => $prompt->user,
                'scopes' => $prompt->scopes,
                'authToken' => $prompt->authToken,
            ]);
        }
    });
}

function signingPublicKey(): string
{
    return app(SigningKeyStore::class)->signingKey()->publicKeyPem;
}

function signingPrivateKey(): string
{
    return app(SigningKeyStore::class)->signingKey()->privateKey();
}

/**
 * Mints a plain JWT (default header typ=JWT, as an id_token would carry) signed with the realm key
 * and persists a matching access-token row, so only the typ guard can reject it as a bearer.
 */
function persistedIdTokenAsBearer(mixed $test): string
{
    $tokenId = Str::random(80);
    $now = new DateTimeImmutable;

    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText(signingPrivateKey()),
        InMemory::plainText(signingPublicKey()),
    );

    $jwt = $config->builder()
        ->withHeader('kid', Jwk::fromPem(signingPublicKey())['kid'])
        ->issuedBy(app(IssuerResolver::class)->url())
        ->identifiedBy($tokenId)
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->relatedTo((string) $test->user->id)
        ->permittedFor((string) $test->client->id)
        ->withClaim('scopes', ['openid'])
        ->getToken($config->signer(), $config->signingKey())
        ->toString();

    AccessToken::factory()->forClient($test->client)->forUser($test->user)->create(['id' => $tokenId]);

    return $jwt;
}

/**
 * Signing keys are stored per realm; a test that enters another realm has to
 * give it a key before it can mint or verify there.
 */
function generateRealmSigningKey(): void
{
    app(SigningKeyStore::class)->rotate(app(SigningKeyGenerator::class)->generate());
}

/**
 * Works the database queue off in process, the way a worker would: the payload
 * is serialized and read back, and JobProcessing fires, which is what restores
 * the context a job was dispatched with. A job that fails rethrows here rather
 * than disappearing into `failed_jobs`.
 */
function workQueue(int $limit = 10): void
{
    $failure = null;
    Event::listen(JobFailed::class, function (JobFailed $event) use (&$failure): void {
        $failure ??= $event->exception;
    });

    $worker = app('queue.worker');

    while ($limit-- > 0 && DB::table('jobs')->count() > 0) {
        $worker->runNextJob('database', 'default', new WorkerOptions(maxTries: 1));
    }

    if ($failure instanceof Throwable) {
        throw $failure;
    }
}

/**
 * Drops the request and the per-request state a worker process would never
 * have seen, so a queued job is worked the way a real worker works it: with
 * nothing to go on but its own payload. Without this a test passes on the
 * request the harness is still holding rather than on what the job carried.
 *
 * The replacement request is the one SetRequestForConsole gives a worker.
 */
function forgetRequest(): void
{
    Context::flush();
    app()->instance('request', Request::create((string) config('app.url', 'http://localhost')));
    URL::defaults(['realm' => (string) config('oidc.realm', 'default')]);
}

/**
 * The X-Inertia header makes Inertia answer with the page payload as JSON instead
 * of rendering a host application's root Blade view, which this package does not ship.
 */
function inertiaRequest(): Request
{
    $request = Request::create('/', 'GET');
    $request->headers->set('X-Inertia', 'true');

    return $request;
}

function renderPage(object $page): string
{
    return (string) $page->toResponse(inertiaRequest())->getContent();
}
