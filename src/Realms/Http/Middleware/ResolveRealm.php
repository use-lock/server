<?php

declare(strict_types=1);

namespace Lock\Server\Realms\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\URL;
use Lock\Server\Realms\Enums\RealmRouting;
use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\RealmResolver;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Runs before StartSession. Below `/realms/{realm}` the provider gets its own
 * session cookie, so a login there cannot consume or regenerate the relying
 * party's session; at the application root (`single`) provider and application
 * deliberately share one session, the way one host would. Removing the realm
 * parameter preserves controller arguments.
 *
 * The resolved realm is also published to the context, which is what carries
 * it into jobs queued while serving the request.
 */
final readonly class ResolveRealm
{
    public function __construct(private RealmResolver $realms, private Store $session) {}

    /** Whether the route serves a realm's pages — the package's own and any an application puts behind this middleware. */
    public static function appliesTo(Route $route): bool
    {
        return in_array(self::class, $route->middleware(), true);
    }

    public function handle(Request $request, Closure $next): Response
    {
        $realm = $this->realms->current()->identifier();

        $request->attributes->set(CurrentRealm::ATTRIBUTE, $realm);
        $request->route()?->forgetParameter('realm');

        URL::defaults(['realm' => $realm]);
        OidcContext::rememberRealm($realm);

        $routing = RealmRouting::configured();

        // Only `path` shares a host between realms; `single` and `domain` each
        // own their origin, where the browser isolates cookies already.
        if ($routing !== RealmRouting::Path) {
            return $next($request);
        }

        $originalCookie = (string) config('session.cookie');
        $originalPath = config('session.path');
        $originalName = $this->session->getName();
        $path = $routing->path($realm);
        $cookie = $this->realms->current()->sessions()->cookieName ?? $originalCookie.'-oidc-'.str_replace('.', '_', $realm);

        if ($cookie === $originalCookie || preg_match('/\A[A-Za-z0-9_-]+\z/', $cookie) !== 1) {
            throw new LogicException('The realm session cookie must have a distinct name using letters, digits, underscores or hyphens.');
        }

        config(['session.cookie' => $cookie, 'session.path' => $path]);
        $this->session->setName($cookie);

        try {
            $response = $next($request);

            if ($request->hasSession()) {
                $response->headers->clearCookie($originalCookie, $path, config('session.domain'));
                $location = $response->headers->get('Location') ?? $response->headers->get('X-Inertia-Location');

                if (is_string($location) && ! $this->staysInRealm($request, $location, $path)) {
                    $response->headers->clearCookie('XSRF-TOKEN', $path, config('session.domain'));
                }
            }

            return $response;
        } finally {
            config(['session.cookie' => $originalCookie, 'session.path' => $originalPath]);
            $this->session->setName($originalName);
        }
    }

    private function staysInRealm(Request $request, string $location, string $path): bool
    {
        $host = parse_url($location, PHP_URL_HOST);
        $targetPath = (string) parse_url($location, PHP_URL_PATH);

        return ($host === null || $host === $request->getHost())
            && ($targetPath === $path || str_starts_with($targetPath, $path.'/'));
    }
}
