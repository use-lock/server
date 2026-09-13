<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms;

/**
 * The issuer is the default audience (RFC 9068 §3). Registered resources are
 * additional audiences the bearer guard accepts (§4); path-relative resources
 * are published through RFC 9728 metadata.
 */
final readonly class RealmAudiences
{
    public function __construct(
        private RealmResolver $realms,
        private IssuerResolver $issuer,
    ) {}

    /** @return list<string> */
    public function default(): array
    {
        return [$this->issuer->url()];
    }

    /** @return list<string> */
    public function all(): array
    {
        return array_values(array_unique([
            $this->issuer->url(),
            ...array_map($this->identifier(...), array_keys($this->realms->current()->resources()->resources)),
        ]));
    }

    /** @param  list<string>  $audience */
    public function accepts(array $audience): bool
    {
        return array_intersect($audience, $this->all()) !== [];
    }

    /**
     * The resources a request is addressed to: an RFC 8707 `resource` names
     * them, its absence means the realm itself.
     *
     * @param  list<string>  $requested
     * @return list<string>
     */
    public function resolve(array $requested): array
    {
        return $requested === [] ? $this->default() : $requested;
    }

    /**
     * The scopes the given resources declare, the same set each publishes as
     * RFC 9728 `scopes_supported`.
     *
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function declaredScopes(array $audiences): array
    {
        $scopes = [];

        foreach ($this->realms->current()->resources()->resources as $resource => $declared) {
            if (in_array($this->identifier($resource), $audiences, true)) {
                $scopes = [...$scopes, ...$declared];
            }
        }

        return array_values(array_unique($scopes));
    }

    /** @return list<string> */
    public function claimedScopes(): array
    {
        return $this->declaredScopes($this->all());
    }

    /** @return list<string>|null */
    public function advertisedScopes(string $path): ?array
    {
        $resources = $this->realms->current()->resources()->resources;
        $path = trim($path, '/');

        foreach ($resources as $identifier => $scopes) {
            if (! $this->isAbsolute($identifier) && trim($identifier, '/') === $path) {
                return $scopes;
            }
        }

        return null;
    }

    /**
     * RFC 9728 §3.3: a protected resource declared under a path relative to
     * the issuer is identified by the issuer URL with that path appended.
     */
    public function protectedResource(string $path): string
    {
        $path = trim($path, '/');
        $issuer = $this->issuer->url();

        return $path === '' ? $issuer : $issuer.'/'.$path;
    }

    private function identifier(string $resource): string
    {
        return $this->isAbsolute($resource) ? $resource : $this->protectedResource($resource);
    }

    private function isAbsolute(string $resource): bool
    {
        return parse_url($resource, PHP_URL_SCHEME) !== null;
    }
}
