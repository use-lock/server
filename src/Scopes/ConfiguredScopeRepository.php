<?php

declare(strict_types=1);

namespace Lock\Server\Scopes;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Collection;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeCatalog;
use Lock\Server\Shared\Scopes\ScopeGrantFilter;
use Lock\Server\Shared\Scopes\ScopeParameterPolicy;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Scopes\ScopeTemplate;
use LogicException;

class ConfiguredScopeRepository implements ScopeRepository
{
    private const array UNBOUNDED_GRANTS = ['client_credentials'];

    private const array OIDC_SCOPES = [
        'openid' => 'Authenticate with your account',
        'profile' => 'Access your basic profile information',
        'email' => 'Access your email address',
    ];

    /** @var array<string, array<string, string>> keyed by realm id and audience set */
    private array $catalogs = [];

    public function __construct(
        private readonly Application $app,
        private readonly RealmResolver $realms,
        private readonly RealmAudiences $audiences,
        private readonly ScopeParameterPolicy $parameters = new AssignedScopeParameterPolicy,
        private readonly ScopeGrantFilter $filter = new UnfilteredScopeGrant,
    ) {}

    /** Parameterized templates are left out: only the scopes they expand to exist. */
    public function all(array $audiences = []): Collection
    {
        return collect($this->definitions($audiences))
            ->reject(fn (string $description, string $id): bool => ScopeTemplate::isTemplate($id))
            ->map(fn (string $description, string $id): Scope => new Scope($id, $description))
            ->values();
    }

    public function find(string $identifier, array $audiences = []): ?Scope
    {
        $scope = $this->all($audiences)->first(fn (Scope $scope): bool => $scope->id === $identifier);

        if ($scope instanceof Scope) {
            return $scope;
        }

        $definitions = $this->definitions($audiences);

        if (isset($definitions[$identifier]) && ScopeTemplate::isTemplate($identifier)) {
            return new Scope($identifier, $definitions[$identifier], template: $identifier);
        }

        foreach ($definitions as $template => $description) {
            $value = ScopeTemplate::match($template, $identifier);

            if ($value !== null) {
                return new Scope($identifier, ScopeTemplate::fill($description, $value), template: $template, parameter: $value);
            }
        }

        return null;
    }

    /**
     * @param  list<string>  $requested
     * @param  list<string>  $audiences  the resources the token is for; empty for the realm default
     * @return list<string>
     */
    public function grant(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null, array $audiences = []): array
    {
        $ids = array_values(array_unique($requested));

        if (! in_array($grantType, self::UNBOUNDED_GRANTS, true)) {
            $ids = array_values(array_filter($ids, fn (string $id): bool => $id !== '*'));
        } elseif ($client instanceof Client) {
            $ids = array_values(array_unique([...$ids, ...$client->defaultScopes($audiences)]));
        }

        if ($client instanceof Client) {
            $ids = array_values(array_filter($ids, fn (string $id): bool => $client->allowsScope($id, $audiences)));
        }

        $wildcard = in_array('*', $ids, true);

        $candidates = array_values(array_filter(array_map(
            fn (string $id): ?Scope => $this->find($id, $audiences),
            $ids,
        )));

        $finalized = array_map(
            fn (Scope $scope): string => $scope->id,
            $this->finalize($candidates, $grantType, $client, $userIdentifier, $audiences),
        );

        return $wildcard ? ['*', ...$finalized] : $finalized;
    }

    /**
     * @param  list<Scope>  $requested
     * @param  list<string>  $audiences
     * @return list<Scope>
     */
    public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null, array $audiences = []): array
    {
        $allowed = array_values(array_filter(
            $requested,
            fn (Scope $scope): bool => $this->find($scope->id, $audiences) instanceof Scope
                && ! $scope->isOpen()
                && ($scope->template === null || $this->parameters->allows($scope, $grantType, $client, $userIdentifier, $audiences)),
        ));

        $kept = array_map(
            fn (Scope $scope): string => $scope->id,
            $this->filter->filter($allowed, $grantType, $client, $userIdentifier, $audiences),
        );

        return array_values(array_filter($allowed, fn (Scope $scope): bool => in_array($scope->id, $kept, true)));
    }

    /**
     * @param  list<string>  $audiences
     * @return array<string, string> scope id => description
     */
    private function definitions(array $audiences): array
    {
        return $this->catalog($this->audiences->resolve($audiences)) + self::OIDC_SCOPES;
    }

    /**
     * The scopes the requested resources own: what each of them declares in
     * the realm's resource settings, plus the realm's own catalog when the
     * realm itself is among them. A catalog class is asked for the audiences
     * directly and owns that split itself.
     *
     * @param  list<string>  $audiences
     * @return array<string, string>
     */
    private function catalog(array $audiences): array
    {
        $configured = $this->realms->current()->scopes()->catalog;
        $declared = $this->audiences->declaredScopes($audiences);

        if (is_string($configured)) {
            return $this->fromClass($configured, $audiences) + array_fill_keys($declared, '');
        }

        $realmOwned = in_array($this->audiences->default()[0], $audiences, true)
            ? array_diff_key($configured, array_flip($this->audiences->claimedScopes()))
            : [];

        return $realmOwned + array_intersect_key($configured, array_flip($declared)) + array_fill_keys($declared, '');
    }

    /**
     * A catalog class is resolved once per realm, audience set and instance
     * because it may query the database — and per realm, not per instance,
     * because under Octane one instance serves every realm. Its failures fall
     * back to an empty catalog (fail-closed: unknown scopes are stripped at
     * issuance) instead of breaking the flow.
     *
     * @param  list<string>  $audiences
     * @return array<string, string>
     */
    private function fromClass(string $configured, array $audiences): array
    {
        sort($audiences);
        $key = $this->realms->current()->identifier()."\n".implode("\n", $audiences);

        if (isset($this->catalogs[$key])) {
            return $this->catalogs[$key];
        }

        $catalog = $this->app->make($configured);

        if (! $catalog instanceof ScopeCatalog) {
            throw new LogicException("The configured scope catalog [{$configured}] must implement ScopeCatalog.");
        }

        return $this->catalogs[$key] = rescue(fn (): array => $catalog->scopes($audiences), [], report: ! $this->app->runningInConsole());
    }
}
