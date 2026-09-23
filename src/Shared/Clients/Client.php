<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

use Lock\Server\Shared\Scopes\ScopeTemplate;

final readonly class Client
{
    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $postLogoutRedirectUris
     * @param  list<string>  $grantTypes
     * @param  list<string>  $defaultScopeAssignments
     * @param  list<string>  $optionalScopeAssignments
     * @param  list<string>  $allowedAudiences
     */
    public function __construct(
        public string $key,
        public string $clientId,
        public string $realm,
        public string $name,
        public TokenEndpointAuthMethod $authMethod,
        public array $redirectUris,
        public array $postLogoutRedirectUris,
        public array $grantTypes,
        public array $defaultScopeAssignments,
        public array $optionalScopeAssignments,
        public array $allowedAudiences,
        public ?string $backchannelLogoutUri,
        public bool $backchannelLogoutSessionRequired,
        public bool $consentRequired,
        public bool $confidential,
        public bool $revoked,
    ) {}

    public function hasGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    /**
     * Default scopes are granted unasked, optional ones on request; `*` among
     * the optional scopes stands for every scope the requested resources own.
     *
     * @param  list<string>  $audiences  the resources the request is for
     */
    public function allowsScope(string $scope, array $audiences = []): bool
    {
        $assigned = $this->assignedScopes($audiences);

        return in_array($scope, $assigned, true)
            || in_array('*', $this->optionalScopes($audiences), true)
            || array_any($assigned, fn (string $template): bool => ScopeTemplate::match($template, $scope) !== null);
    }

    /**
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function defaultScopes(array $audiences = []): array
    {
        return $this->scopesFor($this->defaultScopeAssignments, $audiences);
    }

    /**
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function optionalScopes(array $audiences = []): array
    {
        return $this->scopesFor($this->optionalScopeAssignments, $audiences);
    }

    /**
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function assignedScopes(array $audiences = []): array
    {
        return array_values(array_unique([...$this->defaultScopes($audiences), ...$this->optionalScopes($audiences)]));
    }

    /**
     * An assignment entry may name the resource that owns the scope
     * (`<resource> <scope>`, the RFC 8707 identifier first), which limits it to
     * requests for that resource; a bare entry holds under every resource. A
     * space cannot occur in a scope token (RFC 6749 §3.3), so the two forms
     * never collide.
     *
     * @param  array<int, string>  $assigned
     * @param  list<string>  $audiences
     * @return list<string>
     */
    private function scopesFor(array $assigned, array $audiences): array
    {
        $scopes = [];

        foreach ($assigned as $entry) {
            [$resource, $scope] = str_contains($entry, ' ') ? explode(' ', $entry, 2) : [null, $entry];

            if ($resource === null || in_array($resource, $audiences, true)) {
                $scopes[] = $scope;
            }
        }

        return array_values(array_unique($scopes));
    }
}
