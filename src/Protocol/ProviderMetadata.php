<?php

declare(strict_types=1);

namespace Lock\Server\Protocol;

use Illuminate\Support\Facades\Route;
use Lock\Server\Shared\Authentication\AcrResolver;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeRepository;

/**
 * RFC 8414 §2 permits the OIDC Discovery fields in authorization server metadata.
 */
final readonly class ProviderMetadata
{
    public function __construct(
        private ScopeRepository $scopes,
        private IssuerResolver $issuer,
        private RealmResolver $realms,
        private EndpointUrl $endpoints,
        private AcrResolver $acr,
        private RealmAudiences $audiences,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function document(): array
    {
        $realm = $this->realms->current();
        $grantTypes = ['authorization_code', 'refresh_token', 'client_credentials'];

        if ($realm->clients()->tokenExchange) {
            $grantTypes[] = 'urn:ietf:params:oauth:grant-type:token-exchange';
        }

        $document = [
            'issuer' => $this->issuer->url(),
            'authorization_endpoint' => $this->endpoint('oidc.authorize'),
            'token_endpoint' => $this->endpoint('oidc.token'),
            'jwks_uri' => $this->endpoint('oidc.jwks'),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => $grantTypes,
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => $this->scopes->all($this->audiences->all())
                ->reject(fn (Scope $scope): bool => $scope->hidden)
                ->map(fn (Scope $scope): string => $scope->id)
                ->values()
                ->all(),
            'claims_supported' => $realm->scopes()->claimsSupported,
            'acr_values_supported' => $this->acr->supported(),
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => ['S256'],
            'authorization_response_iss_parameter_supported' => true,
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
        ];

        if (Route::has('oidc.userinfo')) {
            $document['userinfo_endpoint'] = $this->endpoint('oidc.userinfo');
        }

        if (Route::has('oidc.logout')) {
            $document['end_session_endpoint'] = $this->endpoint('oidc.logout');
        }

        if (Route::has('oidc.introspect')) {
            $document['introspection_endpoint'] = $this->endpoint('oidc.introspect');
            $document['introspection_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post'];
        }

        if (Route::has('oidc.revoke')) {
            $document['revocation_endpoint'] = $this->endpoint('oidc.revoke');
            $document['revocation_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post', 'none'];
        }

        if ($realm->clients()->dynamicRegistration) {
            $document['registration_endpoint'] = $this->endpoint('oidc.register');
        }

        return $document;
    }

    public function endpoint(string $routeName): string
    {
        return $this->endpoints->of($routeName);
    }
}
