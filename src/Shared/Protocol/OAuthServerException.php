<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

use RuntimeException;

final class OAuthServerException extends RuntimeException
{
    /** @param string|null $error null for the RFC 6750 §3.1 challenge without credentials */
    private function __construct(
        public readonly ?string $error,
        public readonly string $description,
        public readonly ?string $redirectUri = null,
        public readonly ?string $state = null,
    ) {
        parent::__construct($description);
    }

    public static function invalidRequest(string $description, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('invalid_request', $description, $redirectUri, $state);
    }

    /** RFC 6749 §5.2: the challenge names the realm the client failed to authenticate against. */
    public static function invalidClient(string $description = 'Client authentication failed.'): self
    {
        return new self('invalid_client', $description);
    }

    /**
     * RFC 6750 §3.1: a request without any bearer token is challenged without
     * an error code, and without a body to describe one.
     */
    public static function bearerRequired(): self
    {
        return new self(null, 'A bearer token is required.');
    }

    /** RFC 6750 §3.1. */
    public static function invalidToken(string $description = 'The access token is invalid.'): self
    {
        return new self('invalid_token', $description);
    }

    /** RFC 6750 §3.1. */
    public static function insufficientScope(string $description = 'The access token does not grant the required scope.'): self
    {
        return new self('insufficient_scope', $description);
    }

    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', $description);
    }

    public static function unauthorizedClient(string $description, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('unauthorized_client', $description, $redirectUri, $state);
    }

    public static function unsupportedGrantType(): self
    {
        return new self('unsupported_grant_type', 'The authorization grant type is not supported by the authorization server.');
    }

    public static function unsupportedResponseType(string $redirectUri, ?string $state): self
    {
        return new self('unsupported_response_type', 'The authorization server does not support obtaining an authorization code using this method.', $redirectUri, $state);
    }

    public static function invalidScope(string $scope, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('invalid_scope', "The requested scope is invalid, unknown, or malformed: {$scope}.", $redirectUri, $state);
    }

    public static function accessDenied(?string $description = null, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('access_denied', $description ?? 'The resource owner or authorization server denied the request.', $redirectUri, $state);
    }

    /** RFC 8707 §2 / RFC 8693 §2.2.2. */
    public static function invalidTarget(string $description, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('invalid_target', $description, $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6. */
    public static function loginRequired(string $redirectUri, ?string $state): self
    {
        return new self('login_required', 'The authorization server requires end-user authentication.', $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6: the end user must do something the request forbade prompting for. */
    public static function interactionRequired(string $redirectUri, ?string $state): self
    {
        return new self('interaction_required', 'The authorization server requires end-user interaction.', $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6. */
    public static function consentRequired(string $redirectUri, ?string $state): self
    {
        return new self('consent_required', 'The authorization server requires end-user consent.', $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6 / §6. */
    public static function requestNotSupported(string $redirectUri, ?string $state): self
    {
        return new self('request_not_supported', 'The authorization server does not support the request parameter.', $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6 / §6. */
    public static function requestUriNotSupported(string $redirectUri, ?string $state): self
    {
        return new self('request_uri_not_supported', 'The authorization server does not support the request_uri parameter.', $redirectUri, $state);
    }

    public static function serverError(string $description): self
    {
        return new self('server_error', $description);
    }
}
