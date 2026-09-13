<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

/**
 * Required actions derive from emailVerificationRequired, mfa and password
 * maxAgeDays; separate switches would allow contradictory settings.
 */
final readonly class AuthenticationSettings
{
    /**
     * @param  list<LoginMethod>  $methods  the login methods the realm accepts
     * @param  MfaRequirement  $mfa  how hard the realm insists on a second factor
     * @param  bool  $emailVerificationRequired  whether an unverified address blocks the login
     */
    public function __construct(
        public array $methods = [LoginMethod::Password, LoginMethod::Passkey, LoginMethod::Social],
        public MfaRequirement $mfa = MfaRequirement::IfEnrolled,
        public bool $emailVerificationRequired = false,
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            methods: LoginMethod::listFromConfig((array) config('oidc.authentication.methods', ['password', 'passkey', 'social'])),
            mfa: MfaRequirement::fromConfig(config('oidc.authentication.mfa')),
            emailVerificationRequired: (bool) config('oidc.authentication.email_verification_required', false),
        );
    }

    public function allows(LoginMethod $method): bool
    {
        return in_array($method, $this->methods, true);
    }
}
