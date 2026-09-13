<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\WebAuthn;

use Laravel\Passkeys\Actions\GenerateRegistrationOptions;
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * Override attachment to match the selected authenticator; retain the parent’s security requirements.
 */
final class AttachmentAwareRegistrationOptions extends GenerateRegistrationOptions
{
    public function __construct(private readonly string $attachment) {}

    #[\Override]
    public function authenticatorSelection(): AuthenticatorSelectionCriteria
    {
        $selection = parent::authenticatorSelection();

        return AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: $this->attachment,
            userVerification: $selection->userVerification,
            residentKey: $selection->residentKey,
        );
    }
}
