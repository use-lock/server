<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Views;

use Lock\Server\Shared\Credentials\FactorEnrollment;

final readonly class TwoFactorChallengePrompt
{
    /**
     * $factor is the provider key of the pending second factor ('totp',
     * 'webauthn', ...) so the view can offer the matching input; $factorId is
     * the active enrollment's id. $availableFactors carries every enrollment
     * the challenge may be switched to, so the view can offer a method picker.
     *
     * @param  list<FactorEnrollment>  $availableFactors
     */
    public function __construct(
        public ?string $factor = null,
        public array $availableFactors = [],
        public ?string $factorId = null,
    ) {}
}
