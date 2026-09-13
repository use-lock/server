<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Views;

use Lock\Server\Shared\Credentials\EnrollmentOption;

final readonly class FactorSetupPrompt
{
    /**
     * @param  list<EnrollmentOption>  $options  what this realm offers, recommended first
     * @param  bool  $required  whether the realm is holding a login until a factor is confirmed
     * @param  bool  $enrolled  whether the user already has a factor that can be challenged
     */
    public function __construct(
        public array $options,
        public bool $required = false,
        public bool $enrolled = false,
        public ?string $status = null,
    ) {}
}
