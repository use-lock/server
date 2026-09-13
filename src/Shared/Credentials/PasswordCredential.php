<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lock\Server\Shared\Realms\Settings\PasswordPolicy;
use SensitiveParameter;

/**
 * The host owns password persistence; this contract owns realm policy, verification and history.
 */
interface PasswordCredential
{
    public function verify(Authenticatable $user, #[SensitiveParameter] string $password): bool;

    /**
     * Checks a new password against the realm's policy; $user enables the
     * history rule and is null at registration.
     *
     * @throws ValidationException on the `password` key
     */
    public function validate(?Authenticatable $user, #[SensitiveParameter] string $password): void;

    /** Records the password the user has now, once a change has been persisted. */
    public function record(Authenticatable $user): void;

    /**
     * Start untracked history without resetting an existing rotation clock.
     */
    public function track(Authenticatable $user): void;

    public function changedAt(Authenticatable $user): ?CarbonInterface;

    public function isExpired(Authenticatable $user): bool;

    public function policy(): PasswordPolicy;
}
