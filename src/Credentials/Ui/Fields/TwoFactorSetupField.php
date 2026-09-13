<?php
declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Fields;

use Lattice\Form\Attributes\AsField;
use Lattice\Form\Components\Field;
use Lock\Server\Credentials\FactorRegistry;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorSetupKind;
use Lock\Server\Shared\Ui\Support\ScreenSubject;

/**
 * Resolving option begins enrollment. Providers must make repeated resolves idempotent.
 */
#[AsField('oidc.two-factor-setup')]
class TwoFactorSetupField extends Field
{
    /** `code` or `ceremony` — which body the client renders. */
    public ?string $kind = null;

    public ?string $qrSvg = null;

    public ?string $secret = null;

    public int $otpLength = 6;

    /** @var array<string, mixed>|null */
    public ?array $webauthnOptions = null;

    public ?string $enrollmentId = null;

    #[\Override]
    public static function make(string $name, ?string $label = null): static
    {
        return parent::make($name, $label)->dependsOn('option', self::resolveSetup(...));
    }

    /**
     * @return array<int, mixed>
     */
    protected function defaultRules(): array
    {
        return match ($this->kind) {
            FactorSetupKind::Code->value => ['required', 'string'],
            FactorSetupKind::Ceremony->value => ['required', 'array'],
            default => ['required'],
        };
    }

    /**
     * Submit also resolves fields; only begin an empty enrollment or WebAuthn loses its challenge.
     */
    private static function resolveSetup(self $component, callable $get, mixed $value): void
    {
        $component->reset();

        $option = self::option((string) ($get('option') ?? ''));
        $user = ScreenSubject::current();

        if (! $option instanceof EnrollmentOption || $user === null) {
            return;
        }

        $component->kind = $option->setupKind->value;

        if (self::isFilled($value)) {
            return;
        }

        $enrollment = (app(FactorRegistry::class)->enrollable($option->providerKey) ?? abort(404))
            ->beginEnrollment($user, $option);

        $component->enrollmentId = $enrollment->id;

        $metadata = $enrollment->metadata;
        $component->qrSvg = is_string($metadata['qr_svg'] ?? null) ? $metadata['qr_svg'] : null;
        $component->secret = is_string($metadata['secret'] ?? null) ? $metadata['secret'] : null;
        $component->webauthnOptions = is_array($metadata['options'] ?? null) ? $metadata['options'] : null;
    }

    private static function isFilled(mixed $value): bool
    {
        return match (true) {
            is_string($value) => $value !== '',
            is_array($value) => $value !== [],
            default => $value !== null,
        };
    }

    private static function option(string $id): ?EnrollmentOption
    {
        return $id === '' ? null : app(FactorRegistry::class)->enrollmentOption($id);
    }

    private function reset(): void
    {
        $this->kind = null;
        $this->qrSvg = null;
        $this->secret = null;
        $this->webauthnOptions = null;
        $this->enrollmentId = null;
    }
}
