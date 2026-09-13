<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Lattice\Form\Components\Checkbox;
use Lattice\Form\Components\Form;
use Lattice\Form\Components\OtpInput;
use Lattice\Form\Components\TextInput;
use Lattice\Ui\Components\Link;
use Lattice\Ui\Components\Stack;
use Lattice\Ui\Components\Text;
use Lattice\Ui\Enums\Align;
use Lattice\Ui\Enums\Gap;
use Lattice\Ui\PageSchema;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengePrompt;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengeView;
use Lock\Server\Credentials\Ui\Components\PasskeyVerify;
use Lock\Server\Credentials\Ui\Support\FactorMethodName;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use Symfony\Component\HttpFoundation\Response;

class TwoFactorChallengePage extends AuthPage implements TwoFactorChallengeView
{
    final public function __construct(
        protected readonly ?TwoFactorChallengePrompt $prompt = null,
    ) {}

    public function respond(TwoFactorChallengePrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.two-factor.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        $passkey = $this->prompt?->factor === 'webauthn'
            ? PasskeyVerify::makeIfAvailable(
                'identity.two-factor.login.options',
                'identity.two-factor.login.store',
                label: __('oidc-ui::auth.two-factor.passkey-label'),
                loadingLabel: __('oidc-ui::auth.two-factor.passkey-loading'),
                separator: __('oidc-ui::auth.two-factor.passkey-separator'),
            )
            : null;
        $webauthn = $passkey instanceof PasskeyVerify;

        return $schema->schema([
            $this->heading('two-factor-challenge-heading', __('oidc-ui::auth.two-factor.heading'), $webauthn
                ? __('oidc-ui::auth.two-factor.subtitle-passkey')
                : __('oidc-ui::auth.two-factor.subtitle')),
            ...($webauthn ? [$passkey] : []),
            Form::make('two-factor-challenge')
                ->action(route('identity.two-factor.login.store', absolute: false))
                ->submitLabel(__('oidc-ui::auth.two-factor.continue'))
                ->schema($webauthn ? [
                    TextInput::make('recovery_code', __('oidc-ui::auth.two-factor.recovery-code'))
                        ->helperText(__('oidc-ui::auth.two-factor.recovery-help')),
                ] : [
                    OtpInput::make('code', __('oidc-ui::auth.two-factor.code'))
                        ->length(6)
                        ->visibleWhen('use_recovery_code', false),
                    TextInput::make('recovery_code', __('oidc-ui::auth.two-factor.recovery-code'))
                        ->helperText(__('oidc-ui::auth.two-factor.recovery-help'))
                        ->visibleWhen('use_recovery_code', true),
                    Checkbox::make('use_recovery_code', __('oidc-ui::auth.two-factor.use-recovery')),
                ]),
            ...$this->factorSwitcher(),
        ]);
    }

    /**
     * @return list<Stack>
     */
    private function factorSwitcher(): array
    {
        if (! Route::has('identity.two-factor.login.factor')) {
            return [];
        }

        $available = $this->prompt->availableFactors ?? [];
        $countPerProvider = array_count_values(array_map(
            fn (FactorEnrollment $enrollment): string => $enrollment->providerKey,
            $available,
        ));

        $links = [];

        foreach ($available as $enrollment) {
            if ($enrollment->providerKey === $this->prompt?->factor
                && ($this->prompt->factorId === null || $enrollment->id === $this->prompt->factorId)) {
                continue;
            }

            $label = FactorMethodName::for($enrollment->providerKey);

            if ($countPerProvider[$enrollment->providerKey] > 1) {
                $label .= " ({$enrollment->label})";
            }

            $links[] = Link::make($label)->href(route('identity.two-factor.login.factor', [
                'provider' => $enrollment->providerKey,
                'enrollment' => $enrollment->id,
            ], absolute: false));
        }

        if ($links === []) {
            return [];
        }

        return [
            Stack::make('two-factor-switcher')
                ->align(Align::Center)
                ->gap(Gap::ExtraSmall)
                ->schema([
                    Text::make(__('oidc-ui::auth.two-factor.use-another')),
                    ...$links,
                ]),
        ];
    }
}
