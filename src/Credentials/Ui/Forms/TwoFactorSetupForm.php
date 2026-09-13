<?php
declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Forms;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Lattice\Core\Enums\ColorName;
use Lattice\Core\Option;
use Lattice\Facades\Effects;
use Lattice\Form\Attributes\AsForm;
use Lattice\Form\Components\Choice;
use Lattice\Form\Components\Form;
use Lattice\Form\Components\Wizard;
use Lattice\Form\Components\WizardStep;
use Lattice\Form\FormDefinition;
use Lattice\Http\LatticeResponse;
use Lattice\Ui\Components\Badge;
use Lattice\Ui\Components\Component;
use Lattice\Ui\Components\Icon;
use Lattice\Ui\Components\Stack;
use Lattice\Ui\Components\Text;
use Lattice\Ui\Enums\Align;
use Lattice\Ui\Enums\Gap;
use Lattice\Ui\Enums\Orientation;
use Lattice\Ui\Enums\Size;
use Lattice\Ui\Enums\Variant;
use Lattice\Ui\Enums\Width;
use Lock\Server\Credentials\EnrollmentPolicy;
use Lock\Server\Credentials\FactorRegistry;
use Lock\Server\Credentials\Ui\Concerns\ManagesTwoFactor;
use Lock\Server\Credentials\Ui\Fields\TwoFactorSetupField;
use Lock\Server\Credentials\Ui\Support\EnrollmentOptionLabels;
use Lock\Server\Credentials\Ui\Support\RecoveryCodesModal;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorSetupKind;

/**
 * Precognition resolves step two during Next validation, beginning enrollment before it is shown.
 */
#[AsForm('oidc.two-factor.setup')]
class TwoFactorSetupForm extends FormDefinition
{
    use ManagesTwoFactor;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly EnrollmentPolicy $policy,
    ) {}

    public function definition(Form $form, Request $request): Form
    {
        $options = $this->factors->enrollmentOptions();

        return $form->schema([
            Wizard::make([
                WizardStep::make('method', __('oidc-ui::security.setup.step-method'))
                    ->description(__('oidc-ui::security.setup.step-method-description'))
                    ->schema([
                        Choice::make('option', __('oidc-ui::security.setup.method'))
                            ->options(array_map($this->pickerOption(...), $options))
                            ->optionSchema($this->pickerCard())
                            // Resolve the preselected option even when the user never clicks it.
                            ->value($options[0]->id ?? null)
                            ->rules(['required', Rule::in(array_column($options, 'id'))]),
                    ]),
                WizardStep::make('configure', __('oidc-ui::security.setup.step-configure'))
                    ->description(__('oidc-ui::security.setup.step-configure-description'))
                    ->schema([
                        TwoFactorSetupField::make('setup', __('oidc-ui::security.setup.confirmation')),
                    ]),
            ])->align(Align::Center),
        ]);
    }

    public function handle(Request $request): LatticeResponse
    {
        $user = $this->twoFactorUser();
        $option = $this->factors->enrollmentOption((string) $request->input('option')) ?? abort(404);
        $provider = $this->factors->enrollable($option->providerKey) ?? abort(404);

        $pending = Arr::last(
            $provider->enrollments($user),
            static fn (FactorEnrollment $enrollment): bool => ! $enrollment->confirmedAt instanceof \DateTimeInterface,
        );

        $confirmed = $pending instanceof FactorEnrollment && $provider->confirmEnrollment(
            $user,
            $pending,
            $this->confirmationInput($option, $request->input('setup')),
        );

        if (! $confirmed) {
            throw ValidationException::withMessages([
                'setup' => __('oidc-ui::security.setup.invalid'),
            ]);
        }

        $response = Effects::respond()->toast(
            __('oidc-ui::security.setup.confirmed', ['method' => EnrollmentOptionLabels::label($option)]),
            Variant::Success,
        );

        if ($this->policy->factorConfirmed($user)) {
            $response = $response->openModal(RecoveryCodesModal::make(
                (string) $this->context('recovery_codes_modal', RecoveryCodesModal::DEFAULT_ID),
            ));
        }

        return $response->back();
    }

    /**
     * Visibility is schema-wide, not per option; ordering conveys recommendation without empty badges.
     *
     * @return array<int, Component>
     */
    private function pickerCard(): array
    {
        return [
            Stack::make()
                ->direction(Orientation::Horizontal)
                ->align(Align::Center)
                ->gap(Gap::Medium)
                ->schema([
                    Icon::make('')->dataKey('name', 'icon')->size(Size::Lg),
                    // A full-width stack would wrap under the icon.
                    Stack::make()
                        ->width(Width::Fill)
                        ->gap(Gap::Small)
                        ->schema([
                            Stack::make()
                                ->direction(Orientation::Horizontal)
                                ->align(Align::Center)
                                ->gap(Gap::Small)
                                ->schema([
                                    Text::make('')->dataKey('text', 'label'),
                                    Badge::make('')->dataKey('label', 'role'),
                                ]),
                            Text::make('')
                                ->dataKey('text', 'description')
                                ->size(Size::Sm)
                                ->color(ColorName::Muted),
                        ]),
                ]),
        ];
    }

    private function pickerOption(EnrollmentOption $option): Option
    {
        return Choice::option(
            EnrollmentOptionLabels::label($option),
            $option->id,
            [
                'description' => EnrollmentOptionLabels::description($option),
                'role' => EnrollmentOptionLabels::role($option),
                'icon' => EnrollmentOptionLabels::icon($option),
                'recommended' => $option->recommended,
            ],
        );
    }

    /**
     * Inertia serializes DOM inputs, so the credential travels as a JSON string with the user-supplied label.
     *
     * @return array<string, mixed>
     */
    private function confirmationInput(EnrollmentOption $option, mixed $value): array
    {
        if ($option->setupKind === FactorSetupKind::Code) {
            return ['code' => is_string($value) ? $value : ''];
        }

        $submitted = is_array($value) ? $value : [];
        $name = $submitted['name'] ?? null;
        $credential = $submitted['credential'] ?? null;

        if (is_string($credential)) {
            $credential = json_decode($credential, true);
        }

        return [
            'credential' => is_array($credential) ? $credential : [],
            'name' => is_string($name) ? $name : null,
        ];
    }
}
