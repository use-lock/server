<?php
declare(strict_types=1);

namespace Lock\Server\Consents\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Lattice\Form\Components\Form;
use Lattice\Form\Components\HiddenInput;
use Lattice\Form\Components\Select;
use Lattice\Ui\Components\Button;
use Lattice\Ui\Components\Component;
use Lattice\Ui\Components\Heading;
use Lattice\Ui\Components\Stack;
use Lattice\Ui\Components\Text;
use Lattice\Ui\Enums\Gap;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\PageSchema;
use Lock\Server\Shared\Consents\ConsentPrompt;
use Lock\Server\Shared\Consents\ConsentView;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeParameterPolicy;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

class OAuthConsentPage extends AuthPage implements ConsentView
{
    final public function __construct(
        protected readonly ?ConsentPrompt $prompt = null,
    ) {}

    public function respond(ConsentPrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::oauth.consent.heading', ['client' => (string) $this->prompt?->client->name]);
    }

    public function render(PageSchema $schema): PageSchema
    {
        $prompt = $this->prompt ?? throw new LogicException(static::class.' rendered without its prompt; respond() must supply one before render() runs.');
        $user = $prompt->user;
        $userEmail = $user instanceof Model ? (string) $user->getAttribute('email') : '';

        return $schema->schema([
            Stack::make('oauth-consent-heading')
                ->gap(Gap::Small)
                ->schema([
                    Heading::make(__('oidc-ui::oauth.consent.heading', ['client' => $prompt->client->name]), 2),
                    Text::make(__('oidc-ui::oauth.consent.signed-in-as', ['email' => $userEmail])),
                ]),
            Stack::make('oauth-consent-scopes')
                ->gap(Gap::Small)
                ->schema($this->scopeSchema($prompt)),
            Stack::make('oauth-consent-actions')
                ->gap(Gap::Small)
                ->schema([
                    Form::make('oauth-consent-approve')
                        ->action(route('oidc.approve', absolute: false))
                        ->method(HttpMethod::Post)
                        ->withoutSubmitButton()
                        ->schema([
                            HiddenInput::make('auth_token')->value($prompt->authToken),
                            ...$this->parameterFields($prompt),
                            ...$this->approveFields($prompt),
                            Button::make(__('oidc-ui::oauth.consent.approve'))->submit(),
                        ]),
                    Form::make('oauth-consent-deny')
                        ->action(route('oidc.deny', absolute: false))
                        ->method(HttpMethod::Delete)
                        ->withoutSubmitButton()
                        ->schema([
                            HiddenInput::make('auth_token')->value($prompt->authToken),
                            Button::make(__('oidc-ui::oauth.consent.deny'))->submit(),
                        ]),
                ]),
        ]);
    }

    /**
     * Extension point for host apps: extra fields rendered inside the approve
     * form, submitted alongside `auth_token` to the `oidc.approve` endpoint.
     *
     * @return array<int, Component>
     */
    protected function approveFields(ConsentPrompt $prompt): array
    {
        return [];
    }

    /**
     * One picker per open template, offering the values the parameter policy
     * lets this user choose. A template without any value to offer gets no
     * picker and lapses on approval.
     *
     * @return list<Select>
     */
    private function parameterFields(ConsentPrompt $prompt): array
    {
        $policy = app(ScopeParameterPolicy::class);
        $userIdentifier = (string) $prompt->user->getAuthIdentifier();
        $open = array_values(array_filter($prompt->scopes, fn (Scope $scope): bool => $scope->isOpen()));
        $fields = [];

        foreach ($open as $position => $template) {
            $options = $policy->options($template, $prompt->client, $userIdentifier, $prompt->resources);

            if ($options !== []) {
                $fields[] = Select::make(ConsentPrompt::parameterField($position), $template->description)
                    ->options($options)
                    ->value(array_key_first($options))
                    ->required();
            }
        }

        return $fields;
    }

    /**
     * @return array<int, Component>
     */
    private function scopeSchema(ConsentPrompt $prompt): array
    {
        // Hidden scopes are excluded from discovery on purpose; the consent
        // page must not disclose them either.
        $visible = array_values(array_filter(
            $prompt->scopes,
            fn (Scope $scope): bool => ! $scope->hidden,
        ));

        if ($visible === []) {
            return [];
        }

        return [
            Heading::make(__('oidc-ui::oauth.consent.requested-scopes'), 3),
            ...array_map(
                fn (Scope $scope): Text => Text::make($scope->description),
                $visible,
            ),
        ];
    }
}
