<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Lattice\Core\Enums\ColorName;
use Lattice\Form\Components\Checkbox;
use Lattice\Form\Components\Form;
use Lattice\Form\Components\PasswordInput;
use Lattice\Form\Components\TextInput;
use Lattice\Ui\Components\Button;
use Lattice\Ui\Components\Component;
use Lattice\Ui\Components\Grid;
use Lattice\Ui\Components\Link;
use Lattice\Ui\Components\Stack;
use Lattice\Ui\Components\Text;
use Lattice\Ui\Enums\Align;
use Lattice\Ui\Enums\Gap;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\Enums\Orientation;
use Lattice\Ui\Enums\Size;
use Lattice\Ui\Enums\TextAlign;
use Lattice\Ui\PageSchema;
use Lock\Server\Authentication\Ui\Views\LoginPrompt;
use Lock\Server\Authentication\Ui\Views\LoginView;
use Lock\Server\Credentials\Ui\Components\PasskeyVerify;
use Lock\Server\Shared\Brokering\SocialProviderRegistry;
use Lock\Server\Shared\Realms\Settings\LoginMethod;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use Symfony\Component\HttpFoundation\Response;

class LoginPage extends AuthPage implements LoginView
{
    final public function __construct(
        protected readonly ?LoginPrompt $prompt = null,
    ) {}

    public function respond(LoginPrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.login.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        $passkey = $this->allows(LoginMethod::Passkey)
            ? PasskeyVerify::makeIfAvailable('identity.passkey.login-options', 'identity.passkey.login')
            : null;

        return $schema->schema([
            $this->heading('login-heading', __('oidc-ui::auth.login.heading'), __('oidc-ui::auth.login.subtitle')),
            ...($passkey instanceof PasskeyVerify ? [$passkey] : []),
            ...($this->allows(LoginMethod::Password) ? [
                Form::make('login-form')
                    ->action(route('identity.login.store', absolute: false))
                    ->method(HttpMethod::Post)
                    ->schema($this->formSchema())
                    ->resetOnSuccess(['password'])
                    ->withoutSubmitButton()
                    ->status($this->prompt?->status),
            ] : []),
            ...$this->socialButtons(),
        ]);
    }

    /**
     * A page rendered without a prompt (a subclass instantiated directly) has
     * no realm to ask, so it shows everything it can.
     */
    protected function allows(LoginMethod $method): bool
    {
        return $this->prompt?->allows($method) ?? true;
    }

    /**
     * @return array<int, Component>
     */
    protected function socialButtons(): array
    {
        $providers = $this->allows(LoginMethod::Social)
            ? array_keys(app(SocialProviderRegistry::class)->enabled())
            : [];

        if ($providers === []) {
            return [];
        }

        $buttons = array_map(function (string $provider): Button {
            $button = Button::make($this->socialButtonLabel($provider), "login-social-{$provider}")
                ->href(route('identity.social.redirect', ['provider' => $provider], absolute: false));

            // Rendered from the consuming app's SVG sprite, like brand_icon;
            // set oidc-ui.social_icons.{provider} to '' to drop the icon.
            $icon = config()->string("oidc-ui.social_icons.{$provider}", $provider);

            return $icon === '' ? $button : $button->icon($icon);
        }, $providers);

        return [
            Stack::make('login-social')
                ->gap(Gap::Small)
                ->schema([
                    Text::make(__('oidc-ui::auth.login.social.divider'))
                        ->color(ColorName::Muted)
                        ->size(Size::Sm)
                        ->align(TextAlign::Center),
                    ...$buttons,
                ]),
        ];
    }

    protected function socialButtonLabel(string $provider): string
    {
        $key = "oidc-ui::auth.login.social.{$provider}";

        if (Lang::has($key)) {
            return (string) __($key);
        }

        return (string) __('oidc-ui::auth.login.social.fallback', ['provider' => Str::headline($provider)]);
    }

    /**
     * @return array<int, Component>
     */
    private function formSchema(): array
    {
        $email = $this->emailField();

        $password = $this->passwordInput();

        $schema = [
            Grid::make('login-fields')
                ->columns(1)
                ->schema([
                    $email,
                    $password,
                    Checkbox::make('remember', __('oidc-ui::auth.login.remember')),
                ]),
            Button::make(__('oidc-ui::common.action.log-in'))->submit(),
        ];

        // A host application can disable the register handler; the sign-up
        // prompt would then link to a route that does not exist. A realm that
        // does not accept passwords keeps the route but answers 404 on it.
        if (Route::has('identity.register') && $this->allows(LoginMethod::Password)) {
            $schema[] = Stack::make('login-register-prompt')
                ->align(Align::Center)
                ->direction(Orientation::Horizontal)
                ->gap(Gap::ExtraSmall)
                ->schema([
                    Text::make(__('oidc-ui::auth.login.no-account')),
                    Link::make(__('oidc-ui::auth.login.sign-up'))
                        ->href(route('identity.register', absolute: false)),
                ]);
        }

        return $schema;
    }

    protected function emailField(): TextInput
    {
        return TextInput::make('email', __('oidc-ui::common.field.email-address'))
            ->email()
            ->autoComplete('email')
            ->autoFocus()
            ->placeholder(__('oidc-ui::common.placeholder.email'))
            ->required();
    }

    protected function passwordInput(): PasswordInput
    {
        return PasswordInput::make('password', __('oidc-ui::common.field.password'))
            ->autoComplete('current-password')
            ->placeholder(__('oidc-ui::common.placeholder.password'))
            ->required()
            ->labelAction(Link::make(__('oidc-ui::auth.login.forgot-password'))->href(route('identity.password.request', absolute: false)));
    }
}
