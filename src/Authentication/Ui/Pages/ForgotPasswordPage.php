<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Lattice\Form\Components\Form;
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
use Lattice\Ui\PageSchema;
use Lock\Server\Authentication\Ui\Views\PasswordResetRequestPrompt;
use Lock\Server\Authentication\Ui\Views\PasswordResetRequestView;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use Symfony\Component\HttpFoundation\Response;

class ForgotPasswordPage extends AuthPage implements PasswordResetRequestView
{
    final public function __construct(
        protected readonly ?PasswordResetRequestPrompt $prompt = null,
    ) {}

    public function respond(PasswordResetRequestPrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.forgot-password.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        return $schema->schema([
            $this->heading('forgot-password-heading', __('oidc-ui::auth.forgot-password.heading'), __('oidc-ui::auth.forgot-password.subtitle')),
            Form::make('forgot-password-form')
                ->action(route('identity.password.email', absolute: false))
                ->method(HttpMethod::Post)
                ->schema($this->formSchema())
                ->resetOnSuccess(['email'])
                ->withoutSubmitButton()
                ->status($this->prompt?->status),
        ]);
    }

    /**
     * @return array<int, Component>
     */
    private function formSchema(): array
    {
        return [
            Grid::make('forgot-password-fields')
                ->columns(1)
                ->schema([
                    TextInput::make('email', __('oidc-ui::common.field.email-address'))
                        ->email()
                        ->autoComplete('off')
                        ->autoFocus()
                        ->placeholder(__('oidc-ui::common.placeholder.email'))
                        ->required(),
                ]),
            Button::make(__('oidc-ui::auth.forgot-password.submit'))->submit(),
            Stack::make('forgot-password-login-prompt')
                ->align(Align::Center)
                ->direction(Orientation::Horizontal)
                ->gap(Gap::ExtraSmall)
                ->schema([
                    Text::make(__('oidc-ui::auth.forgot-password.return')),
                    Link::make(__('oidc-ui::auth.forgot-password.login-link'))
                        ->href(route('identity.login', absolute: false)),
                ]),
        ];
    }
}
