<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
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
use Lattice\Ui\PageSchema;
use Lock\Server\Authentication\Ui\Views\RegisterView;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use Symfony\Component\HttpFoundation\Response;

class RegisterPage extends AuthPage implements RegisterView
{
    public function respond(Request $request): Responsable|Response
    {
        return $this->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.register.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        return $schema->schema([
            $this->heading('register-heading', __('oidc-ui::auth.register.heading'), __('oidc-ui::auth.register.subtitle')),
            Form::make('register-form')
                ->action(route('identity.register.store', absolute: false))
                ->method(HttpMethod::Post)
                ->schema($this->formSchema())
                ->resetOnSuccess(['password', 'password_confirmation'])
                ->withoutSubmitButton(),
        ]);
    }

    /**
     * @return array<int, Component>
     */
    private function formSchema(): array
    {
        return [
            Grid::make('register-fields')
                ->columns(1)
                ->schema([
                    TextInput::make('name', __('oidc-ui::common.field.name'))
                        ->autoComplete('name')
                        ->autoFocus()
                        ->placeholder(__('oidc-ui::common.placeholder.full-name'))
                        ->required(),
                    TextInput::make('email', __('oidc-ui::common.field.email-address'))
                        ->email()
                        ->autoComplete('email')
                        ->placeholder(__('oidc-ui::common.placeholder.email'))
                        ->required(),
                    PasswordInput::make('password', __('oidc-ui::common.field.password'))
                        ->autoComplete('new-password')
                        ->placeholder(__('oidc-ui::common.placeholder.password'))
                        ->required()
                        ->needsConfirmation(),
                ]),
            Button::make(__('oidc-ui::auth.register.submit'))->submit(),
            Stack::make('register-login-prompt')
                ->align(Align::Center)
                ->direction(Orientation::Horizontal)
                ->gap(Gap::ExtraSmall)
                ->schema([
                    Text::make(__('oidc-ui::auth.register.have-account')),
                    Link::make(__('oidc-ui::common.action.log-in'))
                        ->href(route('identity.login', absolute: false)),
                ]),
        ];
    }
}
