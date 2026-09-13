<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Lattice\Form\Components\Form;
use Lattice\Form\Components\HiddenInput;
use Lattice\Form\Components\PasswordInput;
use Lattice\Form\Components\TextInput;
use Lattice\Ui\Components\Button;
use Lattice\Ui\Components\Component;
use Lattice\Ui\Components\Grid;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\PageSchema;
use Lock\Server\Authentication\Ui\Views\PasswordResetPrompt;
use Lock\Server\Authentication\Ui\Views\PasswordResetView;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

class ResetPasswordPage extends AuthPage implements PasswordResetView
{
    final public function __construct(
        protected readonly ?PasswordResetPrompt $prompt = null,
    ) {}

    public function respond(PasswordResetPrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.reset-password.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        $prompt = $this->prompt ?? throw new LogicException(static::class.' rendered without its prompt; respond() must supply one before render() runs.');
        $token = $prompt->token;
        $email = $prompt->email ?? '';

        return $schema->schema([
            $this->heading('reset-password-heading', __('oidc-ui::auth.reset-password.heading'), __('oidc-ui::auth.reset-password.subtitle')),
            Form::make('reset-password-form')
                ->action(route('identity.password.update', absolute: false))
                ->method(HttpMethod::Post)
                ->schema($this->formSchema($token, $email))
                ->resetOnSuccess(['password', 'password_confirmation'])
                ->withoutSubmitButton(),
        ]);
    }

    /**
     * @return array<int, Component>
     */
    private function formSchema(string $token, string $email): array
    {
        return [
            Grid::make('reset-password-fields')
                ->columns(1)
                ->schema([
                    HiddenInput::make('token')->value($token),
                    TextInput::make('email', __('oidc-ui::common.field.email-address'))
                        ->email()
                        ->autoComplete('email')
                        ->value($email)
                        ->readOnly()
                        ->required(),
                    PasswordInput::make('password', __('oidc-ui::common.field.password'))
                        ->autoComplete('new-password')
                        ->autoFocus()
                        ->placeholder(__('oidc-ui::common.placeholder.password'))
                        ->required()
                        ->needsConfirmation(),
                ]),
            Button::make(__('oidc-ui::auth.reset-password.submit'))->submit(),
        ];
    }
}
