<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Lattice\Form\Components\Form;
use Lattice\Form\Components\PasswordInput;
use Lattice\Ui\Components\Button;
use Lattice\Ui\Components\Component;
use Lattice\Ui\Components\Grid;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\PageSchema;
use Lock\Server\Authentication\Ui\Views\PasswordConfirmationView;
use Lock\Server\Credentials\Ui\Components\PasskeyVerify;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use Symfony\Component\HttpFoundation\Response;

class ConfirmPasswordPage extends AuthPage implements PasswordConfirmationView
{
    public function respond(Request $request): Responsable|Response
    {
        return $this->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.confirm-password.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        return $schema->schema([
            $this->heading('confirm-password-heading', __('oidc-ui::auth.confirm-password.heading'), __('oidc-ui::auth.confirm-password.subtitle')),
            ...$this->passkeySchema(),
            Form::make('confirm-password-form')
                ->action(route('identity.password.confirm.store', absolute: false))
                ->method(HttpMethod::Post)
                ->schema($this->formSchema())
                ->resetOnSuccess(['password'])
                ->withoutSubmitButton(),
        ]);
    }

    /**
     * @return array<int, Component>
     */
    private function passkeySchema(): array
    {
        $passkey = PasskeyVerify::makeIfAvailable(
            'identity.passkey.confirm-options',
            'identity.passkey.confirm',
            label: __('oidc-ui::auth.confirm-password.passkey-label'),
            loadingLabel: __('oidc-ui::auth.confirm-password.passkey-loading'),
            separator: __('oidc-ui::auth.confirm-password.passkey-separator'),
        );

        return $passkey instanceof PasskeyVerify ? [$passkey] : [];
    }

    /**
     * @return array<int, Component>
     */
    private function formSchema(): array
    {
        return [
            Grid::make('confirm-password-fields')
                ->columns(1)
                ->schema([
                    PasswordInput::make('password', __('oidc-ui::common.field.password'))
                        ->autoComplete('current-password')
                        ->autoFocus()
                        ->placeholder(__('oidc-ui::common.placeholder.password'))
                        ->required(),
                ]),
            Button::make(__('oidc-ui::auth.confirm-password.submit'))->submit(),
        ];
    }
}
