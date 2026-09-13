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
use Lock\Server\Authentication\Ui\Views\PasswordUpdatePrompt;
use Lock\Server\Authentication\Ui\Views\PasswordUpdateView;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use Symfony\Component\HttpFoundation\Response;

class UpdatePasswordPage extends AuthPage implements PasswordUpdateView
{
    final public function __construct(
        protected readonly ?PasswordUpdatePrompt $prompt = null,
    ) {}

    public function respond(PasswordUpdatePrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.update-password.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        return $schema->schema([
            $this->heading(
                'update-password-heading',
                __('oidc-ui::auth.update-password.heading'),
                $this->prompt?->expired === true
                    ? __('oidc-ui::auth.update-password.subtitle-expired')
                    : __('oidc-ui::auth.update-password.subtitle'),
            ),
            Form::make('update-password-form')
                ->action(route('identity.password.change.store', absolute: false))
                ->method(HttpMethod::Post)
                ->schema($this->formSchema())
                ->resetOnSuccess(['current_password', 'password', 'password_confirmation'])
                ->withoutSubmitButton()
                ->status($this->prompt?->status),
        ]);
    }

    /**
     * @return array<int, Component>
     */
    private function formSchema(): array
    {
        $fields = [];

        // Mid-login the server does not accept a current password: the user
        // proved a credential moments ago, and a passkey or social login has
        // none to recite.
        if ($this->prompt?->requiresCurrentPassword !== false) {
            $fields[] = PasswordInput::make('current_password', __('oidc-ui::auth.update-password.current'))
                ->autoComplete('current-password')
                ->autoFocus()
                ->required();
        }

        $new = PasswordInput::make('password', __('oidc-ui::auth.update-password.new'))
            ->autoComplete('new-password')
            ->placeholder(__('oidc-ui::common.placeholder.password'))
            ->required()
            ->needsConfirmation();

        return [
            Grid::make('update-password-fields')
                ->columns(1)
                ->schema([...$fields, $fields === [] ? $new->autoFocus() : $new]),
            Button::make(__('oidc-ui::auth.update-password.submit'))->submit(),
        ];
    }
}
