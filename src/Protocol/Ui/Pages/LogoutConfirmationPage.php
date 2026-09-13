<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Lattice\Form\Components\Form;
use Lattice\Form\Components\HiddenInput;
use Lattice\Ui\Components\Button;
use Lattice\Ui\Components\Link;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\PageSchema;
use Lock\Server\Protocol\Ui\Views\LogoutConfirmationView;
use Lock\Server\Protocol\Ui\Views\LogoutPrompt;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

class LogoutConfirmationPage extends AuthPage implements LogoutConfirmationView
{
    final public function __construct(
        protected readonly ?LogoutPrompt $prompt = null,
    ) {}

    public function respond(LogoutPrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::oauth.logout.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        $prompt = $this->prompt ?? throw new LogicException(static::class.' rendered without its prompt; respond() must supply one before render() runs.');
        $user = $prompt->user;
        $userEmail = $user instanceof Model ? (string) $user->getAttribute('email') : '';
        $clientName = $prompt->client?->name;

        return $schema->schema([
            $this->heading(
                'logout-heading',
                __('oidc-ui::oauth.logout.heading'),
                is_string($clientName) && $clientName !== ''
                    ? __('oidc-ui::oauth.logout.requested-by', ['client' => $clientName])
                    : __('oidc-ui::oauth.logout.requested'),
            ),
            Form::make('logout-confirmation')
                ->action(route('oidc.logout', absolute: false))
                ->method(HttpMethod::Post)
                ->withoutSubmitButton()
                ->schema([
                    HiddenInput::make('logout_confirmation')->value($prompt->confirmationToken),
                    Button::make(__('oidc-ui::oauth.logout.confirm'))->submit(),
                    Link::make(__('oidc-ui::oauth.logout.cancel'))
                        ->href(app(RealmResolver::class)->current()->login()->home),
                ])
                ->status(__('oidc-ui::oauth.logout.signed-in-as', ['email' => $userEmail])),
        ]);
    }
}
