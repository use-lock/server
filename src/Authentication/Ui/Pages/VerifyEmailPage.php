<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Pages;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Lattice\Form\Components\Form;
use Lattice\Ui\Components\Button;
use Lattice\Ui\Components\Link;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\PageSchema;
use Lock\Server\Authentication\Ui\Views\EmailVerificationPrompt;
use Lock\Server\Authentication\Ui\Views\EmailVerificationView;
use Lock\Server\Shared\Ui\Pages\AuthPage;
use Symfony\Component\HttpFoundation\Response;

class VerifyEmailPage extends AuthPage implements EmailVerificationView
{
    final public function __construct(
        protected readonly ?EmailVerificationPrompt $prompt = null,
    ) {}

    public function respond(EmailVerificationPrompt $prompt, Request $request): Responsable|Response
    {
        return new static($prompt)->toResponse($request);
    }

    public function title(): string
    {
        return __('oidc-ui::auth.verify-email.title');
    }

    public function render(PageSchema $schema): PageSchema
    {
        $formSchema = [
            Button::make(__('oidc-ui::auth.verify-email.resend'))->submit(),
        ];

        $logoutRoute = config('oidc-ui.logout_route', 'logout');

        if (Route::has($logoutRoute)) {
            $formSchema[] = Link::make(__('oidc-ui::common.action.log-out'))
                ->href(route($logoutRoute, absolute: false))
                ->method(HttpMethod::Post);
        }

        return $schema->schema([
            $this->heading('verify-email-heading', __('oidc-ui::auth.verify-email.heading'), __('oidc-ui::auth.verify-email.subtitle')),
            Form::make('verify-email-form')
                ->action(route('identity.verification.send', absolute: false))
                ->method(HttpMethod::Post)
                ->schema($formSchema)
                ->withoutSubmitButton()
                ->status($this->statusMessage()),
        ]);
    }

    private function statusMessage(): ?string
    {
        if ($this->prompt?->status !== 'verification-link-sent') {
            return null;
        }

        return __('oidc-ui::auth.verify-email.sent');
    }
}
