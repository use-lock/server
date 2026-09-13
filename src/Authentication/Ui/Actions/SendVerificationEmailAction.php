<?php
declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Actions;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Lattice\Actions\ActionDefinition;
use Lattice\Actions\ActionResult;
use Lattice\Actions\Components\Action as ActionComponent;
use Lattice\Core\Attributes\AsAction;
use Lattice\Ui\Enums\Emphasis;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\Enums\Variant;
use Lock\Server\Shared\Ui\Support\ScreenSubject;

#[AsAction('oidc.send-verification-email')]
class SendVerificationEmailAction extends ActionDefinition
{
    public function definition(ActionComponent $action): ActionComponent
    {
        return $action
            ->label(__('oidc-ui::security.resend-verification'))
            ->method(HttpMethod::Post)
            ->emphasis(Emphasis::Link);
    }

    public function handle(Request $request): ActionResult
    {
        $user = ScreenSubject::current();

        abort_unless($user instanceof MustVerifyEmail, 403);

        if ($user->hasVerifiedEmail()) {
            return ActionResult::success()->toast(__('oidc-ui::security.already-verified'), Variant::Info);
        }

        $user->sendEmailVerificationNotification();

        return ActionResult::success()->toast(__('oidc-ui::security.verification-sent'), Variant::Success);
    }
}
