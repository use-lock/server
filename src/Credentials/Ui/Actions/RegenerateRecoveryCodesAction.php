<?php
declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Actions;

use Illuminate\Http\Request;
use Lattice\Actions\ActionDefinition;
use Lattice\Actions\ActionResult;
use Lattice\Actions\Components\Action as ActionComponent;
use Lattice\Core\Attributes\AsAction;
use Lattice\Ui\Enums\HttpMethod;
use Lattice\Ui\Enums\Variant;
use Lock\Server\Credentials\RecoveryCodeProvider;
use Lock\Server\Credentials\Ui\Concerns\ManagesTwoFactor;
use Lock\Server\Credentials\Ui\Support\RecoveryCodesModal;

#[AsAction('oidc.two-factor.regenerate-recovery-codes')]
class RegenerateRecoveryCodesAction extends ActionDefinition
{
    use ManagesTwoFactor;

    public function __construct(private readonly RecoveryCodeProvider $recoveryCodes) {}

    public function definition(ActionComponent $action): ActionComponent
    {
        return $action
            ->label(__('oidc-ui::security.recovery-codes.regenerate'))
            ->method(HttpMethod::Post)
            ->variant(Variant::Secondary)
            ->confirm(
                title: __('oidc-ui::security.recovery-codes.regenerate-confirm-title'),
                description: __('oidc-ui::security.recovery-codes.regenerate-confirm-description'),
                confirmLabel: __('oidc-ui::security.recovery-codes.regenerate'),
            );
    }

    public function handle(Request $request): ActionResult
    {
        $user = $this->twoFactorUser();

        $this->recoveryCodes->generate($user);

        return ActionResult::success()
            ->toast(__('oidc-ui::security.recovery-codes.regenerated'), Variant::Success)
            ->openModal(RecoveryCodesModal::make(
                (string) $this->context('modal', RecoveryCodesModal::DEFAULT_ID),
            ));
    }
}
