<?php
declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Support;

use Lattice\Fragments\Components\Fragment;
use Lattice\Ui\Components\Modal;
use Lock\Server\Credentials\Ui\Fragments\RecoveryCodesFragment;

final class RecoveryCodesModal
{
    public const string DEFAULT_ID = 'oidc.recovery-codes';

    /**
     * The open-modal effect must carry the dialog; its stable id lets hosts close or restyle it.
     */
    public static function make(string $id = self::DEFAULT_ID): Modal
    {
        return Modal::make($id)
            ->title(__('oidc-ui::security.recovery-codes.heading'))
            ->schema([Fragment::lazy(RecoveryCodesFragment::class)]);
    }
}
