<?php
declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Fragments;

use Lattice\Core\Attributes\AsFragment;
use Lattice\Fragments\FragmentDefinition;
use Lattice\Ui\Components\Stack;
use Lattice\Ui\Components\Text;
use Lattice\Ui\Enums\Align;
use Lattice\Ui\Enums\Gap;
use Lattice\Ui\PageSchema;
use Lock\Server\Credentials\RecoveryCodeProvider;
use Lock\Server\Shared\Ui\Support\ScreenSubject;

#[AsFragment('oidc.recovery-codes')]
class RecoveryCodesFragment extends FragmentDefinition
{
    public function __construct(private readonly RecoveryCodeProvider $recoveryCodes) {}

    public function schema(PageSchema $schema): PageSchema
    {
        $user = ScreenSubject::currentOrFail();

        $codes = $this->recoveryCodes->codes($user);

        if ($codes === []) {
            return $schema->schema([
                Text::make(__('oidc-ui::security.recovery-codes.none')),
            ]);
        }

        return $schema->schema([
            Stack::make('recovery-codes')
                ->align(Align::Center)
                ->gap(Gap::Small)
                ->schema([
                    Text::make(__('oidc-ui::security.recovery-codes.description')),
                    ...array_map(
                        static fn (string $code): Text => Text::make($code)->copyable(),
                        $codes,
                    ),
                ]),
        ]);
    }
}
