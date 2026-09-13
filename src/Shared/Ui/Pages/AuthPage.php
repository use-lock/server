<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Ui\Pages;

use Lattice\Core\Enums\PageLayout;
use Lattice\Http\Page;
use Lattice\Ui\Components\Heading;
use Lattice\Ui\Components\Stack;
use Lattice\Ui\Components\Text;
use Lattice\Ui\Enums\Gap;
use Lattice\Ui\Enums\TextAlign;

abstract class AuthPage extends Page
{
    public function layout(): PageLayout|string|null
    {
        return PageLayout::Auth;
    }

    protected function heading(string $name, string $heading, ?string $subtitle = null): Stack
    {
        return Stack::make($name)
            ->gap(Gap::Small)
            ->schema([
                Heading::make($heading, 2),
                ...($subtitle === null ? [] : [Text::make($subtitle)->align(TextAlign::Center)]),
            ]);
    }
}
