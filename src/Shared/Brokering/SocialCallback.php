<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Brokering;

final readonly class SocialCallback
{
    public function __construct(
        public string $intent,
        public SocialUser $user,
    ) {}
}
