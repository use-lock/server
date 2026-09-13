<?php

declare(strict_types=1);

namespace Lock\Server\Support\Testing;

use Illuminate\Support\Str;

/**
 * An RFC 7636 code verifier and its S256 challenge, for driving the
 * authorization-code flow in tests.
 */
final readonly class PkcePair
{
    public function __construct(
        public string $verifier,
        public string $challenge,
    ) {}

    public static function generate(): self
    {
        $verifier = Str::random(64);

        return new self(
            $verifier,
            sodium_bin2base64(hash('sha256', $verifier, true), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
        );
    }
}
