<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\SigningKeys\Keyring;
use Lock\Server\Shared\Tokens\SignedJwtParser;
use Lock\Server\Tokens\Models\AccessToken;
use Throwable;

/**
 * Every access-token acceptance path must validate the realm signature and
 * issuer through parse() (RFC 9068 §4).
 */
class TokenInspector implements SignedJwtParser
{
    public function __construct(
        private readonly Keyring $keyring,
        private readonly IssuerResolver $issuer,
    ) {}

    public function accessToken(string $jwt): ?AccessToken
    {
        $parsed = $this->parse($jwt);

        return $parsed instanceof Plain ? $this->tokenForParsed($parsed) : null;
    }

    public function parse(string $jwt): ?Plain
    {
        try {
            $parsed = new Parser(new JoseEncoder)->parse($jwt);
        } catch (Throwable) {
            return null;
        }

        if (! $parsed instanceof Plain) {
            return null;
        }

        $validator = new Validator;

        if (! $validator->validate($parsed, new IssuedBy($this->issuer->url()))) {
            return null;
        }

        return $this->keyring->verifies($parsed) ? $parsed : null;
    }

    public function tokenForParsed(Plain $parsed): ?AccessToken
    {
        $jti = $parsed->claims()->get('jti');

        return is_string($jti) ? AccessToken::query()->inRealm()->find($jti) : null;
    }
}
