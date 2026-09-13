<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use DateTimeImmutable;
use Lock\Server\Shared\Authentication\AcrResolver;
use Lock\Server\Shared\Protocol\ProtocolClaims;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\ClaimsAudience;
use Lock\Server\Shared\Scopes\ClaimsRequest;
use Lock\Server\Shared\Scopes\ClaimsResolver;
use Lock\Server\Shared\SigningKeys\Keyring;
use Lock\Server\Tokens\Concerns\ResolvesTokenUser;
use RuntimeException;

class IdTokenBuilder
{
    use ResolvesTokenUser;

    public function __construct(
        private readonly ClaimsResolver $claims,
        private readonly IssuerResolver $issuer,
        private readonly Keyring $keyring,
        private readonly RealmResolver $realms,
        private readonly AcrResolver $acr,
    ) {}

    public function build(IdTokenRequest $request): string
    {
        $clientId = $request->clientId;
        $nonce = $request->nonce;
        $authTime = $request->authTime;
        $sid = $request->sid;
        $amr = $request->amr;
        $now = new DateTimeImmutable;

        $builder = $this->keyring->builder()
            ->issuedBy($this->issuer->url())
            ->permittedFor($clientId)
            ->relatedTo($request->userId)
            ->issuedAt($now)
            ->expiresAt($now->modify('+'.$this->realms->current()->tokens()->idTokenLifetime.' seconds'))
            ->withClaim('azp', $clientId)
            ->withClaim('at_hash', $this->atHash($request->accessToken));

        if ($nonce !== null && $nonce !== '') {
            $builder = $builder->withClaim('nonce', $nonce);
        }

        if ($authTime !== null) {
            $builder = $builder->withClaim('auth_time', $authTime);
        }

        if ($sid !== null && $sid !== '') {
            $builder = $builder->withClaim('sid', $sid);
        }

        if ($amr !== []) {
            $builder = $builder->withClaim('amr', $amr);

            $acr = $this->acr->fromAmr($amr);
            if ($acr !== null) {
                $builder = $builder->withClaim('acr', $acr);
            }
        }

        foreach ($request->idTokenClaims as $name => $value) {
            if (! ProtocolClaims::isReserved($name)) {
                $builder = $builder->withClaim($name, $value);
            }
        }

        $user = $this->resolveUser($request->userId)
            ?? throw new RuntimeException('Unable to resolve the user for id_token issuance: '.$request->userId);

        $resolved = $this->claims->resolve(new ClaimsRequest(
            user: $user,
            audience: ClaimsAudience::IdToken,
            clientId: $clientId,
            scopes: $request->scopes,
        ));

        // OIDC Core §2: the protocol claims are the provider's; a resolver
        // cannot rewrite sub, aud, nonce and the rest of the reserved set.
        foreach ($resolved as $name => $value) {
            if (! ProtocolClaims::isReserved((string) $name)) {
                $builder = $builder->withClaim((string) $name, $value);
            }
        }

        return $this->keyring->sign($builder);
    }

    private function atHash(string $accessTokenJwt): string
    {
        $hash = substr(hash('sha256', $accessTokenJwt, true), 0, 16);

        return sodium_bin2base64($hash, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
