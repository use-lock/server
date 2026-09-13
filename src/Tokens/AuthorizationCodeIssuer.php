<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use DateInterval;
use DateTimeImmutable;
use Illuminate\Support\Facades\DB;
use Lock\Server\Shared\Authentication\AcrResolver;
use Lock\Server\Shared\Authentication\LoginSnapshot;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\AuthorizeRequest;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Sessions\SessionSnapshot;
use Lock\Server\Shared\Tokens\AuthorizationCodes;
use Lock\Server\Tokens\Models\AuthenticationContext;
use Lock\Server\Tokens\Models\AuthorizationCode;
use LogicException;

final readonly class AuthorizationCodeIssuer implements AuthorizationCodes
{
    public function __construct(private AcrResolver $acr, private RealmResolver $realms) {}

    public function issue(AuthorizeRequest $request, Client $client, SessionSnapshot $session, LoginSnapshot $login): string
    {
        $userId = $request->userId ?? throw new LogicException('An authorization request cannot be approved without a user.');
        $authTime = $session->authTime ?? time();

        return DB::transaction(function () use ($request, $client, $session, $login, $userId, $authTime): string {
            $context = AuthenticationContext::query()->forceCreate([
                'realm' => $client->realm,
                'user_id' => $userId,
                'session_id' => $session->sid,
                'amr' => $login->amr,
                'acr' => $this->acr->fromAmr($login->amr),
                'auth_time' => $authTime,
                'id_token_claims' => $login->idTokenClaims,
                'access_token_claims' => $login->accessTokenClaims,
                'expires_at' => $session->expiresAt ?? now()->add($this->realms->current()->sessions()->absolute()),
                'created_at' => now(),
            ]);

            $code = bin2hex(random_bytes(40));

            AuthorizationCode::query()->forceCreate([
                'realm' => $client->realm,
                'code' => $code,
                'user_id' => $userId,
                'client_id' => $client->key,
                'scopes' => $request->scopes,
                'audience' => $request->resources,
                'redirect_uri' => $request->redirectUriRequested ? $request->redirectUri : null,
                'code_challenge' => $request->codeChallenge,
                'code_challenge_method' => $request->codeChallengeMethod,
                'nonce' => $request->nonce,
                'auth_time' => $authTime,
                'context_id' => $context->id,
                'expires_at' => (new DateTimeImmutable)->add(new DateInterval('PT10M')),
            ]);

            return $code;
        });
    }
}
