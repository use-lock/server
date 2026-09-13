<?php

declare(strict_types=1);

namespace Lock\Server\Consents;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Lock\Server\Consents\Models\Consent;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Consents\ConsentApproved;
use Lock\Server\Shared\Consents\ConsentStore;
use LogicException;

/**
 * Consents persist independently of the tokens they led to: a token expiring
 * or being revoked leaves the consent in place, and only `revoke()` withdraws
 * it. Every lookup is scoped to the current realm.
 */
class ConsentRepository implements ConsentStore
{
    /**
     * Every resource the user has a consent for with this client, withdrawn
     * ones included — what an account screen lists.
     *
     * @return Collection<int, Consent>
     */
    public function forClient(string $userId, string $clientKey): Collection
    {
        return Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $clientKey)
            ->orderBy('resource')
            ->get();
    }

    public function covers(string $userId, string $clientKey, array $scopes, array $resources): bool
    {
        if ($resources === []) {
            return false;
        }

        return array_all($resources, fn (string $resource): bool => $this->findByKey($userId, $clientKey, $resource)?->covers($scopes) ?? false);
    }

    public function grant(string $userId, Client $client, array $scopes, array $resources): void
    {
        if ($resources === []) {
            return;
        }

        if ($client->realm !== Consent::currentRealm()) {
            throw new LogicException('A consent client must belong to the current realm.');
        }

        DB::transaction(function () use ($userId, $client, $scopes, $resources): void {
            foreach ($resources as $resource) {
                $consent = $this->findByKey($userId, $client->key, $resource) ?? new Consent([
                    'realm' => $client->realm,
                    'user_id' => $userId,
                    'client_id' => $client->key,
                    'resource' => $resource,
                    'scopes' => [],
                ]);

                $consent->forceFill([
                    'scopes' => array_values(array_unique([...$consent->scopes, ...$scopes])),
                    'granted_at' => Date::now(),
                    'revoked_at' => null,
                ])->save();
            }

            event(new ConsentApproved($scopes, $resources, $client->realm, $userId, $client->clientId));
        });
    }

    public function revoke(string $userId, string $clientKey, ?string $resource = null): void
    {
        Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $clientKey)
            ->when($resource !== null, fn ($query) => $query->where('resource', $resource))
            ->whereNull('revoked_at')
            ->update(['revoked_at' => Date::now()]);
    }

    public function findByKey(string $userId, string $clientKey, string $resource): ?Consent
    {
        return Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $clientKey)
            ->where('resource', $resource)
            ->first();
    }
}
