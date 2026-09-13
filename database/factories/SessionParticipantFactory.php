<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;

/**
 * @extends Factory<SessionParticipant>
 */
class SessionParticipantFactory extends Factory
{
    protected $model = SessionParticipant::class;

    public function definition(): array
    {
        return [
            'session_id' => fn (): string => OidcSession::factory()->create()->id,
            'client_id' => fn (): string => (string) Client::factory()->create()->getKey(),
            'created_at' => now(),
        ];
    }

    public function inSession(OidcSession $session): static
    {
        return $this->state(['session_id' => $session->id]);
    }

    public function forClient(Client $client): static
    {
        return $this->state(['client_id' => $client->getKey()]);
    }
}
