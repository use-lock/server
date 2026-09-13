<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\SessionParticipantFactory;

/**
 * @property string $id
 * @property string $session_id
 * @property string $client_id The client's primary key.
 * @property ?string $logout_status
 * @property ?CarbonInterface $logout_attempted_at
 * @property CarbonInterface $created_at
 */
class SessionParticipant extends Model
{
    /** @use HasFactory<SessionParticipantFactory> */
    use HasFactory;

    use HasUuids;

    public $timestamps = false;

    protected $table = 'oidc_session_participants';

    protected $guarded = [];

    protected static function newFactory(): SessionParticipantFactory
    {
        return SessionParticipantFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime', 'logout_attempted_at' => 'datetime'];
    }
}
