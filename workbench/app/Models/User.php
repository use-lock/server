<?php
declare(strict_types=1);

namespace Workbench\App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Lock\Server\Credentials\Concerns\HasAuthenticationFactors;
use Lock\Server\Shared\Authentication\RealmUser;
use Lock\Server\Tokens\Concerns\HasAccessTokens;
use Workbench\Database\Factories\UserFactory;

class User extends Authenticatable implements MustVerifyEmail, PasskeyUser, RealmUser
{
    /** @use HasFactory<UserFactory> */
    use HasAccessTokens, HasAuthenticationFactors, HasFactory, HasUuids, Notifiable;

    protected $table = 'users';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['email_verified_at' => 'datetime'];
    }
}
