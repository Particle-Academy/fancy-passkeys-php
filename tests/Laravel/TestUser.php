<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Laravel;

use FancyPasskeys\Laravel\Concerns\HasPasskeys;
use Illuminate\Foundation\Auth\User as Authenticatable;

class TestUser extends Authenticatable
{
    use HasPasskeys;

    protected $table = 'users';

    protected $guarded = [];

    protected $hidden = ['password', 'remember_token', 'passkey_user_handle'];
}
