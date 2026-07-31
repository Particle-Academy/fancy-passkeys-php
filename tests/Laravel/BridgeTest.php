<?php

declare(strict_types=1);

use FancyPasskeys\Laravel\EloquentCredentialStore;
use FancyPasskeys\Laravel\Models\PasskeyCredential;
use FancyPasskeys\Laravel\PasskeyManager;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\StoredCredential;
use FancyPasskeys\Tests\Laravel\FakePasskeyManager;
use FancyPasskeys\Tests\Laravel\TestUser;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

function makeTestUser(string $email = 'ada@example.com'): TestUser
{
    return TestUser::create([
        'name' => 'Ada Lovelace',
        'email' => $email,
        'password' => bcrypt('irrelevant'),
    ]);
}

function seedCredential(TestUser $user, string $credentialId = 'Y3JlZC1vbmU'): PasskeyCredential
{
    return PasskeyCredential::create([
        'user_id' => $user->getKey(),
        'credential_id' => $credentialId,
        'public_key' => 'bm90LWEta2V5',
        'user_handle' => $user->passkeyUserHandle(),
        'sign_count' => 0,
        'transports' => ['internal'],
        'aaguid' => '00000000-0000-0000-0000-000000000000',
        'attestation_format' => 'none',
        'name' => 'MacBook Touch ID',
    ]);
}

it('runs the package migrations', function () {
    expect(Schema::hasTable('passkey_credentials'))->toBeTrue();
    expect(Schema::hasColumn('users', 'passkey_user_handle'))->toBeTrue();

    foreach ([
        'user_id', 'credential_id', 'public_key', 'user_handle', 'sign_count', 'transports',
        'aaguid', 'backed_up', 'backup_eligible', 'uv_initialized', 'attestation_format',
        'name', 'last_used_at', 'cloned_at',
    ] as $column) {
        expect(Schema::hasColumn('passkey_credentials', $column))->toBeTrue();
    }
});

it('rejects a duplicate credential ID at the database level', function () {
    $user = makeTestUser();

    $row = [
        'user_id' => $user->getKey(),
        'credential_id' => 'Y3JlZC1vbmU',
        'public_key' => 'bm90LWEta2V5',
        'user_handle' => 'aGFuZGxl',
        'sign_count' => 0,
    ];

    DB::table('passkey_credentials')->insert($row);

    // Deliberately going around the model and the store: the application-level
    // check races with a concurrent request, and this asserts the index is
    // there to catch what loses that race.
    expect(fn () => DB::table('passkey_credentials')->insert($row))
        ->toThrow(QueryException::class);
});

it('turns a lost uniqueness race into credential_already_registered', function () {
    $user = makeTestUser();
    seedCredential($user);

    $store = new EloquentCredentialStore();

    $duplicate = new StoredCredential(
        id: 'Y3JlZC1vbmU',
        publicKey: 'bm90LWEta2V5',
        userHandle: $user->passkeyUserHandle(),
        signCount: 0,
        createdAt: '2026-01-01T00:00:00.000Z',
    );

    expect(fn () => $store->save($duplicate))->toThrow(PasskeyException::class);
});

it('mints a user handle once and keeps it stable', function () {
    $user = makeTestUser();

    expect($user->passkey_user_handle)->toBeNull();

    $handle = $user->passkeyUserHandle();

    expect($handle)->not->toBe('');
    // 32 random bytes, base64url, unpadded.
    expect(strlen($handle))->toBe(43);

    // Never the primary key: a handle is stored by every authenticator the user
    // ever enrols, so a sequential internal ID here leaks to every device.
    expect($handle)->not->toBe((string) $user->getKey());

    expect($user->passkeyUserHandle())->toBe($handle);
    expect($user->fresh()->passkeyUserHandle())->toBe($handle);
});

it('registers the four routes behind the configured middleware', function () {
    $routes = collect(Route::getRoutes()->getRoutes())
        ->keyBy(fn ($route) => $route->getName());

    expect($routes)->toHaveKeys([
        'passkeys.register.options',
        'passkeys.register',
        'passkeys.login.options',
        'passkeys.login',
    ]);

    foreach (['passkeys.register.options', 'passkeys.register'] as $name) {
        expect($routes[$name]->methods())->toContain('POST');
        expect($routes[$name]->gatherMiddleware())->toContain('web')->toContain('auth');
    }

    foreach (['passkeys.login.options', 'passkeys.login'] as $name) {
        expect($routes[$name]->methods())->toContain('POST');
        expect($routes[$name]->gatherMiddleware())->toContain('web');
        // An unthrottled passkey endpoint beside a throttled password endpoint
        // is a bypass, not a feature.
        expect(collect($routes[$name]->gatherMiddleware())->contains(fn ($m) => str_starts_with((string) $m, 'throttle:')))
            ->toBeTrue();
        // Enrollment is authenticated; login is not.
        expect($routes[$name]->gatherMiddleware())->not->toContain('auth');
    }

    expect($routes['passkeys.register.options']->uri())->toBe('passkeys/register/options');
    expect($routes['passkeys.login']->uri())->toBe('passkeys/login');
});

it('keeps enrollment behind the auth middleware', function () {
    $this->postJson('/passkeys/register/options')->assertUnauthorized();
});

it('returns options with an empty allowCredentials for an unknown email', function () {
    $response = $this->postJson('/passkeys/login/options', ['email' => 'nobody@example.com']);

    // A 404 here is a free user-enumeration endpoint.
    $response->assertOk();
    $response->assertJsonPath('publicKey.allowCredentials', []);
    $response->assertJsonStructure(['state', 'publicKey' => ['challenge', 'rpId', 'timeout', 'userVerification']]);
    expect($response->headers->get('Cache-Control'))->toContain('no-store');
});

it('returns the same shape for a known email as an unknown one', function () {
    $user = makeTestUser();
    $user->passkeyUserHandle();

    $known = $this->postJson('/passkeys/login/options', ['email' => $user->email]);
    $unknown = $this->postJson('/passkeys/login/options', ['email' => 'nobody@example.com']);

    $known->assertOk();
    $unknown->assertOk();

    // A user with no passkeys yet is indistinguishable from a user who does not
    // exist. (The timing difference is not closed — the README says so.)
    expect(array_keys($known->json('publicKey')))->toBe(array_keys($unknown->json('publicKey')));
    expect($known->json('publicKey.allowCredentials'))->toBe([]);
});

it('offers the user\'s credentials when the email is known', function () {
    $user = makeTestUser();
    seedCredential($user);

    $response = $this->postJson('/passkeys/login/options', ['email' => $user->email]);

    $response->assertOk();
    $response->assertJsonPath('publicKey.allowCredentials.0.id', 'Y3JlZC1vbmU');
});

it('starts an enrollment ceremony for the signed-in user', function () {
    $user = makeTestUser();

    $response = $this->actingAs($user)->postJson('/passkeys/register/options');

    $response->assertOk();
    $response->assertJsonPath('publicKey.rp.id', 'localhost');
    $response->assertJsonPath('publicKey.user.name', 'ada@example.com');
    $response->assertJsonPath('publicKey.user.id', $user->fresh()->passkey_user_handle);
    $response->assertJsonPath('publicKey.attestation', 'none');
});

it('logs the user in, fires the same Login event Fortify does, and regenerates the session', function () {
    $user = makeTestUser();
    $credential = seedCredential($user);

    // Swap in a manager whose verification succeeds — see FakePasskeyManager.
    $this->app->bind(PasskeyManager::class, fn ($app) => new FakePasskeyManager(
        $app->make(FancyPasskeys\PasskeyServer::class),
        $credential->toStoredCredential(),
    ));

    Event::fake([Login::class, FancyPasskeys\Laravel\Events\PasskeyAuthenticated::class]);

    $this->startSession();
    $sessionIdBefore = session()->getId();

    $response = $this->postJson('/passkeys/login', [
        'state' => 'anything',
        'response' => ['id' => 'Y3JlZC1vbmU'],
    ]);

    $response->assertOk();
    $response->assertJsonPath('user.email', 'ada@example.com');
    $response->assertJsonPath('credential.id', 'Y3JlZC1vbmU');

    $this->assertAuthenticatedAs($user);

    // Fortify's own login side effects, produced from the same place — anything
    // listening (fun-lab, heuristics, audit) cannot tell the two apart.
    Event::assertDispatched(Login::class);
    Event::assertDispatched(FancyPasskeys\Laravel\Events\PasskeyAuthenticated::class);

    // Session fixation: a new session ID after privilege escalation.
    expect(session()->getId())->not->toBe($sessionIdBefore);
});

it('returns the shared error body with a 4xx for a failed ceremony', function () {
    $response = $this->postJson('/passkeys/login', [
        'state' => 'never-issued',
        'response' => ['id' => 'Y3JlZC1vbmU'],
    ]);

    $response->assertStatus(400);
    $response->assertExactJson([
        'error' => [
            'code' => 'challenge_not_found',
            'message' => FancyPasskeys\PasskeyErrorCode::ChallengeNotFound->clientMessage(),
        ],
    ]);
    expect($response->headers->get('Cache-Control'))->toContain('no-store');
});

it('reads and writes credentials through the Eloquent store', function () {
    $user = makeTestUser();
    seedCredential($user);

    $store = new EloquentCredentialStore();
    $handle = $user->passkeyUserHandle();

    expect($store->findById('Y3JlZC1vbmU'))->not->toBeNull();
    expect($store->findByUserHandle($handle))->toHaveCount(1);

    $store->updateAfterAuthentication('Y3JlZC1vbmU', 7, '2026-02-02T03:04:05.000Z');
    expect($store->findById('Y3JlZC1vbmU')->signCount)->toBe(7);

    $store->flagCloned('Y3JlZC1vbmU', '2026-02-02T03:04:06.000Z');
    expect($store->findById('Y3JlZC1vbmU')->clonedAt)->not->toBeNull();

    $store->delete('Y3JlZC1vbmU');
    expect($store->findById('Y3JlZC1vbmU'))->toBeNull();
});

it('announces a clone detection as an event', function () {
    $user = makeTestUser();
    seedCredential($user);

    Event::fake([FancyPasskeys\Laravel\Events\PasskeyCloneDetected::class]);

    (new EloquentCredentialStore())->flagCloned('Y3JlZC1vbmU', '2026-02-02T03:04:06.000Z');

    Event::assertDispatched(FancyPasskeys\Laravel\Events\PasskeyCloneDetected::class);
});

it('keeps the public key and counter out of a passkey summary', function () {
    $user = makeTestUser();
    $credential = seedCredential($user);

    $summary = $credential->toStoredCredential()->toSummary();

    expect($summary)->not->toHaveKey('publicKey');
    expect($summary)->not->toHaveKey('signCount');
    expect($summary['id'])->toBe('Y3JlZC1vbmU');
    expect($summary['name'])->toBe('MacBook Touch ID');
});

it('resolves the guard from Fortify when one is configured', function () {
    /** @var PasskeyManager $manager */
    $manager = $this->app->make(PasskeyManager::class);

    expect($manager->guard())->toBe('web');

    config()->set('fortify.guard', 'sanctum');
    expect($manager->guard())->toBe('sanctum');

    config()->set('passkeys.guard', 'admin');
    expect($manager->guard())->toBe('admin');
});
