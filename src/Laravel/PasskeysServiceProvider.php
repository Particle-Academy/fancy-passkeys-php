<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel;

use FancyPasskeys\Contracts\ChallengeStore;
use FancyPasskeys\Contracts\CredentialStore;
use FancyPasskeys\IssuedLoginCertificate;
use FancyPasskeys\Laravel\Events\PasskeyCertificateIssued;
use FancyPasskeys\Laravel\Http\PasskeyLoginController;
use FancyPasskeys\LoginCertificates;
use FancyPasskeys\Laravel\Http\PasskeyRegistrationController;
use FancyPasskeys\PasskeyPolicy;
use FancyPasskeys\PasskeyServer;
use FancyPasskeys\RelyingParty;
use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

/**
 * Wires the framework-free server into Laravel.
 *
 * An app that is not Laravel ignores this file entirely and constructs
 * {@see PasskeyServer} directly.
 */
class PasskeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/passkeys.php', 'passkeys');

        $this->app->singleton(RelyingParty::class, static function ($app): RelyingParty {
            $config = (array) $app['config']->get('passkeys.rp', []);

            /** @var list<string> $origins */
            $origins = array_values((array) ($config['origins'] ?? []));

            // Throws here — at boot, with a stack trace — rather than on every
            // login in production with an opaque browser error.
            return new RelyingParty(
                (string) ($config['id'] ?? ''),
                (string) ($config['name'] ?? ''),
                $origins,
                (bool) ($config['allow_subdomains'] ?? false),
            );
        });

        $this->app->singleton(PasskeyPolicy::class, static function ($app): PasskeyPolicy {
            $config = (array) $app['config']->get('passkeys.policy', []);

            return new PasskeyPolicy(
                (string) ($config['user_verification'] ?? 'preferred'),
                (string) ($config['resident_key'] ?? 'preferred'),
                (string) ($config['attestation'] ?? 'none'),
                (int) ($config['timeout_ms'] ?? 60000),
                (int) ($config['challenge_ttl'] ?? 300),
                array_values(array_map('intval', (array) ($config['algorithms'] ?? [-8, -7, -257]))),
                (string) ($config['counter_policy'] ?? 'reject'),
            );
        });

        $this->app->bind(ChallengeStore::class, static function ($app): ChallengeStore {
            /** @var CacheManager $cache */
            $cache = $app->make('cache');
            $store = $app['config']->get('passkeys.cache.store');

            return new CacheChallengeStore(
                $cache->store(is_string($store) && $store !== '' ? $store : null),
                (string) $app['config']->get('passkeys.cache.prefix', 'passkeys:challenge:'),
            );
        });

        $this->app->bind(CredentialStore::class, EloquentCredentialStore::class);

        $this->app->singleton(PasskeyServer::class, static fn ($app): PasskeyServer => new PasskeyServer(
            $app->make(RelyingParty::class),
            $app->make(PasskeyPolicy::class),
            $app->make(ChallengeStore::class),
            $app->make(CredentialStore::class),
            certificates: self::loginCertificates($app),
        ));

        $this->app->singleton(PasskeyManager::class, static fn ($app): PasskeyManager => new PasskeyManager(
            $app->make(PasskeyServer::class),
        ));
        $this->app->alias(PasskeyManager::class, 'passkeys');
    }

    /**
     * Login certificates, from `passkeys.certificates`. Null — off — unless
     * `enabled` is true.
     *
     * Claims come from the current request (IP, user agent, X-Request-Id), or
     * from an invokable class named in `claims`, called as
     * `(Request $request, array $subject): array`. Delivery is the
     * {@see PasskeyCertificateIssued} event; the app's listener decides where
     * the certificate goes.
     */
    private static function loginCertificates(Application $app): ?LoginCertificates
    {
        $config = (array) $app['config']->get('passkeys.certificates', []);

        if (! (bool) ($config['enabled'] ?? false)) {
            return null;
        }

        $claimsClass = $config['claims'] ?? null;

        $claims = static function (array $subject) use ($app, $claimsClass): array {
            $request = $app->bound('request') ? $app->make('request') : null;

            if (! $request instanceof Request) {
                return [];
            }

            if (is_string($claimsClass) && $claimsClass !== '') {
                return (array) $app->make($claimsClass)($request, $subject);
            }

            return array_filter([
                'ip' => $request->ip(),
                'userAgent' => $request->userAgent(),
                'requestId' => $request->headers->get('X-Request-Id'),
            ], static fn (mixed $value): bool => $value !== null && $value !== '');
        };

        return new LoginCertificates(
            ceremonies: array_values((array) ($config['ceremonies'] ?? ['registration', 'authentication'])),
            claims: $claims,
            deliver: static function (IssuedLoginCertificate $issued): void {
                PasskeyCertificateIssued::dispatch($issued);
            },
        );
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes(
                [__DIR__ . '/../../config/passkeys.php' => $this->app->configPath('passkeys.php')],
                'passkeys-config',
            );
            $this->publishes(
                [__DIR__ . '/../../database/migrations' => $this->app->databasePath('migrations')],
                'passkeys-migrations',
            );
        }

        if ((bool) $this->app['config']->get('passkeys.routes.enabled', true)) {
            $this->registerRoutes();
        }
    }

    /**
     * Four POST endpoints in their own group.
     *
     * Fortify's routes are never modified or re-registered. If the app has
     * Fortify's `login` limiter registered, the passkey login path reuses it so
     * an existing throttle covers both — an unthrottled passkey endpoint beside
     * a throttled password endpoint is a bypass, not a feature.
     */
    private function registerRoutes(): void
    {
        $config = (array) $this->app['config']->get('passkeys.routes', []);

        /** @var list<string> $middleware */
        $middleware = array_values((array) ($config['middleware'] ?? ['web']));
        /** @var list<string> $authMiddleware */
        $authMiddleware = array_values((array) ($config['auth_middleware'] ?? ['auth']));

        $limiter = $config['limiter'] ?? null;

        if (! is_string($limiter) || $limiter === '') {
            $limiter = RateLimiter::limiter('login') !== null ? 'login' : 'passkeys';
        }

        if ($limiter === 'passkeys' && RateLimiter::limiter('passkeys') === null) {
            RateLimiter::for('passkeys', static fn ($request) => \Illuminate\Cache\RateLimiting\Limit::perMinute(30)
                ->by(strtolower((string) $request->input('email', '')) . '|' . $request->ip()));
        }

        Route::group([
            'prefix' => (string) ($config['prefix'] ?? 'passkeys'),
            'middleware' => $middleware,
            'as' => 'passkeys.',
        ], static function () use ($authMiddleware, $limiter): void {
            Route::middleware($authMiddleware)->group(static function (): void {
                Route::post('register/options', [PasskeyRegistrationController::class, 'options'])
                    ->name('register.options');
                Route::post('register', [PasskeyRegistrationController::class, 'store'])
                    ->name('register');
            });

            Route::middleware(['throttle:' . $limiter])->group(static function (): void {
                Route::post('login/options', [PasskeyLoginController::class, 'options'])
                    ->name('login.options');
                Route::post('login', [PasskeyLoginController::class, 'store'])
                    ->name('login');
            });
        });
    }
}
