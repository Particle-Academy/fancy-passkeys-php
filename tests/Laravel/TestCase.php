<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Laravel;

use FancyPasskeys\Laravel\PasskeysServiceProvider;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Bootstrap\LoadConfiguration;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

/**
 * A hand-built Laravel kernel for the bridge tests: laravel/framework only, no
 * orchestra/testbench (the same approach as change-council's and fancy-sign's
 * harnesses). In-memory SQLite, blank provider keys, nothing leaves the process.
 */
abstract class TestCase extends BaseTestCase
{
    /**
     * Artisan output is not mocked: that path needs Mockery, which arrived
     * only through testbench. RefreshDatabase's migrate call runs for real.
     */
    public $mockConsoleOutput = false;

    public function createApplication(): Application
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fancy-passkeys-tests';
        foreach (['config', 'bootstrap/cache', 'storage/framework/views', 'storage/framework/sessions', 'storage/logs'] as $dir) {
            if (! is_dir($base . '/' . $dir)) {
                mkdir($base . '/' . $dir, 0777, true);
            }
        }
        // An empty .env: the framework reads one, and nothing in it may come from the machine.
        file_put_contents($base . '/.env', '');

        $app = Application::configure(basePath: $base)
            ->withProviders([PasskeysServiceProvider::class], withBootstrapProviders: false)
            ->withMiddleware(static function (Middleware $middleware): void {})
            ->withExceptions(static function (Exceptions $exceptions): void {})
            ->create();

        $app->afterBootstrapping(LoadConfiguration::class, function (Application $app): void {
            $app['env'] = 'testing';
            $this->defineEnvironment($app);
        });

        $app->make(Kernel::class)->bootstrap();

        return $app;
    }

    protected function defineEnvironment(Application $app): void
    {
        $config = $app['config'];

        $config->set('app.env', 'testing');
        $config->set('app.key', 'base64:' . base64_encode(random_bytes(32)));

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $config->set('cache.default', 'array');
        $config->set('session.driver', 'array');
        $config->set('mail.default', 'array');
        $config->set('services.anthropic.key', '');
        $config->set('services.openai.key', '');

        $config->set('auth.providers.users.model', TestUser::class);

        /*
         * These are set as whole sub-arrays on purpose: mergeConfigFrom is a
         * shallow merge, so setting only `passkeys.rp.id` here would replace
         * the entire `rp` block and silently drop the origin list.
         */
        $config->set('passkeys.rp', [
            'id' => 'localhost',
            'name' => 'Fancy Passkeys Test',
            'origins' => ['http://localhost'],
            'allow_subdomains' => false,
        ]);

        $config->set('passkeys.users', [
            'table' => 'users',
            'model' => TestUser::class,
        ]);

        // The harness stands in for the host app's users table. It must be part
        // of the same migration run as the package's, and must sort first.
        $app->afterResolving('migrator', static function ($migrator): void {
            $migrator->path(__DIR__ . '/migrations');
        });
    }
}
