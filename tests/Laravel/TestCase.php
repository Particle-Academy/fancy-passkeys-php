<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Laravel;

use FancyPasskeys\Laravel\PasskeysServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [PasskeysServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('auth.providers.users.model', TestUser::class);

        /*
         * These are set as whole sub-arrays on purpose: mergeConfigFrom is a
         * shallow merge, so setting only `passkeys.rp.id` here would replace
         * the entire `rp` block and silently drop the origin list.
         */
        $app['config']->set('passkeys.rp', [
            'id' => 'localhost',
            'name' => 'Fancy Passkeys Test',
            'origins' => ['http://localhost'],
            'allow_subdomains' => false,
        ]);

        $app['config']->set('passkeys.users', [
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
