<?php

namespace SqlQueryProtection;

use Console\SqlProtectionCommand;
use Illuminate\Support\ServiceProvider;


class SqlQueryProtectionServiceProvider extends ServiceProvider
{
    public function register()
    {

        // Register the command with Artisan
        $this->commands([
            SqlProtectionCommand::class,
        ]);

        // Register services, merge configurations
        $this->mergeConfigFrom(__DIR__.'/../config/sqlqueryprotection.php', 'sqlqueryprotection');
    }

    public function boot()
    {
        // Publish configuration
        $this->publishes([
            __DIR__.'/../config/sqlqueryprotection.php' => config_path('sqlqueryprotection.php'),
        ], 'config');
    }
}
