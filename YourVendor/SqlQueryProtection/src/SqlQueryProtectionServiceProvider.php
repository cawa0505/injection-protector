<?php

namespace YourVendor\SqlQueryProtection;

use Illuminate\Support\ServiceProvider;

class SqlQueryProtectionServiceProvider extends ServiceProvider
{
    public function register()
    {
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
