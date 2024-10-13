<?php

namespace YourVendor\SqlQueryProtection\Tests;

use Illuminate\Contracts\Console\Kernel;

trait CreatesApplication
{
    protected function createApplication()
    {
        $app = require __DIR__.'/../../../../bootstrap/app.php'; // Adjust the path to your bootstrap file
        $app->make(Kernel::class)->bootstrap();

        return $app;
    }
}
