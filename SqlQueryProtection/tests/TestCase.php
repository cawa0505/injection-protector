<?php

namespace YourVendor\SqlQueryProtection\Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    use CreatesApplication;

    protected function setUp(): void
    {
        parent::setUp();
        // Any additional setup can go here, such as configuring the environment
    }
}
