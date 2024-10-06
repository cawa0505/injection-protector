<?php

namespace YourVendor\SqlQueryProtection\Facades;

use Illuminate\Support\Facades\Facade;

class SqlQueryProtectionFacade extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'sqlqueryprotection';
    }
}
