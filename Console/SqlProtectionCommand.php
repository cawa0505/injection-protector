<?php

namespace Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Route;
use SqlQueryProtection\Middleware\SqlQueryProtection;

class SqlProtectionCommand extends Command
{
    protected $signature = 'sqlprotection:scan';
    protected $description = 'Scan for SQL injection vulnerabilities';

    public function handle()
    {
        $this->info('Running SQL Protection Scan...');
        
        // Get all routes
        $routes = Route::getRoutes();
        
        $vulnerableRoutes = [];

        // Check each route for SQL injection vulnerabilities
        foreach ($routes as $route) {
            $action = $route->getAction();
            $middleware = $action['middleware'] ?? [];
            
            // Check if the SQL injection protection middleware is applied
            if (in_array(SqlQueryProtection::class, (array) $middleware)) {
            
                
                $this->info('Checking route: ' . $route->uri);
                // Add your logic to analyze route parameters or request handling
                
                // If a vulnerability is detected, add to the list
                // Here you should define your criteria for marking a route as vulnerable
                // Example:
                if ($this->isVulnerable($route)) {
                    $vulnerableRoutes[] = $route->uri;
                }
            }
        }

        // Display results
        if (empty($vulnerableRoutes)) {
            $this->info('No SQL injection vulnerabilities detected.');
        } else {
            $this->warn('Potential SQL injection vulnerabilities found in the following routes:');
            foreach ($vulnerableRoutes as $vulnerableRoute) {
                $this->line($vulnerableRoute);
            }
        }
    }

    // Example method to determine if a route is vulnerable
    protected function isVulnerable($route)
    {
        // Implement your logic to check for vulnerabilities here
        // This can include analyzing request parameters, query strings, etc.
        // For simplicity, this method currently returns false.
        
        return false; // Change this based on your vulnerability detection logic
    }
}
