<?php

namespace SqlQueryProtection\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Route;
use SqlQueryProtection\Middleware\SqlQueryProtection;

class SqlProtectionCommand extends Command
{
    protected $signature = 'sqlprotection:scan';
    protected $description = 'Scan for SQL and LDAP injection vulnerabilities in route parameters and URIs';

    protected $sqlPatterns = [
        '/\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER|RENAME|DESCRIBE|SHOW|EXEC|DECLARE|CAST|CONVERT|USE|GRANT|REVOKE|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|LOCK|UNLOCK|PREPARE|EXECUTE|DEALLOCATE|SET|SLEEP|BENCHMARK|PG_SLEEP|WAITFOR)\b/i',
        '/(\bOR\b|\bAND\b|\bNOT\b)\s*\d+\s*=\s*\d+/i', // Logical operators with always true conditions
        '/(\bOR\b|\bAND\b)\s*\'[^\']*\'\s*=\s*\'[^\']*\'/i', // Logical operators with string comparison
        '/(\bOR\b|\bAND\b)\s*[\d\w]+\s*=\s*[\d\w]+/i', // Logical operators with field comparison
        '/(\bINTO\b\s*OUTFILE\s*|LOAD_FILE\s*\()/i', // File operations
        '/CHAR\s*\(\d+.*?\)/i', // CHAR() function to bypass filters
        '/CONCAT\s*\(.*?\)/i', // CONCAT() function to bypass filters
        '/(?:\b(?:EXEC\s*(?:UTE)?\s*(?:IMMEDIATE)?|EXPLAIN|OPTIMIZE)\b)/i', // EXEC/EXPLAIN/OPTIMIZE commands
        '/%c0%a7/i', // Example harmful byte sequence
        '/%00/i', // Null byte
        '/%20/i', // Space encoding
    ];

    protected $ldapPatterns = [
        '/(\bOR\b|\bAND\b|\bNOT\b)\s*\d+\s*=\s*\d+/i', // Logical operators (common in LDAP)
        '/\|\|/i', // Double pipe (LDAP)
        '/\&\&/i', // Double ampersand (LDAP)
        '/[^\x00-\x1F\x20\x22\x27\x28\x29\x2A\x2B\x2C\x2F\x3A\x3C\x3E\x3F\x5B\x5D\x7B\x7D\x7C]/', // Special characters in LDAP
        '/(\\\|\s*\\\s*\\\s*\\\s*)/', // Escaped characters
        '/(&(.*?)(=|~))?(.*?)(|)/', // LDAP filter syntax
    ];

    public function handle()
    {
        $this->info('Running SQL and LDAP Protection Scan...');

        // Get all routes
        $routes = Route::getRoutes();

        $vulnerableRoutes = [];

        // Check each route for SQL and LDAP injection vulnerabilities
        foreach ($routes as $route) {
            $action = $route->getAction();
            $middleware = $action['middleware'] ?? [];

            // Check if the SQL injection protection middleware is applied
            if (in_array(SqlQueryProtection::class, (array) $middleware)) {
                $this->info('Checking route: ' . $route->uri);

                // Check URI for vulnerabilities
                if ($this->isVulnerable($route->uri, $this->sqlPatterns) || $this->isVulnerable($route->uri, $this->ldapPatterns)) {
                    $vulnerableRoutes[] = 'Vulnerable URI: ' . $route->uri;
                }

                // Check request parameters for vulnerabilities
                $requestParameters = $this->getRequestParametersForRoute($route);
                foreach ($requestParameters as $key => $value) {
                    if ($this->isVulnerable($value, $this->sqlPatterns) || $this->isVulnerable($value, $this->ldapPatterns)) {
                        $vulnerableRoutes[] = 'Vulnerable parameter in ' . $route->uri . ': ' . $key . ' = ' . $value;
                    }
                }
            }
        }

        // Display results
        if (empty($vulnerableRoutes)) {
            $this->info('No SQL or LDAP injection vulnerabilities detected.');
        } else {
            $this->warn('Potential SQL or LDAP injection vulnerabilities found in the following routes:');
            foreach ($vulnerableRoutes as $vulnerableRoute) {
                $this->line($vulnerableRoute);
            }
        }
    }

    // Method to check if a value is vulnerable to injection
    protected function isVulnerable($value, $patterns)
    {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true; // Detected a potential injection pattern
            }
        }
        return false; // No vulnerabilities found
    }

    // Method to get simulated request parameters for a given route
    protected function getRequestParametersForRoute($route)
    {
        // Here you can define how to simulate request parameters
        // For simplicity, return an array of test inputs that simulate user input
        return [
            'id' => '1 OR 1=1', // Example of a malicious input
            'username' => 'admin\' OR \'1\'=\'1',
            'ldap' => '(uid=*))(|(uid=*))', // Example LDAP injection
            'query' => 'SELECT * FROM users WHERE name=\'test\' UNION SELECT * FROM information_schema.tables;'
            // Add more test parameters as needed
        ];
    }
}
