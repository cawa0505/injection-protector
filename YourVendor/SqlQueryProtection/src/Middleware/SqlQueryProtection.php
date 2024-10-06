<?php

namespace YourVendor\SqlQueryProtection\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class SqlQueryProtection
{
    // Define the special character pattern
    protected $specialCharPattern = '/[\'"\(\)&!`~]/';

    // Define the cookie special character pattern
    protected $specialCharPatternCookie = '/[\'"\(\)&!`~*]/';

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Check if New Relic is available
        $useNewRelic = extension_loaded('newrelic');

        // Helper function for logging
        $logWarning = function ($message, $context = []) use ($useNewRelic) {
            if ($useNewRelic) {
                $contextString = json_encode($context); // Convert details to a string format
                Log::channel('newrelic')->warning($message.' | Details: '.$contextString, $context);
            } else {
                Log::warning($message, $context);
            }
        };

        // Define patterns to detect SQL injection attempts
        $sqlPatterns = [
            '/\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER|RENAME|DESCRIBE|SHOW|EXEC|DECLARE|CAST|CONVERT|USE|GRANT|REVOKE|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|LOCK|UNLOCK|PREPARE|EXECUTE|DEALLOCATE|SET|SLEEP|BENCHMARK|PG_SLEEP|WAITFOR)\b/i',
            '/(\bOR\b|\bAND\b|\bNOT\b)\s*\d+\s*=\s*\d+/i', // Logical operators with always true conditions
            '/(\bOR\b|\bAND\b)\s*\'[^\']*\'\s*=\s*\'[^\']*\'/i', // Logical operators with string comparison
            '/(\bOR\b|\bAND\b)\s*[\d\w]+\s*=\s*[\d\w]+/i', // Logical operators with field comparison
            '/(\bINTO\b\s*OUTFILE\s*|LOAD_FILE\s*\()/i', // File operations
            '/CHAR\s*\(\d+.*?\)/i', // CHAR() function to bypass filters
            '/CONCAT\s*\(.*?\)/i', // CONCAT() function to bypass filters
            '/(?:\b(?:EXEC\s*(?:UTE)?\s*(?:IMMEDIATE)?|EXPLAIN|OPTIMIZE)\b)/i', // EXEC/EXPLAIN/OPTIMIZE commands
            '/%c0%a7/i', // Example harmful byte sequence
            '/%00/i', // Null byte (common in some types of injection attacks)
            '/%20/i', // Space encoding (space is often used to obfuscate payloads)
        ];

        // Define patterns to detect XSS attempts
        $xssPatterns = [
            '/<script\b[^>]*>(.*?)<\/script>/is', // Script tags
            '/on\w+="[^"]*"/i', // Inline event handlers
            '/javascript:/i', // JavaScript protocol
            '/vbscript:/i', // VBScript protocol
            '/<.*?javascript:.*?>/i', // JavaScript within tags
            '/<.*?vbscript:.*?>/i', // VBScript within tags
            '/<.*?on\w+=.*?>/i', // Event handlers within tags
        ];

        // Define refined patterns to detect LDAP injection attempts
        $ldapPatterns = [
            '/\*\(/', // Wildcard character followed by opening parenthesis
            '/\)\*\*/', // Closing parenthesis followed by wildcard characters
            '/\(\|/', // Opening parenthesis followed by OR operator
            '/\(\&/', // Opening parenthesis followed by AND operator
            '/\(\!/', // Opening parenthesis followed by NOT operator
            '/\(~/', // Opening parenthesis followed by approximate match
            '/\(&/', // Opening parenthesis followed by AND operator
            '/\(objectClass=/', // Opening parenthesis followed by objectClass
            '/\(uid=/', // Opening parenthesis followed by uid
            '/\(cn=/', // Opening parenthesis followed by cn
            '/\(mail=/', // Opening parenthesis followed by mail
            '/\(dc=/', // Opening parenthesis followed by dc
            '/\(o=/', // Opening parenthesis followed by o
            '/\(ou=/', // Opening parenthesis followed by ou
        ];

        $excludedCookiePattern = [
            '/SL_C_23361dd035530_SID=({.*?})/',
            '/SL_L_23361dd035530_SID=({.*?})/',
        ];

        // Function to check values against SQL injection patterns
        $checkForSqlInjection = function ($key, $value, $type = 'input', $skipPatterns = []) use ($sqlPatterns, $request, $logWarning) {
            foreach ($sqlPatterns as $pattern) {
                // Skip specific patterns if requested
                $skip = false;
                foreach ($skipPatterns as $skipPattern) {
                    if (preg_match($skipPattern, $value)) {
                        $skip = true;
                        break;
                    }
                }

                if ($skip) {
                    continue;
                }

                if (preg_match($pattern, $value)) {
                    $logWarning('Potential SQL injection attempt detected', [
                        'type' => $type,
                        'key' => $key,
                        'value' => $value,
                        'ip' => $request->ip(),
                        'url' => $request->fullUrl(),
                    ]);

                    return response()->json(['error' => 'Suspicious activity detected'], 400);
                }
            }

            return null;
        };

        // Function to check values against XSS patterns
        $checkForXssInjection = function ($key, $value, $type = 'input') use ($xssPatterns, $request, $logWarning) {
            foreach ($xssPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    $logWarning('Potential XSS attempt detected', [
                        'type' => $type,
                        'key' => $key,
                        'value' => $value,
                        'ip' => $request->ip(),
                        'url' => $request->fullUrl(),
                    ]);

                    return response()->json(['error' => 'Suspicious activity detected'], 400);
                }
            }

            return null;
        };

        // Function to check the URL for LDAP injection
        $checkUrlForLdapInjection = function ($url) use ($ldapPatterns, $request, $logWarning) {
            foreach ($ldapPatterns as $pattern) {
                if (preg_match($pattern, $url)) {
                    $logWarning('Potential LDAP injection attempt detected in URL', [
                        'type' => 'url',
                        'value' => $url,
                        'ip' => $request->ip(),
                        'url' => $request->fullUrl(),
                    ]);

                    return response()->json(['error' => 'Suspicious activity detected'], 400);
                }
            }

            return null;
        };

        // Specifically check for attack types in the X-RTC-ATTACKTYPE header
        $attackTypeHeader = $request->header('X-RTC-ATTACKTYPE');
        if ($attackTypeHeader) {
            if (in_array(strtolower($attackTypeHeader), ['sqlinjection'])) {
                $logWarning('Potential SQL injection attempt detected via X-RTC-ATTACKTYPE header', [
                    'type' => 'header',
                    'key' => 'X-RTC-ATTACKTYPE',
                    'value' => $attackTypeHeader,
                    'ip' => $request->ip(),
                    'url' => $request->fullUrl(),
                ]);

                return response()->json(['error' => 'Suspicious activity detected'], 400);
            } elseif (in_array(strtolower($attackTypeHeader), ['ldapinjection'])) {
                $logWarning('Potential LDAP injection attempt detected via X-RTC-ATTACKTYPE header', [
                    'type' => 'header',
                    'key' => 'X-RTC-ATTACKTYPE',
                    'value' => $attackTypeHeader,
                    'ip' => $request->ip(),
                    'url' => $request->fullUrl(),
                ]);

                return response()->json(['error' => 'Suspicious activity detected'], 400);
            }
        }

        // Check the full URL for SQL injection
        $decodedUrl = urldecode($request->fullUrl());
        $response = $checkForSqlInjection('url', $decodedUrl, 'url', [
            '/\b(SELECT|UPDATE|SHOW|DELETE)\b/i',
        ]);
        if ($response) {
            return $response;
        }

        // Check the full URL for LDAP injection
        $response = $checkUrlForLdapInjection($decodedUrl);
        if ($response) {
            return $response;
        }

        // Check request inputs for SQL and XSS injection
        // foreach ($request->all() as $key => $value) {
        //     if (is_string($value)) {
        //         $response = $checkForSqlInjection($key, $value, 'input');
        //         if ($response) {
        //             return $response;
        //         }
        //         $response = $checkForXssInjection($key, $value, 'input');
        //         if ($response) {
        //             return $response;
        //         }
        //     }
        // }
        // Check request headers for SQL and XSS injection
        foreach ($request->headers->all() as $key => $values) {
            foreach ($values as $value) {
                // Call the function to extract and clean the cookie value
                $value = $this->extractAndCleanCookieValue($value, $excludedCookiePattern);

                if (is_string($value)) {
                    $response = $checkForSqlInjection($key, $value, 'header');
                    if ($response) {
                        return $response;
                    }
                    $response = $checkForXssInjection($key, $value, 'header');
                    if ($response) {
                        return $response;
                    }
                }
            }
        }

        // Function to check headers for SQL injection, XSS, and special characters if header key is 'cookie'
        foreach ($request->headers->all() as $key => $values) {
            foreach ($values as $value) {

                // Call the function to extract and clean the cookie value
                $value = $this->extractAndCleanCookieValue($value, $excludedCookiePattern);

                if (is_string($value)) {
                    // Check for special characters in 'cookie' headers
                    if (stripos($key, 'cookie') !== false && preg_match($this->specialCharPatternCookie, $value)) {
                        $logWarning('Potential harmful characters detected in header with cookie key', [
                            'type' => 'header',
                            'key' => $key,
                            'value' => $value,
                            'ip' => $request->ip(),
                            'url' => $request->fullUrl(),
                        ]);

                        return response()->json(['error' => 'Suspicious activity detected'], 400);
                    }

                    // Check for special characters in 'x-xsrf-token' headers
                    if (stripos($key, 'x-xsrf-token') !== false && preg_match($this->specialCharPattern, $value)) {
                        $logWarning('Potential harmful characters detected in x-xsrf-token header', [
                            'type' => 'header',
                            'key' => $key,
                            'value' => $value,
                            'ip' => $request->ip(),
                            'url' => $request->fullUrl(),
                        ]);

                        return response()->json(['error' => 'Suspicious activity detected'], 400);
                    }

                    // Check for SQL injection patterns in headers
                    $response = $checkForSqlInjection($key, $value, 'header');
                    if ($response) {
                        return $response;
                    }

                    // Check for XSS injection patterns in headers
                    $response = $checkForXssInjection($key, $value, 'header');
                    if ($response) {
                        return $response;
                    }
                }
            }
        }

        // Check cookies for dynamic session keys
        foreach ($request->cookies as $cookieName => $cookieValue) {
            if (is_string($cookieValue)) {
                // Avoid special characters in cookies
                if (preg_match($this->specialCharPattern, $cookieValue)) {
                    $logWarning('Potential harmful characters detected in cookie', [
                        'type' => 'cookie',
                        'key' => $cookieName,
                        'value' => $cookieValue,
                        'ip' => $request->ip(),
                        'url' => $request->fullUrl(),
                    ]);

                    return response()->json(['error' => 'Suspicious activity detected'], 400);
                }

                $response = $checkForSqlInjection($cookieName, $cookieValue, 'cookie');
                if ($response) {
                    return $response;
                }
                $response = $checkForXssInjection($cookieName, $cookieValue, 'cookie');
                if ($response) {
                    return $response;
                }
            }
        }

        // Check X-XSRF-TOKEN cookie for dynamic session keys and extra characters
        $xsrfToken = $request->cookie('XSRF-TOKEN');
        if ($xsrfToken) {
            $decodedXsrfToken = urldecode($xsrfToken); // Decode the token
            if (! empty($decodedXsrfToken)) { // Check if the decoded token is not empty
                $xsrfTokenParts = explode(';', $decodedXsrfToken);
                foreach ($xsrfTokenParts as $part) {
                    if (strpos($part, '=') !== false) {
                        [$key, $sessionValue] = explode('=', $part, 2);

                        // Avoid special characters in the session key and value
                        if (preg_match($this->specialCharPattern, $key) || preg_match($this->specialCharPattern, $sessionValue)) {
                            $logWarning('Potential harmful characters detected in session key or value within XSRF-TOKEN cookie', [
                                'type' => 'cookie',
                                'key' => $key,
                                'value' => $sessionValue,
                                'ip' => $request->ip(),
                                'url' => $request->fullUrl(),
                            ]);

                            return response()->json(['error' => 'Suspicious activity detected'], 400);
                        }

                        $response = $checkForSqlInjection($key, $sessionValue, 'cookie');
                        if ($response) {
                            return $response;
                        }
                        $response = $checkForXssInjection($key, $sessionValue, 'cookie');
                        if ($response) {
                            return $response;
                        }
                    }
                }
            }
        }

        // Proceed with the request
        return $next($request);
    }

    // Function to find and clean the cookie value based on multiple patterns
    public function extractAndCleanCookieValue($cookieValue, array $excludedCookiePattern)
    {
        foreach ($excludedCookiePattern as $pattern) {
            // Find and extract the cookie value using regex
            preg_match($pattern, $cookieValue, $matches);
            // Check if the cookie value was found
            if (isset($matches[1])) {
                // Extracted cookie value (still in JSON format)
                $extractedValue = $matches[1];

                // Remove all double and single quotes
                $cleanedValue = str_replace(['"', "'"], '', $extractedValue);

                // Return the cleaned value if found
                return $cleanedValue;
            }
        }

        // Return the original cookie value if no match is found
        return $cookieValue;
    }
}
