<?php

namespace SqlQueryProtection\Tests;

use Illuminate\Http\Request;
use SqlQueryProtection\Middleware\SqlQueryProtection;

class SqlQueryProtectionTest extends TestCase
{
    protected $middleware;

    
    protected function setUp(): void
    {
        parent::setUp();
        $this->middleware = new SqlQueryProtection();
    }

    private function createRequest(array $headers = [], array $cookies = [], string $url = '')
    {
        return Request::create($url ?: 'http://localhost', 'GET', [], $cookies, [], $headers);
    }

    public function testSqlInjectionDetectedInHeader()
    {
        $request = $this->createRequest([
            'X-Injected-Header' => "UNION SELECT * FROM users",
        ]);

        $response = $this->middleware->handle($request, function () {
            return response()->json(['success' => true], 200);
        });

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertStringContainsString('Suspicious activity detected', $response->getContent());
    }

    // Add more tests...
}
