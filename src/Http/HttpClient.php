<?php

declare(strict_types=1);

namespace InID\Http;

// How the SDK talks to InID. Swap it for tests, or for the app's own client (Guzzle, Laravel's).
interface HttpClient
{
    /**
     * @param array<string, string> $headers
     * @throws NetworkException when InID can't be reached (no answer at all)
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null, float $timeout = 10.0): HttpResponse;
}
