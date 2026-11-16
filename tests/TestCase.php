<?php

declare(strict_types=1);

namespace InID\Tests;

use InID\Config;
use InID\Cookie;
use InID\InID;
use InID\Jwks;
use InID\Request;
use InID\Response;
use InID\Tests\Support\FakeInID;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected FakeInID $fake;
    protected InID $inid;

    protected function setUp(): void
    {
        Jwks::forget();
        $this->fake = new FakeInID();
        $this->inid = new InID(new Config(FakeInID::PK, FakeInID::SK, FakeInID::ISSUER, webhookSecret: 'whsec_test'), $this->fake);
    }

    protected function request(string $method, string $pathAndQuery, array $cookies = [], array $headers = []): Request
    {
        if ($cookies) {
            $headers['cookie'] = Cookie::serialize($cookies);
        }
        return new Request($method, 'https://app.test' . $pathAndQuery, $headers);
    }

    /** @return array<string, \InID\Cookie> the response's cookies by name */
    protected function cookies(Response $response): array
    {
        $byName = [];
        foreach ($response->cookies as $cookie) {
            $byName[$cookie->name] = $cookie;
        }
        return $byName;
    }

    protected function query(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        return $query;
    }
}
