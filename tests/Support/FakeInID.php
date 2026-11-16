<?php

declare(strict_types=1);

namespace InID\Tests\Support;

use InID\Base64Url;
use InID\Http\HttpClient;
use InID\Http\HttpResponse;
use InID\Http\NetworkException;

// InID in the test process: a JWKS from a test RSA key, ID tokens signed with it, and token,
// revoke and API answers chosen by each test. Every request is recorded.
final class FakeInID implements HttpClient
{
    public const ISSUER = 'https://id.test';
    public const PK = 'pk_test_app';
    public const SK = 'sk_test_secret';
    public const KID = 'key-1';

    private static ?\OpenSSLAsymmetricKey $key = null;

    /** @var list<array{method: string, url: string, headers: array, body: ?string}> */
    public array $requests = [];
    public bool $down = false;
    /** @var array<string, HttpResponse|callable> by "METHOD path" */
    public array $routes = [];
    public int $jwksStatus = 200;

    public static function key(): \OpenSSLAsymmetricKey
    {
        return self::$key ??= openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }

    public static function otherKey(): \OpenSSLAsymmetricKey
    {
        static $other = null;
        return $other ??= openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }

    public function jwks(): array
    {
        $rsa = openssl_pkey_get_details(self::key())['rsa'];
        return ['keys' => [['kty' => 'RSA', 'kid' => self::KID, 'alg' => 'RS256', 'use' => 'sig', 'n' => Base64Url::encode($rsa['n']), 'e' => Base64Url::encode($rsa['e'])]]];
    }

    // An ID token for this app, ten minutes long, unless the test says otherwise
    public static function idToken(array $claims = [], array $header = [], ?\OpenSSLAsymmetricKey $key = null): string
    {
        $claims = [
            'iss' => self::ISSUER,
            'aud' => self::PK,
            'sub' => 'usr_1',
            'exp' => time() + 600,
            'iat' => time(),
            'sid' => 'ses_current',
            'given_name' => 'Ana',
            'family_name' => 'Gómez',
            'email' => 'ana@example.com',
            'email_verified' => true,
            'phone_number' => '+573001234567',
            'roles' => ['member'],
            'permissions' => ['invoices:read'],
            ...$claims,
        ];
        $header = ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => self::KID, ...$header];
        $data = Base64Url::encode(json_encode($header)) . '.' . Base64Url::encode(json_encode($claims));
        openssl_sign($data, $signature, $key ?? self::key(), OPENSSL_ALGO_SHA256);
        return $data . '.' . Base64Url::encode($signature);
    }

    // The token endpoint answers with these tokens (or a status)
    public function tokens(string $idToken, string $refreshToken = 'rt_new'): void
    {
        $this->routes['POST /oauth/token'] = new HttpResponse(200, json_encode(['id_token' => $idToken, 'refresh_token' => $refreshToken, 'access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 600]));
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null, float $timeout = 10.0): HttpResponse
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];
        if ($this->down) {
            throw new NetworkException('down');
        }
        $path = (string) parse_url($url, PHP_URL_PATH);
        if ($method === 'GET' && $path === '/.well-known/jwks.json') {
            return new HttpResponse($this->jwksStatus, json_encode($this->jwks()));
        }
        $answer = $this->routes["$method $path"] ?? null;
        if (is_callable($answer)) {
            return $answer($method, $url, $headers, $body);
        }
        if ($answer instanceof HttpResponse) {
            return $answer;
        }
        if ($method === 'POST' && $path === '/oauth/revoke') {
            return new HttpResponse(200, '{}');
        }
        return new HttpResponse(404, '{"error":"not_found"}');
    }

    /** @return list<array> the requests to this path */
    public function sent(string $method, string $path): array
    {
        return array_values(array_filter($this->requests, static fn ($r) => $r['method'] === $method && parse_url($r['url'], PHP_URL_PATH) === $path));
    }
}
