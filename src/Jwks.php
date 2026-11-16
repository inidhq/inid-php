<?php

declare(strict_types=1);

namespace InID;

use InID\Http\HttpClient;

// InID's public keys, kept an hour. A key it doesn't know (InID just rotated its signing key)
// is looked for at once, but once per key id and at most once a second: tokens with made-up
// key ids can't make it ask InID again and again.
final class Jwks
{
    private const TTL = 3600;

    // Per issuer, for the life of the process (long-running servers keep it across requests)
    /** @var array<string, array{at: float, keys: array<string, array{n: string, e: string}>, missed: array<string, true>, askedAt: float}> */
    private static array $memory = [];

    /** @var array<string, \OpenSSLAsymmetricKey> */
    private static array $imported = [];

    public function __construct(
        private readonly HttpClient $http,
        // Any PSR-16 cache (Laravel's, Symfony's): shares the keys across PHP-FPM requests
        private readonly ?\Psr\SimpleCache\CacheInterface $cache = null,
    ) {
    }

    // For tests
    public static function forget(): void
    {
        self::$memory = [];
        self::$imported = [];
    }

    /** @throws InIDException when InID answers but not with its keys */
    public function key(string $issuer, string $kid): ?\OpenSSLAsymmetricKey
    {
        $jwk = $this->jwk($issuer, $kid);
        if ($jwk === null) {
            return null;
        }
        $id = $jwk['n'] . '.' . $jwk['e'];
        if (!isset(self::$imported[$id])) {
            $key = openssl_pkey_get_public(self::pem($jwk['n'], $jwk['e']));
            if ($key === false) {
                return null;
            }
            self::$imported[$id] = $key;
        }
        return self::$imported[$id];
    }

    /** @return array{n: string, e: string}|null */
    private function jwk(string $issuer, string $kid): ?array
    {
        $now = microtime(true);
        $known = self::$memory[$issuer] ?? $this->fromCache($issuer);
        if ($known !== null && $now - $known['at'] < self::TTL) {
            if (isset($known['keys'][$kid])) {
                self::$memory[$issuer] = $known;
                return $known['keys'][$kid];
            }
            if (isset($known['missed'][$kid]) || $now - $known['askedAt'] < 1) {
                return null;
            }
            $known['missed'][$kid] = true;
            if (count($known['missed']) > 100) {
                $known['missed'] = [];
            }
        }
        // Only lookups for unknown keys count toward "once a second"
        $askedAt = $known !== null ? $now : 0.0;
        if ($known !== null) {
            $known['askedAt'] = $now;
            self::$memory[$issuer] = $known;
        }
        $response = $this->http->request('GET', $issuer . '/.well-known/jwks.json', ['accept' => 'application/json']);
        if (!$response->ok()) {
            throw new InIDException('jwks_unavailable', $response->status);
        }
        $keys = [];
        foreach ($response->json()['keys'] ?? [] as $jwk) {
            if (is_array($jwk) && ($jwk['kty'] ?? null) === 'RSA' && is_string($jwk['kid'] ?? null) && is_string($jwk['n'] ?? null) && is_string($jwk['e'] ?? null)) {
                $keys[$jwk['kid']] = ['n' => $jwk['n'], 'e' => $jwk['e']];
            }
        }
        self::$memory[$issuer] = ['at' => $now, 'keys' => $keys, 'missed' => $known['missed'] ?? [], 'askedAt' => $askedAt];
        try {
            $this->cache?->set($this->cacheKey($issuer), ['at' => $now, 'keys' => $keys], self::TTL);
        } catch (\Throwable) {
            // A broken cache must not sign everyone out: the keys are still in memory
        }
        return $keys[$kid] ?? null;
    }

    private function fromCache(string $issuer): ?array
    {
        try {
            $cached = $this->cache?->get($this->cacheKey($issuer));
        } catch (\Throwable) {
            return null;
        }
        if (!is_array($cached) || !isset($cached['at'], $cached['keys'])) {
            return null;
        }
        return ['at' => (float) $cached['at'], 'keys' => $cached['keys'], 'missed' => [], 'askedAt' => 0.0];
    }

    // PSR-16 keys can't hold ":" or "/"
    private function cacheKey(string $issuer): string
    {
        return 'inid.jwks.' . sha1($issuer);
    }

    // An RSA public key as PEM (SubjectPublicKeyInfo), from the JWK's modulus and exponent:
    // what openssl_verify needs, with no JWT library
    public static function pem(string $n, string $e): string
    {
        $integer = static function (string $bytes): string {
            $bytes = ltrim($bytes, "\0");
            // DER integers are signed: a leading 1 bit needs a zero byte before it
            if ($bytes === '' || ord($bytes[0]) > 0x7f) {
                $bytes = "\0" . $bytes;
            }
            return "\x02" . self::length(strlen($bytes)) . $bytes;
        };
        $rsaKey = $integer(Base64Url::decode($n)) . $integer(Base64Url::decode($e));
        $rsaKey = "\x30" . self::length(strlen($rsaKey)) . $rsaKey;
        // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1), NULL parameters
        $algorithm = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $bitString = "\x03" . self::length(strlen($rsaKey) + 1) . "\0" . $rsaKey;
        $spki = "\x30" . self::length(strlen($algorithm . $bitString)) . $algorithm . $bitString;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\0");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
