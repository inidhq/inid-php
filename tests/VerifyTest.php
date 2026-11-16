<?php

declare(strict_types=1);

namespace InID\Tests;

use InID\Base64Url;
use InID\Config;
use InID\InID;
use InID\InIDException;
use InID\Jwks;
use InID\Tests\Support\FakeInID;

// 8. ID token verification (and the bearer helper for native apps' backends)
final class VerifyTest extends TestCase
{
    public function testAGoodToken(): void
    {
        $checked = $this->inid->verifyIdToken(FakeInID::idToken());
        $this->assertNotNull($checked);
        $this->assertFalse($checked->expired);
        $this->assertSame('usr_1', $checked->claims['sub']);
    }

    public function testWrongAudience(): void
    {
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken(['aud' => 'pk_test_other'])));
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken(['aud' => [FakeInID::PK]])));
    }

    public function testWrongIssuer(): void
    {
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken(['iss' => 'https://evil.test'])));
    }

    public function testBadSignature(): void
    {
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], [], FakeInID::otherKey())));
        // The claims changed after signing
        [$header, , $signature] = explode('.', FakeInID::idToken());
        $forged = $header . '.' . Base64Url::encode(json_encode(['iss' => FakeInID::ISSUER, 'aud' => FakeInID::PK, 'sub' => 'usr_admin', 'exp' => time() + 600])) . '.' . $signature;
        $this->assertNull($this->inid->verifyIdToken($forged));
    }

    public function testOnlyRs256(): void
    {
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], ['alg' => 'none'])));
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], ['alg' => 'HS256'])));
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], ['kid' => 7])));
        $this->assertNull($this->inid->verifyIdToken('not.a.token'));
        $this->assertNull($this->inid->verifyIdToken('nope'));
    }

    public function testMissingClaims(): void
    {
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken(['sub' => 12])));
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken(['exp' => 'tomorrow'])));
    }

    public function testUnknownKidAsksInIDOnceAndRemembersIt(): void
    {
        $this->assertNotNull($this->inid->verifyIdToken(FakeInID::idToken()));
        $this->assertCount(1, $this->fake->sent('GET', '/.well-known/jwks.json'));
        // An unknown key: InID is asked at once (it may have just rotated)
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], ['kid' => 'key-a'])));
        $this->assertCount(2, $this->fake->sent('GET', '/.well-known/jwks.json'));
        // Another one within the same second: not asked
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], ['kid' => 'key-b'])));
        $this->assertCount(2, $this->fake->sent('GET', '/.well-known/jwks.json'));
        usleep(1_050_000);
        // Missed once: never asked for again
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], ['kid' => 'key-a'])));
        $this->assertCount(2, $this->fake->sent('GET', '/.well-known/jwks.json'));
        // key-b was never asked about, so now it is
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken([], ['kid' => 'key-b'])));
        $this->assertCount(3, $this->fake->sent('GET', '/.well-known/jwks.json'));
        // Known keys are kept: no request
        $this->assertNotNull($this->inid->verifyIdToken(FakeInID::idToken()));
        $this->assertCount(3, $this->fake->sent('GET', '/.well-known/jwks.json'));
    }

    public function testExpiredStillVerifiesButSaysSo(): void
    {
        $checked = $this->inid->verifyIdToken(FakeInID::idToken(['exp' => time() - 10]));
        $this->assertNotNull($checked);
        $this->assertTrue($checked->expired);
    }

    public function testNonce(): void
    {
        $this->assertNotNull($this->inid->verifyIdToken(FakeInID::idToken(['nonce' => 'n1']), 'n1'));
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken(['nonce' => 'n1']), 'n2'));
        $this->assertNull($this->inid->verifyIdToken(FakeInID::idToken(), 'n1'));
    }

    public function testJwksErrorIsAnError(): void
    {
        $this->fake->jwksStatus = 503;
        $this->expectException(InIDException::class);
        $this->inid->verifyIdToken(FakeInID::idToken());
    }

    public function testKeysAreSharedThroughAPsr16Cache(): void
    {
        $cache = new class implements \Psr\SimpleCache\CacheInterface {
            public array $items = [];
            public function get(string $key, mixed $default = null): mixed { return $this->items[$key] ?? $default; }
            public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool { $this->items[$key] = $value; return true; }
            public function delete(string $key): bool { unset($this->items[$key]); return true; }
            public function clear(): bool { $this->items = []; return true; }
            public function getMultiple(iterable $keys, mixed $default = null): iterable { return []; }
            public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool { return true; }
            public function deleteMultiple(iterable $keys): bool { return true; }
            public function has(string $key): bool { return isset($this->items[$key]); }
        };
        $config = new Config(FakeInID::PK, FakeInID::SK, FakeInID::ISSUER);
        $this->assertNotNull((new InID($config, $this->fake, $cache))->verifyIdToken(FakeInID::idToken()));
        $this->assertCount(1, $cache->items);
        // Another process: memory is empty, the cache has the keys
        Jwks::forget();
        $this->assertNotNull((new InID($config, $this->fake, $cache))->verifyIdToken(FakeInID::idToken()));
        $this->assertCount(1, $this->fake->sent('GET', '/.well-known/jwks.json'));
    }

    public function testPemFromJwkMatchesOpenSsl(): void
    {
        $details = openssl_pkey_get_details(FakeInID::key());
        $this->assertSame($details['key'], Jwks::pem(Base64Url::encode($details['rsa']['n']), Base64Url::encode($details['rsa']['e'])));
    }

    public function testBearerForNativeApps(): void
    {
        $this->assertSame('usr_1', $this->inid->verifyBearer('Bearer ' . FakeInID::idToken())?->user->id);
        $this->assertSame('usr_1', $this->inid->verifyBearer(FakeInID::idToken())?->user->id);
        $this->assertNull($this->inid->verifyBearer('Bearer ' . FakeInID::idToken(['exp' => time() - 1])));
        $this->assertNull($this->inid->verifyBearer('Bearer ' . FakeInID::idToken(['aud' => 'pk_other'])));
        $this->assertNull($this->inid->verifyBearer(null));
        $auth = $this->inid->bearerAuth($this->request('GET', '/api/me', [], ['authorization' => 'Bearer ' . FakeInID::idToken(['roles' => ['admin']])]));
        $this->assertTrue($auth->has(role: 'admin'));
    }

    public function testConfigFromEnv(): void
    {
        putenv('INID_PUBLISHABLE_KEY=pk_test_env');
        putenv('INID_SECRET_KEY=sk_test_env');
        putenv('INID_ISSUER=https://id.local/');
        putenv('INID_APP_URL=https://app.local/');
        try {
            $config = Config::fromEnv(['scope' => 'openid email']);
            $this->assertSame('pk_test_env', $config->publishableKey);
            $this->assertSame('https://id.local', $config->issuer);
            $this->assertSame('https://app.local', $config->appUrl);
            $this->assertSame('/api/inid', $config->apiPath);
            $this->assertSame('openid email', $config->scope);
            $this->assertSame('pk_given', Config::fromEnv(['publishableKey' => 'pk_given'])->publishableKey);
        } finally {
            putenv('INID_PUBLISHABLE_KEY');
            putenv('INID_SECRET_KEY');
            putenv('INID_ISSUER');
            putenv('INID_APP_URL');
        }
        try {
            Config::fromEnv(['secretKey' => 'sk_x']);
            $this->fail('missing publishable key accepted');
        } catch (InIDException $e) {
            $this->assertStringContainsString('INID_PUBLISHABLE_KEY', $e->getMessage());
        }
        $this->expectExceptionMessage('INID_SECRET_KEY');
        new Config('pk_x', 'nope');
    }
}
