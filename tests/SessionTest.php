<?php

declare(strict_types=1);

namespace InID\Tests;

use InID\Cookie;
use InID\Http\HttpResponse;
use InID\Tests\Support\FakeInID;

// 3. Reading the session, and renewing it before it ends
final class SessionTest extends TestCase
{
    public function testAValidSessionNeedsNoCallToInIDBeyondItsKeys(): void
    {
        $result = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(), Cookie::REFRESH => 'rt_1']), true);
        $this->assertSame('usr_1', $result->session?->user->id);
        $this->assertSame([], $result->setCookies);
        $this->assertSame([], $this->fake->sent('POST', '/oauth/token'));
    }

    public function testNearExpiryItRenewsWithTheRefreshToken(): void
    {
        $renewed = FakeInID::idToken(['exp' => time() + 600, 'given_name' => 'Ana María']);
        $this->fake->tokens($renewed, 'rt_2');
        $result = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() + 30]), Cookie::REFRESH => 'rt_1', 'other' => 'x']), true);

        $this->assertSame('Ana María', $result->session?->user->firstName);
        $sent = $this->fake->sent('POST', '/oauth/token')[0];
        parse_str($sent['body'], $form);
        $this->assertSame(['grant_type' => 'refresh_token', 'refresh_token' => 'rt_1'], $form);
        $this->assertStringStartsWith('Basic ', $sent['headers']['authorization']);

        $set = [];
        foreach ($result->setCookies as $cookie) {
            $set[$cookie->name] = $cookie->value;
        }
        $this->assertSame([Cookie::SESSION => $renewed, Cookie::REFRESH => 'rt_2'], $set);
        // The same request sees the renewed session
        $this->assertSame([Cookie::SESSION => $renewed, Cookie::REFRESH => 'rt_2', 'other' => 'x'], Cookie::parse($result->cookieHeader));
    }

    public function testAnExpiredSessionIsRenewedToo(): void
    {
        $this->fake->tokens(FakeInID::idToken());
        $result = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() - 100]), Cookie::REFRESH => 'rt_1']), true);
        $this->assertNotNull($result->session);
    }

    public function testWithoutRefreshAllowedItIsNotRenewed(): void
    {
        $result = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() + 30]), Cookie::REFRESH => 'rt_1']));
        $this->assertNotNull($result->session);
        $this->assertSame([], $this->fake->sent('POST', '/oauth/token'));
        $expired = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() - 1])]));
        $this->assertNull($expired->session);
    }

    public function testA4xxFromInIDEndsTheSession(): void
    {
        $this->fake->routes['POST /oauth/token'] = new HttpResponse(400, '{"error":"invalid_grant"}');
        $result = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() + 30]), Cookie::REFRESH => 'rt_1', 'other' => 'x']), true);
        $this->assertNull($result->session);
        $cleared = [];
        foreach ($result->setCookies as $cookie) {
            $cleared[$cookie->name] = $cookie->maxAge;
        }
        $this->assertSame([Cookie::SESSION => 0, Cookie::REFRESH => 0], $cleared);
        $this->assertSame('other=x', $result->cookieHeader);
    }

    public function testANetworkErrorKeepsWhatIsStillValid(): void
    {
        $token = FakeInID::idToken(['exp' => time() + 30]);
        // The keys are fetched first; then InID goes away
        $this->inid->verifyIdToken($token);
        $this->fake->down = true;
        $result = $this->inid->session(Cookie::serialize([Cookie::SESSION => $token, Cookie::REFRESH => 'rt_1']), true);
        $this->assertSame('usr_1', $result->session?->user->id);
        $this->assertSame([], $result->setCookies);
    }

    public function testA5xxKeepsWhatIsStillValidButNotWhatEnded(): void
    {
        $this->fake->routes['POST /oauth/token'] = new HttpResponse(503, '');
        $valid = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() + 30]), Cookie::REFRESH => 'rt_1']), true);
        $this->assertNotNull($valid->session);
        $ended = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() - 5]), Cookie::REFRESH => 'rt_1']), true);
        $this->assertNull($ended->session);
        $this->assertSame([], $ended->setCookies);
    }

    public function testUserAndHas(): void
    {
        $user = $this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['roles' => ['admin', 3], 'permissions' => ['x']])]))->session->user;
        $this->assertSame(['admin'], $user->roles);
        $this->assertTrue($user->has(role: 'admin'));
        $this->assertTrue($user->has(permission: 'x'));
        $this->assertTrue($user->has('admin', 'x'));
        $this->assertFalse($user->has('admin', 'y'));
        $this->assertFalse($user->has('member'));
        // Neither asked: true when signed in, false when not
        $this->assertTrue($user->has());
        $this->assertTrue((new \InID\Auth($this->inid->session(Cookie::serialize([Cookie::SESSION => FakeInID::idToken()]))->session))->has());
        $this->assertFalse((new \InID\Auth())->has());
        $this->assertFalse((new \InID\Auth())->has(role: 'admin'));
    }
}
