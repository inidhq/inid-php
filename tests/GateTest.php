<?php

declare(strict_types=1);

namespace InID\Tests;

use InID\Cookie;
use InID\Tests\Support\FakeInID;

// 6. The gate
final class GateTest extends TestCase
{
    private const PROTECT = ['/dashboard', '#^/orgs/\d+/billing#', ['path' => '/admin', 'role' => 'admin', 'entrance' => 'team'], ['path' => '/invoices', 'permission' => 'invoices:read']];

    public function testAProtectedPathSendsToSignInWithReturnTo(): void
    {
        $gate = $this->inid->gate($this->request('GET', '/dashboard/reports?range=7d'), self::PROTECT);
        $this->assertSame(307, $gate->response?->status);
        $this->assertSame('https://app.test/api/inid/signin?return_to=%2Fdashboard%2Freports%3Frange%3D7d', $gate->response->header('location'));
        $this->assertFalse($gate->auth->isSignedIn);
    }

    public function testTheRuleEntranceGoesAlong(): void
    {
        $gate = $this->inid->gate($this->request('GET', '/admin'), self::PROTECT);
        $this->assertSame(['return_to' => '/admin', 'entrance' => 'team'], $this->query((string) $gate->response?->header('location')));
    }

    public function testSubpathsMatchButNotLookalikes(): void
    {
        $this->assertNotNull($this->inid->gate($this->request('GET', '/dashboard'), self::PROTECT)->response);
        $this->assertNotNull($this->inid->gate($this->request('GET', '/dashboard/x/y'), self::PROTECT)->response);
        $this->assertNull($this->inid->gate($this->request('GET', '/dashboardx'), self::PROTECT)->response);
        $this->assertNull($this->inid->gate($this->request('GET', '/'), self::PROTECT)->response);
    }

    public function testRegularExpressions(): void
    {
        $this->assertNotNull($this->inid->gate($this->request('GET', '/orgs/42/billing'), self::PROTECT)->response);
        $this->assertNull($this->inid->gate($this->request('GET', '/orgs/acme/billing'), self::PROTECT)->response);
    }

    public function testACallableDecides(): void
    {
        $protect = fn (\InID\Request $r) => str_starts_with($r->path(), '/app');
        $this->assertNotNull($this->inid->gate($this->request('GET', '/app/x'), $protect)->response);
        $this->assertNull($this->inid->gate($this->request('GET', '/home'), $protect)->response);
    }

    public function testSignedInWithoutTheRoleIsForbidden(): void
    {
        $cookies = [Cookie::SESSION => FakeInID::idToken(['roles' => ['member']])];
        $gate = $this->inid->gate($this->request('GET', '/admin/users', $cookies), self::PROTECT);
        $this->assertSame(403, $gate->response?->status);
        $this->assertSame('Forbidden', $gate->response->body);
        $this->assertTrue($gate->auth->isSignedIn);
    }

    public function testSignedInWithTheRoleOrPermissionGoesOn(): void
    {
        $cookies = [Cookie::SESSION => FakeInID::idToken(['roles' => ['admin'], 'permissions' => ['invoices:read']])];
        foreach (['/admin', '/invoices/7', '/dashboard'] as $path) {
            $gate = $this->inid->gate($this->request('GET', $path, $cookies), self::PROTECT);
            $this->assertNull($gate->response, $path);
            $this->assertSame('usr_1', $gate->auth->userId);
            $this->assertTrue($gate->auth->has(role: 'admin'));
        }
        $gate = $this->inid->gate($this->request('GET', '/invoices', [Cookie::SESSION => FakeInID::idToken(['permissions' => []])]), self::PROTECT);
        $this->assertSame(403, $gate->response?->status);
    }

    public function testAPathOnlyRuleLetsAnySignedInUserThrough(): void
    {
        $protect = [['path' => '/panel']];
        $gate = $this->inid->gate($this->request('GET', '/panel', [Cookie::SESSION => FakeInID::idToken(['roles' => [], 'permissions' => []])]), $protect);
        $this->assertNull($gate->response);
        $this->assertTrue($gate->auth->has());
        $this->assertSame(307, $this->inid->gate($this->request('GET', '/panel'), $protect)->response?->status);
    }

    public function testTheGateRenewsAndHandsBackTheCookies(): void
    {
        $renewed = FakeInID::idToken();
        $this->fake->tokens($renewed, 'rt_2');
        $gate = $this->inid->gate($this->request('GET', '/dashboard', [Cookie::SESSION => FakeInID::idToken(['exp' => time() + 10]), Cookie::REFRESH => 'rt_1']), self::PROTECT);
        $this->assertNull($gate->response);
        $this->assertCount(2, $gate->setCookies);
        $this->assertSame($renewed, Cookie::parse($gate->cookieHeader)[Cookie::SESSION]);
    }

    public function testRenewedCookiesGoBackWithA403Too(): void
    {
        $this->fake->tokens(FakeInID::idToken(['roles' => []]), 'rt_2');
        $gate = $this->inid->gate($this->request('GET', '/admin', [Cookie::SESSION => FakeInID::idToken(['exp' => time() + 10]), Cookie::REFRESH => 'rt_1']), self::PROTECT);
        $this->assertSame(403, $gate->response?->status);
        $this->assertCount(2, $gate->response->cookies);
    }

    public function testBackFromGoogleOnTheAppsDomainGoesOnToInID(): void
    {
        $gate = $this->inid->gate($this->request('GET', '/?state=inidg_abc&code=4%2F0A&scope=email'));
        $this->assertSame(307, $gate->response?->status);
        $this->assertSame(FakeInID::ISSUER . '/oauth/google/callback?state=inidg_abc&code=4%2F0A&scope=email', $gate->response->header('location'));
        $this->assertNotNull($this->inid->gate($this->request('GET', '/x?state=inidg_abc&error=access_denied'))->response);
        $this->assertNull($this->inid->gate($this->request('GET', '/?state=other&code=1'))->response);
        $this->assertNull($this->inid->gate($this->request('GET', '/?state=inidg_abc'))->response);
    }

    public function testTheApiPathIsAnsweredOrSkipped(): void
    {
        $this->assertSame(302, $this->inid->gate($this->request('GET', '/api/inid/signin'))->response?->status);
        $skipped = $this->inid->gate($this->request('GET', '/api/inid/signin'), null, false);
        $this->assertTrue($skipped->skipped);
        $this->assertNull($skipped->response);
    }
}
