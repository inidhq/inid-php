<?php

declare(strict_types=1);

namespace InID\Tests\Laravel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use InID\Cookie;
use InID\Http\HttpClient;
use InID\Jwks;
use InID\Laravel\Facades\InID;
use InID\Laravel\InIDServiceProvider;
use InID\Tests\Support\FakeInID;
use Orchestra\Testbench\TestCase;

final class LaravelTest extends TestCase
{
    private FakeInID $fake;

    protected function getPackageProviders($app): array
    {
        return [InIDServiceProvider::class];
    }

    protected function getPackageAliases($app): array
    {
        return ['InID' => InID::class];
    }

    protected function defineEnvironment($app): void
    {
        Jwks::forget();
        $this->fake = new FakeInID();
        $app->instance(HttpClient::class, $this->fake);
        $app['config']->set('inid.publishable_key', FakeInID::PK);
        $app['config']->set('inid.secret_key', FakeInID::SK);
        $app['config']->set('inid.issuer', FakeInID::ISSUER);
        $app['config']->set('inid.webhook_secret', 'whsec_test');
        $app['config']->set('inid.cache', 'array');
        $app['config']->set('inid.protect', ['/dashboard']);
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
    }

    protected function defineRoutes($router): void
    {
        $router->middleware('web')->group(function () use ($router) {
            $router->get('/', fn () => 'home ' . (InID::user()?->id ?? 'nobody'));
            $router->get('/dashboard', fn (Request $request) => 'dashboard ' . $request->inid()->userId);
            $router->get('/admin', fn () => 'admin ' . inid()->user()->id)->middleware('inid:role,admin');
            $router->get('/team', fn () => 'team')->middleware('inid:role,staff,entrance,team');
            $router->get('/reports', fn () => 'reports')->middleware('inid:permission,reports:read');
            $router->get('/account', fn () => 'account')->middleware('inid:auth');
            $router->get('/blade', fn () => Blade::render("@inidSignIn(['appName' => 'Mi App', 'returnTo' => '/panel'])\n@inidSignedIn signed-in @endInidSignedIn\n@inidSignedIn(['role' => 'admin']) is-admin @endInidSignedIn\n@inidSignedOut signed-out @endInidSignedOut\n@inidSignIn(['appName' => 'Again'])"));
        });
        $router->get('/api/me', fn () => response()->json(['id' => InID::userId()]))->middleware('inid.bearer');
        $router->get('/api/admin', fn () => 'ok')->middleware('inid.bearer:role,admin');
    }

    private function signedIn(array $claims = []): array
    {
        return ['Cookie' => Cookie::serialize([Cookie::SESSION => FakeInID::idToken($claims), Cookie::REFRESH => 'rt_1'])];
    }

    public function testRoutesAreRegisteredUnderTheApiPath(): void
    {
        $response = $this->get('/api/inid/signin?return_to=/dashboard');
        $response->assertStatus(302);
        $this->assertStringStartsWith(FakeInID::ISSUER . '/oauth/authorize?', $response->headers->get('location'));
        $this->assertCount(1, $response->headers->getCookies());
        $this->get('/api/inid/session')->assertExactJson(['user' => null, 'accountUrl' => FakeInID::ISSUER . '/account?client_id=' . FakeInID::PK]);
        $this->get('/api/inid/nope')->assertStatus(404);
    }

    public function testSignOutIsAPostWithoutCsrfAndClearsCookies(): void
    {
        $response = $this->post('/api/inid/signout', [], $this->signedIn());
        $response->assertOk()->assertExactJson(['ok' => true]);
        $cookies = [];
        foreach ($response->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = $cookie;
        }
        $this->assertTrue($cookies[Cookie::SESSION]->isCleared());
        $this->assertSame('1', $cookies[Cookie::SIGNED_OUT]->getValue());
        $this->assertStringContainsString('Max-Age=0', (string) $cookies[Cookie::REFRESH]);
    }

    public function testConfigProtectSendsToSignIn(): void
    {
        $this->get('/dashboard?x=1')->assertStatus(307)->assertHeader('location', 'http://localhost/api/inid/signin?return_to=%2Fdashboard%3Fx%3D1');
        $this->get('/dashboard', $this->signedIn())->assertOk()->assertSeeText('dashboard usr_1');
    }

    public function testFacadeAndHelperSeeTheUser(): void
    {
        $this->get('/')->assertSeeText('home nobody');
        $this->get('/', $this->signedIn())->assertSeeText('home usr_1');
    }

    public function testRouteMiddlewareRole(): void
    {
        $this->get('/admin')->assertStatus(307);
        $this->get('/admin', $this->signedIn(['roles' => ['member']]))->assertStatus(403);
        $this->get('/admin', $this->signedIn(['roles' => ['admin']]))->assertOk()->assertSeeText('admin usr_1');
    }

    public function testRouteMiddlewareEntranceAndPermission(): void
    {
        $location = $this->get('/team')->assertStatus(307)->headers->get('location');
        $this->assertStringEndsWith('return_to=%2Fteam&entrance=team', $location);
        $this->get('/reports', $this->signedIn(['permissions' => []]))->assertStatus(403);
        $this->get('/reports', $this->signedIn(['permissions' => ['reports:read']]))->assertOk();
        $this->get('/account')->assertStatus(307);
        $this->get('/account', $this->signedIn(['roles' => []]))->assertOk();
    }

    public function testTheWebGroupRenewsTheSessionAndSendsTheCookies(): void
    {
        $renewed = FakeInID::idToken();
        $this->fake->tokens($renewed, 'rt_2');
        $response = $this->get('/admin', ['Cookie' => Cookie::serialize([Cookie::SESSION => FakeInID::idToken(['exp' => time() + 10]), Cookie::REFRESH => 'rt_1'])]);
        // Not admin after renewal (member): 403, and still the renewed cookies
        $response->assertStatus(403);
        $values = [];
        foreach ($response->headers->getCookies() as $cookie) {
            $values[$cookie->getName()] = $cookie->getValue();
        }
        // Raw tokens, not encrypted by Laravel
        $this->assertSame($renewed, $values[Cookie::SESSION]);
        $this->assertSame('rt_2', $values[Cookie::REFRESH]);
        $this->assertCount(1, $this->fake->sent('POST', '/oauth/token'));
    }

    public function testBackFromGoogleGoesOnToInID(): void
    {
        $this->get('/?state=inidg_x&code=abc')->assertStatus(307)->assertHeader('location', FakeInID::ISSUER . '/oauth/google/callback?state=inidg_x&code=abc');
    }

    public function testBlade(): void
    {
        $html = $this->get('/blade')->getContent();
        $this->assertStringContainsString('<script src="https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js"></script><inid-sign-in app-name="Mi App" return-to="/panel"></inid-sign-in>', $html);
        $this->assertStringContainsString('signed-out', $html);
        $this->assertStringNotContainsString('signed-in', $html);
        $this->assertStringNotContainsString('is-admin', $html);
        // The script once per page
        $this->assertSame(1, substr_count($html, '<script'));

        $html = $this->get('/blade', $this->signedIn(['roles' => ['admin']]))->getContent();
        $this->assertStringContainsString('signed-in', $html);
        $this->assertStringContainsString('is-admin', $html);
        $this->assertStringNotContainsString('signed-out', $html);
    }

    public function testBearerMiddlewareForNativeApps(): void
    {
        $this->getJson('/api/me')->assertStatus(401)->assertExactJson(['error' => 'not_signed_in']);
        $this->getJson('/api/me', ['Authorization' => 'Bearer ' . FakeInID::idToken()])->assertOk()->assertExactJson(['id' => 'usr_1']);
        $this->getJson('/api/admin', ['Authorization' => 'Bearer ' . FakeInID::idToken()])->assertStatus(403);
        $this->getJson('/api/admin', ['Authorization' => 'Bearer ' . FakeInID::idToken(['roles' => ['admin']])])->assertOk();
    }

    public function testWebhookFromTheRequest(): void
    {
        $body = '{"type":"session.ended","sub":"usr_1","sid":"ses_1","created_at":"2026-11-16T00:00:00Z"}';
        $at = time();
        Route::post('/hooks/inid', fn () => response()->json(InID::verifyWebhook()));
        $this->call('POST', '/hooks/inid', [], [], [], ['HTTP_INID_SIGNATURE' => "t=$at,v1=" . hash_hmac('sha256', "$at.$body", 'whsec_test'), 'CONTENT_TYPE' => 'application/json'], $body)
            ->assertOk()->assertJson(['type' => 'session.ended', 'sid' => 'ses_1']);
    }
}
