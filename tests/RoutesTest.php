<?php

declare(strict_types=1);

namespace InID\Tests;

use InID\Base64Url;
use InID\Cookie;
use InID\Http\HttpResponse;
use InID\Response;
use InID\Tests\Support\FakeInID;

final class RoutesTest extends TestCase
{
    private function signIn(string $query = '', array $cookies = []): Response
    {
        return $this->inid->handle($this->request('GET', '/api/inid/signin' . $query, $cookies));
    }

    private function flowOf(Response $response): array
    {
        foreach ($response->cookies as $cookie) {
            if (str_starts_with($cookie->name, Cookie::FLOW . '_')) {
                return json_decode(Base64Url::decode($cookie->value), true);
            }
        }
        $this->fail('no flow cookie');
    }

    // ---------- 1. signin ----------

    public function testSignInRedirectsToInIDWithEveryParameterAndPkce(): void
    {
        $response = $this->signIn('?return_to=/dashboard%3Ftab%3D1&ui_locales=es&login_hint=ana@example.com&entrance=team');
        $this->assertSame(302, $response->status);
        $this->assertSame('no-store', $response->header('cache-control'));
        $location = (string) $response->header('location');
        $this->assertStringStartsWith(FakeInID::ISSUER . '/oauth/authorize?', $location);
        $query = $this->query($location);
        $flow = $this->flowOf($response);

        $this->assertSame(FakeInID::PK, $query['client_id']);
        $this->assertSame('https://app.test/api/inid/callback', $query['redirect_uri']);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('openid profile email phone', $query['scope']);
        $this->assertSame($flow['state'], $query['state']);
        $this->assertSame($flow['nonce'], $query['nonce']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame(Base64Url::encode(hash('sha256', $flow['verifier'], true)), $query['code_challenge']);
        $this->assertSame('es', $query['ui_locales']);
        $this->assertSame('ana@example.com', $query['login_hint']);
        $this->assertSame('team', $query['entrance']);
        $this->assertArrayNotHasKey('prompt', $query);
        $this->assertArrayNotHasKey('display', $query);
        $this->assertSame('/dashboard?tab=1', $flow['returnTo']);
        $this->assertSame(22, strlen($flow['state']));
        $this->assertSame(43, strlen($flow['verifier']));

        $cookie = $this->cookies($response)[Cookie::FLOW . '_' . $flow['state']];
        $this->assertSame('/api/inid', $cookie->path);
        $this->assertSame(600, $cookie->maxAge);
        $line = (string) $cookie;
        $this->assertStringContainsString('HttpOnly; SameSite=Lax; Secure', $line);
    }

    public function testSignInSanitizesReturnTo(): void
    {
        foreach (['https://evil.test', '//evil.test', '/\\evil.test', 'dashboard'] as $bad) {
            $this->assertSame('/', $this->flowOf($this->signIn('?return_to=' . rawurlencode($bad)))['returnTo'], $bad);
        }
        $this->assertSame('/', $this->flowOf($this->signIn())['returnTo']);
    }

    public function testSignInAsksAgainAfterSigningOut(): void
    {
        $query = $this->query((string) $this->signIn('', [Cookie::SIGNED_OUT => '1'])->header('location'));
        $this->assertSame('login', $query['prompt']);
    }

    public function testEmbeddedSignInAddsDisplayEmbedAndPromptLogin(): void
    {
        $response = $this->signIn('?display=embed&return_to=/panel&page=/entrar&prompt=none');
        $query = $this->query((string) $response->header('location'));
        $this->assertSame('embed', $query['display']);
        $this->assertSame('login', $query['prompt']);
        $flow = $this->flowOf($response);
        $this->assertTrue($flow['embed']);
        $this->assertSame('/entrar', $flow['page']);
        $this->assertSame('/panel', $flow['returnTo']);
    }

    public function testEmbeddedResumeAfterGoogle(): void
    {
        $continue = http_build_query(['request' => 'req_1', 'session' => 's', 'from' => 'google', 'lang' => 'es', 'evil' => 'x']);
        $response = $this->signIn('?display=embed&continue=' . rawurlencode($continue));
        $location = (string) $response->header('location');
        $this->assertStringStartsWith(FakeInID::ISSUER . '/oauth/authorize/continue?', $location);
        $this->assertSame(['request' => 'req_1', 'session' => 's', 'from' => 'google', 'lang' => 'es', 'display' => 'embed'], $this->query($location));
        $this->assertSame([], $response->cookies);
    }

    public function testCookiesAreNotSecureOnHttp(): void
    {
        $response = $this->inid->handle(new \InID\Request('GET', 'http://localhost:8000/api/inid/signin'));
        $this->assertStringNotContainsString('Secure', $response->setCookieHeaders()[0]);
        $this->assertSame('http://localhost:8000/api/inid/callback', $this->query((string) $response->header('location'))['redirect_uri']);
    }

    // ---------- 2. callback ----------

    private function startedFlow(string $query = '?return_to=/panel'): array
    {
        $response = $this->signIn($query);
        $flow = $this->flowOf($response);
        return [$flow, [Cookie::FLOW . '_' . $flow['state'] => $this->cookies($response)[Cookie::FLOW . '_' . $flow['state']]->value]];
    }

    public function testCallbackExchangesTheCodeAndSetsTheSession(): void
    {
        [$flow, $cookies] = $this->startedFlow();
        $idToken = FakeInID::idToken(['nonce' => $flow['nonce']]);
        $this->fake->tokens($idToken, 'rt_1');

        $response = $this->inid->handle($this->request('GET', '/api/inid/callback?code=c_1&state=' . $flow['state'], $cookies + [Cookie::SIGNED_OUT => '1']));

        $this->assertSame(302, $response->status);
        $this->assertSame('/panel', $response->header('location'));
        $sent = $this->fake->sent('POST', '/oauth/token')[0];
        $this->assertSame('Basic ' . base64_encode(FakeInID::PK . ':' . FakeInID::SK), $sent['headers']['authorization']);
        parse_str($sent['body'], $form);
        $this->assertSame(['grant_type' => 'authorization_code', 'code' => 'c_1', 'redirect_uri' => 'https://app.test/api/inid/callback', 'code_verifier' => $flow['verifier']], $form);

        $set = $this->cookies($response);
        $this->assertSame($idToken, $set[Cookie::SESSION]->value);
        $this->assertSame(30 * 86400, $set[Cookie::SESSION]->maxAge);
        $this->assertSame('rt_1', $set[Cookie::REFRESH]->value);
        $this->assertSame(0, $set[Cookie::SIGNED_OUT]->maxAge);
        $this->assertSame(0, $set[Cookie::FLOW . '_' . $flow['state']]->maxAge);
    }

    public function testCallbackRejectsAnotherNonce(): void
    {
        [$flow, $cookies] = $this->startedFlow();
        $this->fake->tokens(FakeInID::idToken(['nonce' => 'someone-else']));
        $response = $this->inid->handle($this->request('GET', '/api/inid/callback?code=c_1&state=' . $flow['state'], $cookies));
        $this->assertSame(400, $response->status);
        $this->assertArrayNotHasKey(Cookie::SESSION, $this->cookies($response));
    }

    public function testCallbackWithAnotherStateGoesHomeWithoutExchanging(): void
    {
        [, $cookies] = $this->startedFlow();
        $response = $this->inid->handle($this->request('GET', '/api/inid/callback?code=c_1&state=other', $cookies));
        $this->assertSame(302, $response->status);
        $this->assertSame('/', $response->header('location'));
        $this->assertSame([], $this->fake->sent('POST', '/oauth/token'));
        $this->assertSame(0, $this->cookies($response)[Cookie::FLOW . '_other']->maxAge);
    }

    public function testCallbackWithoutCodeGoesToReturnTo(): void
    {
        [$flow, $cookies] = $this->startedFlow();
        $response = $this->inid->handle($this->request('GET', '/api/inid/callback?error=access_denied&state=' . $flow['state'], $cookies));
        $this->assertSame('/panel', $response->header('location'));
    }

    public function testEmbeddedCallbackLeavesTheFrame(): void
    {
        [$flow, $cookies] = $this->startedFlow('?display=embed&return_to=/panel</script>');
        $this->fake->tokens(FakeInID::idToken(['nonce' => $flow['nonce']]));
        $response = $this->inid->handle($this->request('GET', '/api/inid/callback?code=c_1&state=' . $flow['state'], $cookies));
        $this->assertSame(200, $response->status);
        $this->assertSame('text/html; charset=utf-8', $response->header('content-type'));
        $this->assertSame('<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace("/panel' . '\\' . 'u003c/script>")</script>', $response->body);
        $this->assertArrayHasKey(Cookie::SESSION, $this->cookies($response));
    }

    public function testEmbeddedCallbackFromGoogleGoesBackToThePage(): void
    {
        [$flow, $cookies] = $this->startedFlow('?display=embed&return_to=/panel&page=/entrar%3Fx%3D1');
        $response = $this->inid->handle($this->request('GET', '/api/inid/callback?inid_continue=abc&state=' . $flow['state'], $cookies));
        $this->assertSame('/entrar?x=1&inid_continue=abc', $response->header('location'));
    }

    // ---------- 4. signout ----------

    public function testSignOutRevokesClearsAndRemembers(): void
    {
        $response = $this->inid->handle($this->request('POST', '/api/inid/signout', [Cookie::SESSION => FakeInID::idToken(), Cookie::REFRESH => 'rt_1']));
        $this->assertSame(200, $response->status);
        $this->assertSame('{"ok":true}', $response->body);
        $this->assertSame('no-store', $response->header('cache-control'));
        $revoke = $this->fake->sent('POST', '/oauth/revoke')[0];
        parse_str($revoke['body'], $form);
        $this->assertSame(['token' => 'rt_1', 'token_type_hint' => 'refresh_token'], $form);
        $this->assertStringStartsWith('Basic ', $revoke['headers']['authorization']);
        $set = $this->cookies($response);
        $this->assertSame(0, $set[Cookie::SESSION]->maxAge);
        $this->assertSame(0, $set[Cookie::REFRESH]->maxAge);
        $this->assertSame('1', $set[Cookie::SIGNED_OUT]->value);
        $this->assertSame(30 * 86400, $set[Cookie::SIGNED_OUT]->maxAge);
    }

    public function testSignOutWorksWhenInIDIsDown(): void
    {
        $this->fake->down = true;
        $response = $this->inid->handle($this->request('POST', '/api/inid/signout', [Cookie::REFRESH => 'rt_1']));
        $this->assertSame(200, $response->status);
        $this->assertSame('1', $this->cookies($response)[Cookie::SIGNED_OUT]->value);
    }

    // ---------- 5. /session ----------

    public function testSessionRouteAnswersTheUserInCamelCase(): void
    {
        $token = FakeInID::idToken(['public_metadata' => ['plan' => 'pro']]);
        $response = $this->inid->handle($this->request('GET', '/api/inid/session', [Cookie::SESSION => $token]));
        $this->assertSame(200, $response->status);
        $this->assertSame('no-store', $response->header('cache-control'));
        $this->assertSame([
            'user' => [
                'id' => 'usr_1',
                'firstName' => 'Ana',
                'lastName' => 'Gómez',
                'name' => 'Ana Gómez',
                'email' => 'ana@example.com',
                'emailVerified' => true,
                'phone' => '+573001234567',
                'roles' => ['member'],
                'permissions' => ['invoices:read'],
                'publicMetadata' => ['plan' => 'pro'],
            ],
            'accountUrl' => FakeInID::ISSUER . '/account?client_id=' . FakeInID::PK,
        ], json_decode($response->body, true));
    }

    public function testSessionRouteSignedOut(): void
    {
        $response = $this->inid->handle($this->request('GET', '/api/inid/session'));
        $this->assertSame(['user' => null, 'accountUrl' => FakeInID::ISSUER . '/account?client_id=' . FakeInID::PK], json_decode($response->body, true));
    }

    public function testSessionRouteWritesEmptyMetadataAsAnObject(): void
    {
        $response = $this->inid->handle($this->request('GET', '/api/inid/session', [Cookie::SESSION => FakeInID::idToken(['given_name' => null, 'family_name' => null, 'name' => 'Ana'])]));
        $this->assertStringContainsString('"publicMetadata":{}', $response->body);
        $this->assertSame('Ana', json_decode($response->body, true)['user']['name']);
    }

    public function testSessionRouteRenewsANearlyEndedSession(): void
    {
        $renewed = FakeInID::idToken(['exp' => time() + 600]);
        $this->fake->tokens($renewed, 'rt_2');
        $response = $this->inid->handle($this->request('GET', '/api/inid/session', [Cookie::SESSION => FakeInID::idToken(['exp' => time() + 30]), Cookie::REFRESH => 'rt_1']));
        $this->assertSame('usr_1', json_decode($response->body, true)['user']['id']);
        $this->assertSame($renewed, $this->cookies($response)[Cookie::SESSION]->value);
    }

    // ---------- sessions ----------

    public function testSessionsListsAndMarksTheCurrentOne(): void
    {
        $this->fake->routes['GET /v1/users/usr_1/sessions'] = new HttpResponse(200, json_encode(['sessions' => [
            ['id' => 'ses_current', 'createdAt' => '2026-01-01', 'lastActiveAt' => '2026-01-02', 'device' => 'Mac'],
            ['id' => 'ses_other', 'createdAt' => '2026-01-01', 'lastActiveAt' => '2026-01-02', 'device' => null],
        ]]));
        $response = $this->inid->handle($this->request('GET', '/api/inid/sessions', [Cookie::SESSION => FakeInID::idToken()]));
        $body = json_decode($response->body, true);
        $this->assertTrue($body['sessions'][0]['current']);
        $this->assertFalse($body['sessions'][1]['current']);
        $this->assertSame('Bearer ' . FakeInID::SK, $this->fake->sent('GET', '/v1/users/usr_1/sessions')[0]['headers']['authorization']);
    }

    public function testSessionsEndsOthersOrOne(): void
    {
        $this->fake->routes['GET /v1/users/usr_1/sessions'] = new HttpResponse(200, json_encode(['sessions' => [['id' => 'ses_current'], ['id' => 'ses_a'], ['id' => 'ses_b']]]));
        $this->fake->routes['DELETE /v1/users/usr_1/sessions/ses_a'] = new HttpResponse(200, '{"ended":1}');
        $this->fake->routes['DELETE /v1/users/usr_1/sessions/ses_b'] = new HttpResponse(200, '{"ended":1}');
        $cookies = [Cookie::SESSION => FakeInID::idToken()];
        $this->assertSame('{"ended":2}', $this->inid->handle($this->request('DELETE', '/api/inid/sessions?others=1', $cookies))->body);
        $this->assertSame('{"ended":1}', $this->inid->handle($this->request('DELETE', '/api/inid/sessions/ses_a', $cookies))->body);
        $this->assertCount(2, $this->fake->sent('DELETE', '/v1/users/usr_1/sessions/ses_a'));
        $this->assertCount(1, $this->fake->sent('DELETE', '/v1/users/usr_1/sessions/ses_b'));
    }

    public function testSessionsNeedsSomeoneSignedIn(): void
    {
        $response = $this->inid->handle($this->request('GET', '/api/inid/sessions'));
        $this->assertSame(401, $response->status);
        $this->assertSame('{"error":"not_signed_in"}', $response->body);
    }

    public function testAnythingElseIsNotFound(): void
    {
        foreach ([['GET', '/api/inid/nope'], ['POST', '/api/inid/signin'], ['GET', '/api/inid/signout']] as [$method, $path]) {
            $response = $this->inid->handle($this->request($method, $path));
            $this->assertSame(404, $response->status);
            $this->assertSame('{"error":"not_found"}', $response->body);
        }
    }
}
