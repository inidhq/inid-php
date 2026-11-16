<?php

declare(strict_types=1);

namespace InID\Tests;

use InID\Http\HttpResponse;
use InID\InIDException;
use InID\Tests\Support\FakeInID;

final class AppApiTest extends TestCase
{
    public function testCallsCarryTheSecretKeyAndJson(): void
    {
        $this->fake->routes['PUT /v1/users/usr_1/role'] = new HttpResponse(200, '{"id":"usr_1","role":"admin"}');
        $this->fake->routes['PATCH /v1/users/usr_1/metadata'] = new HttpResponse(200, '{}');
        $this->fake->routes['POST /v1/invitations'] = new HttpResponse(200, '{"invited":1}');
        $this->fake->routes['GET /v1/roles'] = new HttpResponse(200, '{"roles":[{"key":"admin"}],"defaultRole":"member"}');
        $api = $this->inid->api();

        $this->assertSame(['id' => 'usr_1', 'role' => 'admin'], $api->setRole('usr_1', 'admin'));
        $sent = $this->fake->sent('PUT', '/v1/users/usr_1/role')[0];
        $this->assertSame('Bearer ' . FakeInID::SK, $sent['headers']['authorization']);
        $this->assertSame('{"role":"admin"}', $sent['body']);

        $api->setMetadata('usr_1', public: []);
        $this->assertSame('{"publicMetadata":{}}', $this->fake->sent('PATCH', '/v1/users/usr_1/metadata')[0]['body']);
        $api->invite('ana@example.com', 'admin');
        $this->assertSame('{"email":"ana@example.com","role":"admin"}', $this->fake->sent('POST', '/v1/invitations')[0]['body']);
        $this->assertSame('member', $api->roles()['defaultRole']);
    }

    public function testErrorsCarryInIDsCodeAndStatus(): void
    {
        $this->fake->routes['GET /v1/users/nobody'] = new HttpResponse(404, '{"error":"user_not_found"}');
        try {
            $this->inid->api()->user('nobody');
            $this->fail('no error');
        } catch (InIDException $e) {
            $this->assertSame('user_not_found', $e->error);
            $this->assertSame(404, $e->status);
        }
    }
}
