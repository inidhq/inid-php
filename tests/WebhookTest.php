<?php

declare(strict_types=1);

namespace InID\Tests;

use InID\InIDException;
use InID\Webhook;

// 7. Webhook signatures
final class WebhookTest extends TestCase
{
    private const BODY = '{"type":"user.updated","sub":"usr_1","created_at":"2026-11-16T10:00:00Z"}';

    private static function sign(string $body, int $at, string $secret = 'whsec_test'): string
    {
        return "t=$at,v1=" . hash_hmac('sha256', "$at.$body", $secret);
    }

    public function testAValidSignatureGivesTheEvent(): void
    {
        $event = $this->inid->verifyWebhook(self::BODY, self::sign(self::BODY, time()));
        $this->assertSame(['type' => 'user.updated', 'sub' => 'usr_1', 'created_at' => '2026-11-16T10:00:00Z'], $event);
    }

    public function testAnotherSecretIsRejected(): void
    {
        $this->expectRejected(fn () => $this->inid->verifyWebhook(self::BODY, self::sign(self::BODY, time(), 'whsec_other')));
    }

    public function testAChangedBodyIsRejected(): void
    {
        $this->expectRejected(fn () => $this->inid->verifyWebhook(str_replace('usr_1', 'usr_2', self::BODY), self::sign(self::BODY, time())));
    }

    public function testTooOldOrTooNewIsRejected(): void
    {
        $this->expectRejected(fn () => $this->inid->verifyWebhook(self::BODY, self::sign(self::BODY, time() - 301)));
        $this->expectRejected(fn () => $this->inid->verifyWebhook(self::BODY, self::sign(self::BODY, time() + 301)));
        $this->assertIsArray($this->inid->verifyWebhook(self::BODY, self::sign(self::BODY, 1000), 1200));
    }

    public function testMalformedHeadersAreRejected(): void
    {
        $at = time();
        $mac = hash_hmac('sha256', "$at." . self::BODY, 'whsec_test');
        foreach ([null, '', 'garbage', "v1=$mac", "t=$at", "t=,v1=$mac", "t=abc,v1=$mac", "t=$at,v1=zz"] as $header) {
            $this->expectRejected(fn () => $this->inid->verifyWebhook(self::BODY, $header), (string) $header);
        }
    }

    public function testWithoutASecretItSaysSo(): void
    {
        try {
            Webhook::verify(self::BODY, self::sign(self::BODY, time()), '');
            $this->fail('no secret accepted');
        } catch (InIDException $e) {
            $this->assertSame('webhook_secret_missing', $e->error);
        }
    }

    private function expectRejected(callable $verify, string $case = ''): void
    {
        try {
            $verify();
            $this->fail("accepted: $case");
        } catch (InIDException $e) {
            $this->assertSame('invalid_signature', $e->error, $case);
        }
    }
}
