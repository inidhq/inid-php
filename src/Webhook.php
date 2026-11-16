<?php

declare(strict_types=1);

namespace InID;

// InID-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>
final class Webhook
{
    public const TOLERANCE_SECONDS = 300;

    /**
     * The event, from the body exactly as received (before any JSON parsing). Event types:
     * user.created, user.updated, user.deleted (may carry token), session.created,
     * session.ended (carries sid), subscription.cancel_requested, customer.logged_out,
     * customer.registered, checkout.abandoned. Every one has type, created_at, and sub or token.
     *
     * @throws InIDException invalid_signature when it isn't InID's (or is too old)
     */
    public static function verify(string $rawBody, ?string $signature, string $secret, ?int $now = null): array
    {
        if ($secret === '') {
            throw new InIDException('webhook_secret_missing');
        }
        $now ??= time();
        $parts = [];
        foreach (explode(',', (string) $signature) as $part) {
            [$key, $value] = array_pad(explode('=', trim($part), 2), 2, '');
            $parts[$key] = $value;
        }
        $at = ctype_digit($parts['t'] ?? '') ? (int) $parts['t'] : 0;
        $given = $parts['v1'] ?? '';
        if ($at === 0 || $given === '' || abs($now - $at) > self::TOLERANCE_SECONDS) {
            throw new InIDException('invalid_signature');
        }
        $expected = hash_hmac('sha256', $at . '.' . $rawBody, $secret);
        if (!hash_equals($expected, strtolower($given))) {
            throw new InIDException('invalid_signature');
        }
        $event = json_decode($rawBody, true);
        if (!is_array($event)) {
            throw new InIDException('invalid_body');
        }
        return $event;
    }
}
