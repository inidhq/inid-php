<?php

declare(strict_types=1);

namespace InID;

// An ID token InID signed for this app. An ended one still comes back (expired: true), so the
// session can be renewed from it; it never counts as signed in.
final class VerifiedToken
{
    public function __construct(
        public readonly array $claims,
        public readonly int $exp,
        public readonly bool $expired,
        public readonly string $token,
    ) {
    }

    public function session(): Session
    {
        return new Session(User::fromClaims($this->claims), $this->exp, $this->claims, $this->token);
    }
}
