<?php

declare(strict_types=1);

namespace InID;

final class Session
{
    public function __construct(
        public readonly User $user,
        // When this session's token ends (unix seconds); renewed before then
        public readonly int $expiresAt,
        public readonly array $claims,
        // The ID token itself (to call the app's own APIs with it, for instance)
        public readonly string $idToken = '',
    ) {
    }

    // InID's id for this sign-in (each sign-in, in each browser), when the token has one
    public function id(): ?string
    {
        return is_string($this->claims['sid'] ?? null) ? $this->claims['sid'] : null;
    }
}
