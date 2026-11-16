<?php

declare(strict_types=1);

namespace InID;

// Who is signed in, for a page or an API route
final class Auth implements \JsonSerializable
{
    public readonly bool $isSignedIn;
    public readonly ?string $userId;
    public readonly ?User $user;

    public function __construct(public readonly ?Session $session = null)
    {
        $this->isSignedIn = $session !== null;
        $this->user = $session?->user;
        $this->userId = $session?->user->id;
    }

    public function has(?string $role = null, ?string $permission = null): bool
    {
        return $this->user !== null && $this->user->has($role, $permission);
    }

    public function jsonSerialize(): array
    {
        return ['isSignedIn' => $this->isSignedIn, 'userId' => $this->userId, 'user' => $this->user];
    }
}
