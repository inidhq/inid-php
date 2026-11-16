<?php

declare(strict_types=1);

namespace InID;

// The person signed in, from InID's ID token. JSON in camelCase, like every InID SDK.
final class User implements \JsonSerializable
{
    /**
     * @param list<string> $roles
     * @param list<string> $permissions
     * @param array<string, mixed> $publicMetadata
     */
    public function __construct(
        // The person's id at this app (InID gives each app its own)
        public readonly string $id,
        public readonly ?string $firstName = null,
        public readonly ?string $lastName = null,
        public readonly ?string $name = null,
        public readonly ?string $email = null,
        public readonly bool $emailVerified = false,
        // E.164
        public readonly ?string $phone = null,
        public readonly array $roles = [],
        public readonly array $permissions = [],
        public readonly array $publicMetadata = [],
    ) {
    }

    public static function fromClaims(array $claims): self
    {
        $text = static fn (mixed $v): ?string => is_string($v) && $v !== '' ? $v : null;
        $strings = static fn (mixed $v): array => is_array($v) ? array_values(array_filter($v, 'is_string')) : [];
        $firstName = $text($claims['given_name'] ?? null);
        $lastName = $text($claims['family_name'] ?? null);
        $metadata = $claims['public_metadata'] ?? null;
        // A JSON object decodes to an associative array; a JSON list isn't metadata
        $metadata = is_array($metadata) && ($metadata === [] || !array_is_list($metadata)) ? $metadata : [];
        return new self(
            id: (string) $claims['sub'],
            firstName: $firstName,
            lastName: $lastName,
            name: implode(' ', array_filter([$firstName, $lastName])) ?: $text($claims['name'] ?? null),
            email: $text($claims['email'] ?? null),
            emailVerified: ($claims['email_verified'] ?? null) === true,
            phone: $text($claims['phone_number'] ?? null),
            roles: $strings($claims['roles'] ?? null),
            permissions: $strings($claims['permissions'] ?? null),
            publicMetadata: $metadata,
        );
    }

    // has(role: 'admin'), has(permission: 'invoices:read'); both must hold when both are given;
    // with neither, true (someone is signed in, nothing more is asked)
    public function has(?string $role = null, ?string $permission = null): bool
    {
        if ($role !== null && !in_array($role, $this->roles, true)) {
            return false;
        }
        return $permission === null || in_array($permission, $this->permissions, true);
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'firstName' => $this->firstName,
            'lastName' => $this->lastName,
            'name' => $this->name,
            'email' => $this->email,
            'emailVerified' => $this->emailVerified,
            'phone' => $this->phone,
            'roles' => $this->roles,
            'permissions' => $this->permissions,
            // {} rather than [] when empty
            'publicMetadata' => (object) $this->publicMetadata,
        ];
    }
}
