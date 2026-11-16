<?php

declare(strict_types=1);

namespace InID;

use InID\Http\HttpClient;

// InID's API for the app's server, with the secret key: its users, their roles and metadata,
// its roles, invitations, sessions. Errors throw InIDException with InID's code and status.
final class AppApi
{
    public function __construct(private readonly Config $config, private readonly HttpClient $http)
    {
    }

    /** @return array{users: list<array>, total: int, next: ?string} */
    public function users(?string $search = null, ?string $before = null): array
    {
        $query = array_filter(['q' => $search, 'before' => $before], static fn ($v) => $v !== null);
        return $this->call('GET', '/v1/users' . ($query ? '?' . http_build_query($query) : ''));
    }

    // id, firstName, lastName, email, emailVerified, phone, role, authorizedAt, scopes, metadata
    public function user(string $sub): array
    {
        return $this->call('GET', '/v1/users/' . rawurlencode($sub));
    }

    // null: back to the role new users get
    public function setRole(string $sub, ?string $role): array
    {
        return $this->call('PUT', '/v1/users/' . rawurlencode($sub) . '/role', ['role' => $role]);
    }

    // Each one given replaces the previous one (8 KB at most); public travels in the ID token
    public function setMetadata(string $sub, ?array $public = null, ?array $private = null): array
    {
        $body = [];
        if ($public !== null) {
            $body['publicMetadata'] = (object) $public;
        }
        if ($private !== null) {
            $body['privateMetadata'] = (object) $private;
        }
        return $this->call('PATCH', '/v1/users/' . rawurlencode($sub) . '/metadata', (object) $body);
    }

    // roles: [{key, name, permissions}], defaultRole, entrances: [{key, name}]
    public function roles(): array
    {
        return $this->call('GET', '/v1/roles');
    }

    public function invite(string $email, ?string $role = null): array
    {
        return $this->call('POST', '/v1/invitations', array_filter(['email' => $email, 'role' => $role], static fn ($v) => $v !== null));
    }

    /**
     * Up to 200 at once: [['email' => ..., 'role' => ...], ...] → {invited, failed}
     * @param list<array{email: string, role?: string}> $invitations
     */
    public function inviteMany(array $invitations): array
    {
        return $this->call('POST', '/v1/invitations', ['invitations' => $invitations]);
    }

    /** @return list<array{id: string, createdAt: string, lastActiveAt: string, device: ?string}> */
    public function sessions(string $sub): array
    {
        return $this->call('GET', '/v1/users/' . rawurlencode($sub) . '/sessions')['sessions'] ?? [];
    }

    // One session (its sid), or all of them without one
    public function endSessions(string $sub, ?string $sid = null): int
    {
        $path = '/v1/users/' . rawurlencode($sub) . '/sessions' . ($sid !== null ? '/' . rawurlencode($sid) : '');
        return (int) ($this->call('DELETE', $path)['ended'] ?? 0);
    }

    // Any other endpoint of InID's API, with the secret key
    public function call(string $method, string $path, mixed $body = null): array
    {
        $headers = ['authorization' => 'Bearer ' . $this->config->secretKey, 'accept' => 'application/json'];
        if ($body !== null) {
            $headers['content-type'] = 'application/json';
        }
        try {
            $response = $this->http->request($method, $this->config->issuer . $path, $headers, $body === null ? null : json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        } catch (Http\NetworkException $e) {
            throw new InIDException('inid_unreachable', null, $e);
        }
        $data = $response->json();
        if (!$response->ok()) {
            throw new InIDException(is_string($data['error'] ?? null) ? $data['error'] : 'request_failed', $response->status);
        }
        return $data;
    }
}
