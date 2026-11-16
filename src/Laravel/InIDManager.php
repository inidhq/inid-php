<?php

declare(strict_types=1);

namespace InID\Laravel;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use InID\AppApi;
use InID\Auth;
use InID\InID;
use InID\Session;
use InID\User;

// What InID::…, inid()->… and $request->inid() reach: who is signed in on the current request,
// the app API, webhooks, and the HTML for Blade
final class InIDManager
{
    public const AUTH = 'inid.auth';
    public const GATED = 'inid.gated';
    private const SCRIPT = 'inid.script';

    public function __construct(private readonly Container $app)
    {
    }

    public function core(): InID
    {
        return $this->app->make(InID::class);
    }

    /**
     * Who is signed in on this request: what the "inid" middleware found (renewed), or else read
     * from the cookies (no renewal outside the middleware).
     */
    public function auth(?Request $request = null): Auth
    {
        $request ??= $this->app->make('request');
        $auth = $request->attributes->get(self::AUTH);
        if (!$auth instanceof Auth) {
            $auth = $this->core()->auth(Bridge::request($request));
            $request->attributes->set(self::AUTH, $auth);
        }
        return $auth;
    }

    public function user(): ?User
    {
        return $this->auth()->user;
    }

    public function userId(): ?string
    {
        return $this->auth()->userId;
    }

    public function session(): ?Session
    {
        return $this->auth()->session;
    }

    public function isSignedIn(): bool
    {
        return $this->auth()->isSignedIn;
    }

    public function has(?string $role = null, ?string $permission = null): bool
    {
        return $this->auth()->has($role, $permission);
    }

    // A native app's caller, from "Authorization: Bearer <id_token>"
    public function bearer(?Request $request = null): Auth
    {
        $request ??= $this->app->make('request');
        return new Auth($this->core()->verifyBearer($request->header('authorization')));
    }

    /** @internal for the middleware */
    public function share(Request $request, Auth $auth, bool $gated = false): void
    {
        $request->attributes->set(self::AUTH, $auth);
        if ($gated) {
            $request->attributes->set(self::GATED, true);
        }
    }

    public function api(): AppApi
    {
        return $this->core()->api();
    }

    /**
     * The webhook's event, from the request (its raw body and InID-Signature header).
     * @throws \InID\InIDException invalid_signature
     */
    public function verifyWebhook(?Request $request = null): array
    {
        $request ??= $this->app->make('request');
        return $this->core()->verifyWebhook($request->getContent(), $request->header('InID-Signature'));
    }

    // ---------- Blade ----------

    /**
     * <inid-sign-in> with its attributes (appName → app-name, returnTo → return-to, entrance,
     * redirect), and the @inid/js script before it (once per page).
     */
    public function signIn(array $attributes = []): string
    {
        return $this->script() . $this->element('inid-sign-in', $attributes);
    }

    // @inid/js from the CDN, once per page
    public function script(): string
    {
        $request = $this->app->make('request');
        if ($request->attributes->get(self::SCRIPT)) {
            return '';
        }
        $request->attributes->set(self::SCRIPT, true);
        $src = (string) config('inid.script', 'https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js');
        return '<script src="' . e($src) . '"></script>';
    }

    public function element(string $tag, array $attributes = []): string
    {
        $apiPath = $this->core()->config->apiPath;
        if ($apiPath !== '/api/inid' && !array_key_exists('apiPath', $attributes)) {
            $attributes['apiPath'] = $apiPath;
        }
        $html = '<' . $tag;
        foreach ($attributes as $name => $value) {
            if ($value === null || $value === false) {
                continue;
            }
            $name = strtolower(preg_replace('/(?<!^)[A-Z]/', '-$0', (string) $name));
            $html .= $value === true ? ' ' . e($name) : ' ' . e($name) . '="' . e((string) $value) . '"';
        }
        return $html . '></' . $tag . '>';
    }
}
