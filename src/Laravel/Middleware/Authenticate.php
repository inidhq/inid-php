<?php

declare(strict_types=1);

namespace InID\Laravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use InID\Laravel\Bridge;
use InID\Laravel\InIDManager;

// The gate, as Laravel middleware (alias "inid"):
//   inid                         renews the session and shares who is signed in
//   inid:auth                    and someone must be signed in
//   inid:role,admin              with that role (inid:permission,invoices:read for a permission)
//   inid:role,staff,entrance,team   signing in through that entrance
final class Authenticate
{
    public function __construct(private readonly InIDManager $inid)
    {
    }

    public function handle(Request $request, Closure $next, string ...$params)
    {
        $core = $this->inid->core();
        $bridged = Bridge::request($request);
        $cookies = [];
        // Once per request, even when it runs from the web group and again on a route
        if (!$request->attributes->get(InIDManager::GATED)) {
            $gate = $core->gate($bridged, config('inid.protect') ?: null, false);
            if ($gate->skipped) {
                return $next($request);
            }
            if ($gate->response) {
                return Bridge::response($gate->response);
            }
            $this->inid->share($request, $gate->auth, gated: true);
            if ($gate->cookieHeader !== null) {
                // The rest of this request sees the renewed session too
                $request->headers->set('cookie', $gate->cookieHeader);
            }
            $cookies = $gate->setCookies;
        }

        $rule = self::rule($params);
        if ($rule !== null) {
            $denied = $core->enforce($bridged, $this->inid->auth($request), [$rule]);
            if ($denied) {
                return Bridge::response($denied->withCookies($cookies));
            }
        }
        return Bridge::withCookies($next($request), $cookies);
    }

    /** inid:role,admin,entrance,team → ['path' => '/', 'role' => 'admin', 'entrance' => 'team'] */
    public static function rule(array $params): ?array
    {
        if (!$params) {
            return null;
        }
        $rule = ['path' => '/'];
        for ($i = 0; $i < count($params); $i++) {
            $key = trim($params[$i]);
            if ($key === 'auth') {
                continue;
            }
            if (!in_array($key, ['role', 'permission', 'entrance'], true) || !isset($params[$i + 1])) {
                throw new \InvalidArgumentException("inid middleware: expected auth, role,<role>, permission,<permission> or entrance,<entrance>; got \"$key\"");
            }
            $rule[$key] = trim($params[++$i]);
        }
        return $rule;
    }
}
