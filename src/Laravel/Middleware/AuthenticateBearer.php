<?php

declare(strict_types=1);

namespace InID\Laravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use InID\InID;
use InID\Laravel\InIDManager;

// For a native app's backend (alias "inid.bearer"): "Authorization: Bearer <id_token>" must be
// a valid ID token for this app. inid.bearer:role,admin / inid.bearer:permission,x as with "inid".
final class AuthenticateBearer
{
    public function __construct(private readonly InIDManager $inid)
    {
    }

    public function handle(Request $request, Closure $next, string ...$params)
    {
        $auth = $this->inid->bearer($request);
        if (!$auth->user) {
            return response()->json(['error' => 'not_signed_in'], 401, ['www-authenticate' => 'Bearer']);
        }
        $rule = Authenticate::rule($params);
        if ($rule !== null && !InID::allows($auth->user, $rule)) {
            return response()->json(['error' => 'forbidden'], 403);
        }
        $this->inid->share($request, $auth);
        return $next($request);
    }
}
