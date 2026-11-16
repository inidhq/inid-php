<?php

declare(strict_types=1);

namespace InID;

use InID\Http\DefaultHttpClient;
use InID\Http\HttpClient;
use InID\Http\NetworkException;

// Sign-in with InID for an app's server. The app is an OpenID Connect client of InID (its
// publishable key is the client id, its secret key the client secret). Signing in is the
// authorization code flow with PKCE; the session is InID's signed ID token in a cookie,
// checked with InID's public keys, never with a call to InID. It lasts ten minutes; the
// refresh token (another cookie) renews it.
//
//   $inid = InID::fromEnv();                                  // INID_PUBLISHABLE_KEY, INID_SECRET_KEY
//   $gate = $inid->gate(Request::fromGlobals(), ['/dashboard', ['path' => '/admin', 'role' => 'admin']]);
//   if ($gate->response) { $gate->response->send(); exit; }  // InID's routes, a sign-in, a 403
//   ...the page, with $gate->auth->user; send $gate->setCookies with it
final class InID
{
    // A session with less than this left is renewed now, not in the middle of the next request
    private const RENEW_BEFORE_SECONDS = 60;
    private const COOKIE_MAX_AGE = 30 * 86400;
    private const FLOW_MAX_AGE = 600;

    public readonly HttpClient $http;
    private readonly Jwks $jwks;

    public function __construct(
        public readonly Config $config,
        ?HttpClient $http = null,
        ?\Psr\SimpleCache\CacheInterface $cache = null,
    ) {
        $this->http = $http ?? new DefaultHttpClient();
        $this->jwks = new Jwks($this->http, $cache);
    }

    /** Keys and settings from the environment unless given (see Config::fromEnv) */
    public static function fromEnv(array $config = [], ?HttpClient $http = null, ?\Psr\SimpleCache\CacheInterface $cache = null): self
    {
        return new self(Config::fromEnv($config), $http, $cache);
    }

    public function api(): AppApi
    {
        return new AppApi($this->config, $this->http);
    }

    // ---------- tokens ----------

    /** @throws InIDException only when InID's keys can't be had (InID answered with an error) */
    public function verifyIdToken(string $token, ?string $nonce = null, ?int $now = null): ?VerifiedToken
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        try {
            $header = json_decode(Base64Url::decode($parts[0]), true);
            if (!is_array($header) || ($header['alg'] ?? null) !== 'RS256' || !is_string($header['kid'] ?? null)) {
                return null;
            }
            $key = $this->jwks->key($this->config->issuer, $header['kid']);
            if ($key === null) {
                return null;
            }
            if (openssl_verify($parts[0] . '.' . $parts[1], Base64Url::decode($parts[2]), $key, OPENSSL_ALGO_SHA256) !== 1) {
                return null;
            }
            $claims = json_decode(Base64Url::decode($parts[1]), true);
            if (!is_array($claims)
                || ($claims['iss'] ?? null) !== $this->config->issuer
                || ($claims['aud'] ?? null) !== $this->config->publishableKey
                || !is_string($claims['sub'] ?? null)
                || !(is_int($claims['exp'] ?? null) || is_float($claims['exp'] ?? null))) {
                return null;
            }
            if ($nonce !== null && ($claims['nonce'] ?? null) !== $nonce) {
                return null;
            }
            $exp = (int) $claims['exp'];
            return new VerifiedToken($claims, $exp, $exp <= ($now ?? time()), $token);
        } catch (InIDException $e) {
            throw $e;
        } catch (\Throwable) {
            // Malformed, or InID couldn't be reached for its keys: not a session
            return null;
        }
    }

    /**
     * A native app's ID token, sent to the app's backend as "Authorization: Bearer <id_token>":
     * its session when valid and not expired (the same checks as the cookie, aud = publishable key).
     * Accepts the header's value or the bare token.
     */
    public function verifyBearer(?string $authorization): ?Session
    {
        $token = trim(preg_replace('/^Bearer\s+/i', '', (string) $authorization));
        if ($token === '') {
            return null;
        }
        $checked = $this->verifyIdToken($token);
        return $checked && !$checked->expired ? $checked->session() : null;
    }

    // Who calls, from the request's Authorization header (native apps)
    public function bearerAuth(Request $request): Auth
    {
        return new Auth($this->verifyBearer($request->header('authorization')));
    }

    /** @throws InIDException invalid_signature, webhook_secret_missing */
    public function verifyWebhook(string $rawBody, ?string $signature, ?int $now = null): array
    {
        return Webhook::verify($rawBody, $signature, (string) $this->config->webhookSecret, $now);
    }

    // ---------- the session ----------

    /**
     * The session in these cookies. With $refresh, one that ends within a minute is renewed:
     * setCookies go back to the browser, cookieHeader is what this same request should see.
     */
    public function session(?string $cookieHeader, bool $refresh = false, bool $secure = true): SessionResult
    {
        $jar = Cookie::parse($cookieHeader);
        $current = isset($jar[Cookie::SESSION]) ? $this->verifyIdToken($jar[Cookie::SESSION]) : null;
        if ($current && $current->exp - time() > self::RENEW_BEFORE_SECONDS) {
            return new SessionResult($current->session());
        }
        $stillGood = $current && !$current->expired ? $current->session() : null;
        if (!$refresh || !isset($jar[Cookie::REFRESH])) {
            return new SessionResult($stillGood);
        }
        try {
            $tokens = $this->token(['grant_type' => 'refresh_token', 'refresh_token' => $jar[Cookie::REFRESH]]);
            $renewed = $this->verifyIdToken($tokens['id_token']);
            if (!$renewed) {
                throw new InIDException('invalid_id_token', 400);
            }
            $jar[Cookie::SESSION] = $tokens['id_token'];
            $jar[Cookie::REFRESH] = $tokens['refresh_token'];
            return new SessionResult($renewed->session(), $this->sessionCookies($tokens, $secure), Cookie::serialize($jar));
        } catch (InIDException $e) {
            // InID said no (signed out elsewhere, authorization taken back): the session is over
            if ($e->status !== null && $e->status < 500) {
                unset($jar[Cookie::SESSION], $jar[Cookie::REFRESH]);
                return new SessionResult(null, $this->clearCookies($secure), Cookie::serialize($jar));
            }
            // InID couldn't answer: what's still valid stays
            return new SessionResult($stillGood);
        } catch (NetworkException) {
            return new SessionResult($stillGood);
        }
    }

    // Who is signed in, from a request (it reads the session; the gate is what renews it)
    public function auth(Request $request): Auth
    {
        return new Auth($this->session($request->cookieHeader())->session);
    }

    // ---------- the gate ----------

    /**
     * What every framework's middleware does with each request. Rules: a path ("/admin" covers
     * /admin and /admin/x, not /adminx), a regular expression with its delimiters
     * ("#^/orgs/\d+/billing#"; any rule not starting with "/"), or
     * ['path' => ..., 'role' => ?, 'permission' => ?, 'entrance' => ?]. Or a callable(Request): bool.
     *
     * @param list<string|array>|callable|null $protect
     */
    public function gate(Request $request, array|callable|null $protect = null, bool $routes = true): GateResult
    {
        $anonymous = new Auth();
        $path = $request->path();
        $apiPath = $this->config->apiPath;
        if ($path === $apiPath || str_starts_with($path, $apiPath . '/')) {
            return $routes ? new GateResult($anonymous, $this->handle($request)) : new GateResult($anonymous, skipped: true);
        }
        // Back from Google on the app's own domain (its domain on Google's screen): Google's
        // answer is for InID, so the person goes straight on there, before any page renders
        $state = $request->query('state') ?? '';
        if (str_starts_with($state, 'inidg_') && ($request->hasQuery('code') || $request->hasQuery('error'))) {
            return new GateResult($anonymous, new Response(307, ['location' => $this->config->issuer . '/oauth/google/callback?' . $request->queryString(), 'cache-control' => 'no-store']));
        }
        $result = $this->session($request->cookieHeader(), true, $this->secure($request));
        $auth = new Auth($result->session);
        $denied = $this->enforce($request, $auth, self::rulesFor($request, $protect));
        if ($denied) {
            // The renewed session goes back even with a sign-in or a 403 (refresh tokens are single-use)
            return new GateResult($auth, $denied->withCookies($result->setCookies));
        }
        return new GateResult($auth, null, $result->setCookies, $result->cookieHeader);
    }

    /**
     * What the rules covering this request require: null when allowed; a redirect to sign in
     * (with return_to and the first rule's entrance) when no one is signed in; a 403 when the
     * person lacks a rule's role or permission.
     */
    public function enforce(Request $request, Auth $auth, array $rules): ?Response
    {
        if (!$rules) {
            return null;
        }
        if (!$auth->user) {
            $query = ['return_to' => $request->path() . ($request->queryString() !== '' ? '?' . $request->queryString() : '')];
            foreach ($rules as $rule) {
                if (is_array($rule) && is_string($rule['entrance'] ?? null) && $rule['entrance'] !== '') {
                    $query['entrance'] = $rule['entrance'];
                    break;
                }
            }
            return Response::redirect($this->origin($request) . $this->config->apiPath . '/signin?' . http_build_query($query), 307);
        }
        foreach ($rules as $rule) {
            if (is_array($rule) && !self::allows($auth->user, $rule)) {
                return new Response(403, ['content-type' => 'text/plain; charset=utf-8'], 'Forbidden');
            }
        }
        return null;
    }

    /** The rules (of $protect) that cover this request */
    public static function rulesFor(Request $request, array|callable|null $protect): array
    {
        if ($protect === null) {
            return [];
        }
        // A list of rules is never taken for a [class, method] callable
        if (!is_array($protect)) {
            return $protect($request) ? ['/'] : [];
        }
        $path = $request->path();
        return array_values(array_filter($protect, static fn ($rule) => self::covers($path, is_array($rule) ? (string) ($rule['path'] ?? '/') : (string) $rule)));
    }

    private static function covers(string $path, string $rule): bool
    {
        if ($rule !== '' && $rule[0] !== '/') {
            return preg_match($rule, $path) === 1;
        }
        return $path === $rule || str_starts_with($path, str_ends_with($rule, '/') ? $rule : $rule . '/');
    }

    // A rule's role and permission (each only when it names one)
    public static function allows(User $user, array $rule): bool
    {
        $role = $rule['role'] ?? null;
        $permission = $rule['permission'] ?? null;
        if (is_string($role) && $role !== '' && !in_array($role, $user->roles, true)) {
            return false;
        }
        return !(is_string($permission) && $permission !== '' && !in_array($permission, $user->permissions, true));
    }

    // ---------- the routes under the api path ----------

    // signin, callback, signout, session, sessions
    public function handle(Request $request): Response
    {
        $apiPath = $this->config->apiPath;
        $path = $request->path();
        $action = str_starts_with($path, $apiPath . '/') ? substr($path, strlen($apiPath) + 1) : '';
        $method = strtoupper($request->method);

        return match (true) {
            $method === 'GET' && $action === 'signin' => $this->signIn($request),
            $method === 'GET' && $action === 'callback' => $this->callback($request),
            $method === 'POST' && $action === 'signout' => $this->signOut($request),
            $method === 'GET' && $action === 'session' => $this->sessionRoute($request),
            $action === 'sessions' || str_starts_with($action, 'sessions/') => $this->sessions($request, $action),
            default => Response::json(['error' => 'not_found'], 404),
        };
    }

    private function signIn(Request $request): Response
    {
        $issuer = $this->config->issuer;
        // display=embed: InID's form inside the app's own page (<inid-sign-in>)
        $embed = $request->query('display') === 'embed';
        // Back from Google, the frame goes on with the same sign-in (its flow cookie stays)
        $resume = $request->query('continue');
        if ($embed && $resume !== null) {
            parse_str($resume, $given);
            $kept = [];
            foreach (['request', 'session', 'from', 'lang'] as $key) {
                if (is_string($given[$key] ?? null) && $given[$key] !== '') {
                    $kept[$key] = $given[$key];
                }
            }
            $kept['display'] = 'embed';
            return Response::redirect($issuer . '/oauth/authorize/continue?' . http_build_query($kept));
        }
        $flow = [
            'state' => self::random(16),
            'nonce' => self::random(16),
            'verifier' => self::random(32),
            'returnTo' => self::safeReturn($request->query('return_to')),
        ];
        if ($embed) {
            // page: where the form is, to go on there after Google
            $flow['embed'] = true;
            $flow['page'] = self::safeReturn($request->query('page') ?: $request->query('return_to'));
        }
        $query = [
            'client_id' => $this->config->publishableKey,
            'redirect_uri' => $this->redirectUri($request),
            'response_type' => 'code',
            'scope' => $this->config->scope,
            'state' => $flow['state'],
            'nonce' => $flow['nonce'],
            'code_challenge' => Base64Url::encode(hash('sha256', $flow['verifier'], true)),
            'code_challenge_method' => 'S256',
        ];
        foreach (['ui_locales', 'login_hint', 'prompt', 'entrance'] as $passed) {
            $value = $request->query($passed);
            if ($value !== null && $value !== '') {
                $query[$passed] = $value;
            }
        }
        // In the page, someone InID knows still clicks to go in: never signed in by just loading it
        if ($embed) {
            $query['display'] = 'embed';
            $query['prompt'] = 'login';
        }
        // Right after signing out of the app, InID asks too: they chose to leave
        if (isset(Cookie::parse($request->cookieHeader())[Cookie::SIGNED_OUT])) {
            $query['prompt'] = 'login';
        }
        // One cookie per sign-in (named by its state): two at once (two tabs) don't overwrite each other
        $flowCookie = new Cookie(Cookie::FLOW . '_' . $flow['state'], Base64Url::encode(json_encode($flow, JSON_UNESCAPED_SLASHES)), self::FLOW_MAX_AGE, $this->config->apiPath, $this->secure($request));
        return Response::redirect($issuer . '/oauth/authorize?' . http_build_query($query), 302, [$flowCookie]);
    }

    private function callback(Request $request): Response
    {
        $secure = $this->secure($request);
        $state = $request->query('state') ?? '';
        $flowName = preg_match('/^[\w-]{1,64}$/', $state) ? Cookie::FLOW . '_' . $state : Cookie::FLOW;
        $clearFlow = new Cookie($flowName, '', 0, $this->config->apiPath, $secure);
        $flow = null;
        try {
            $raw = Cookie::parse($request->cookieHeader())[$flowName] ?? '';
            $decoded = $raw !== '' ? json_decode(Base64Url::decode($raw), true) : null;
            $flow = is_array($decoded) && is_string($decoded['state'] ?? null) ? $decoded : null;
        } catch (\Throwable) {
        }
        $embedded = ($flow['embed'] ?? false) === true;
        // Back from Google, a sign-in that started in the app's page goes on in it
        $resume = $request->query('inid_continue');
        if ($resume !== null && $embedded && $request->query('state') === $flow['state']) {
            $page = self::safeReturn($flow['page'] ?? null);
            return Response::redirect($page . (str_contains($page, '?') ? '&' : '?') . http_build_query(['inid_continue' => $resume]));
        }
        $code = $request->query('code');
        // From InID's form inside the page, the whole page goes on (not just its frame)
        $go = fn (string $to, array $cookies) => $embedded ? self::leaveFrame($to, $cookies) : Response::redirect($to, 302, $cookies);
        if (!$flow || !$code || $request->query('state') !== $flow['state']) {
            return $go(self::safeReturn($flow['returnTo'] ?? null), [$clearFlow]);
        }
        try {
            $tokens = $this->token(['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $this->redirectUri($request), 'code_verifier' => (string) ($flow['verifier'] ?? '')]);
            if (!$this->verifyIdToken($tokens['id_token'], (string) ($flow['nonce'] ?? ''))) {
                throw new InIDException('invalid_id_token', 400);
            }
        } catch (InIDException $e) {
            return Response::json(['error' => $e->error], $e->status !== null && $e->status < 500 ? 400 : 502, [$clearFlow]);
        } catch (NetworkException) {
            return Response::json(['error' => 'inid_unreachable'], 502, [$clearFlow]);
        }
        return $go(self::safeReturn($flow['returnTo'] ?? null), [$clearFlow, ...$this->sessionCookies($tokens, $secure), new Cookie(Cookie::SIGNED_OUT, '', 0, '/', $secure)]);
    }

    private function signOut(Request $request): Response
    {
        $secure = $this->secure($request);
        $refreshToken = Cookie::parse($request->cookieHeader())[Cookie::REFRESH] ?? null;
        // The sign-in ends at InID too (best effort); the person's InID stays signed in (that's theirs)
        if ($refreshToken) {
            try {
                $this->http->request('POST', $this->config->issuer . '/oauth/revoke', $this->clientHeaders(), http_build_query(['token' => $refreshToken, 'token_type_hint' => 'refresh_token']), 3.0);
            } catch (\Throwable) {
            }
        }
        return Response::json(['ok' => true], 200, [...$this->clearCookies($secure), new Cookie(Cookie::SIGNED_OUT, '1', self::COOKIE_MAX_AGE, '/', $secure)]);
    }

    private function sessionRoute(Request $request): Response
    {
        $result = $this->session($request->cookieHeader(), true, $this->secure($request));
        return Response::json([
            'user' => $result->session?->user,
            'accountUrl' => $this->config->issuer . '/account?' . http_build_query(['client_id' => $this->config->publishableKey]),
        ], 200, $result->setCookies);
    }

    // The person's own sessions at this app, and ending them: one (DELETE sessions/{id}) or
    // all but this one (DELETE sessions?others=1)
    private function sessions(Request $request, string $action): Response
    {
        $current = $this->session($request->cookieHeader())->session;
        if (!$current) {
            return Response::json(['error' => 'not_signed_in'], 401);
        }
        $api = $this->api();
        $sid = $current->id();
        try {
            $method = strtoupper($request->method);
            if ($method === 'GET' && $action === 'sessions') {
                $list = array_map(static fn (array $s) => [...$s, 'current' => ($s['id'] ?? null) === $sid], $api->sessions($current->user->id));
                return Response::json(['sessions' => $list]);
            }
            if ($method === 'DELETE') {
                $one = str_starts_with($action, 'sessions/') ? rawurldecode(substr($action, strlen('sessions/'))) : '';
                $ending = $one !== '' ? [$one] : ($request->query('others') ? array_values(array_filter(array_map(static fn (array $s) => $s['id'] ?? null, $api->sessions($current->user->id)), static fn ($id) => is_string($id) && $id !== $sid)) : []);
                foreach ($ending as $id) {
                    $api->endSessions($current->user->id, $id);
                }
                return Response::json(['ended' => count($ending)]);
            }
        } catch (InIDException) {
            return Response::json(['error' => 'sessions_unavailable'], 502);
        }
        return Response::json(['error' => 'not_found'], 404);
    }

    // ---------- helpers ----------

    /** @return array{id_token: string, refresh_token: string} */
    private function token(array $params): array
    {
        $response = $this->http->request('POST', $this->config->issuer . '/oauth/token', $this->clientHeaders(), http_build_query($params));
        $body = $response->json();
        if (!$response->ok()) {
            throw new InIDException(is_string($body['error'] ?? null) ? $body['error'] : 'token_failed', $response->status);
        }
        if (!is_string($body['id_token'] ?? null)) {
            throw new InIDException('invalid_id_token', 400);
        }
        return ['id_token' => $body['id_token'], 'refresh_token' => is_string($body['refresh_token'] ?? null) ? $body['refresh_token'] : ''];
    }

    private function clientHeaders(): array
    {
        return [
            'content-type' => 'application/x-www-form-urlencoded',
            'accept' => 'application/json',
            'authorization' => 'Basic ' . base64_encode(rawurlencode($this->config->publishableKey) . ':' . rawurlencode($this->config->secretKey)),
        ];
    }

    private function sessionCookies(array $tokens, bool $secure): array
    {
        return [
            new Cookie(Cookie::SESSION, $tokens['id_token'], self::COOKIE_MAX_AGE, '/', $secure),
            new Cookie(Cookie::REFRESH, $tokens['refresh_token'], self::COOKIE_MAX_AGE, '/', $secure),
        ];
    }

    private function clearCookies(bool $secure): array
    {
        return [new Cookie(Cookie::SESSION, '', 0, '/', $secure), new Cookie(Cookie::REFRESH, '', 0, '/', $secure)];
    }

    // INID_APP_URL when set (behind proxies), the request's own origin otherwise
    public function origin(Request $request): string
    {
        return $this->config->appUrl ?? $request->origin();
    }

    public function secure(Request $request): bool
    {
        return str_starts_with($this->origin($request), 'https://');
    }

    private function redirectUri(Request $request): string
    {
        return $this->origin($request) . $this->config->apiPath . '/callback';
    }

    // Only somewhere in the app itself: a path, never another site
    public static function safeReturn(mixed $to): string
    {
        return is_string($to) && preg_match('#^/(?![/\\\\])#', $to) ? $to : '/';
    }

    private static function random(int $bytes): string
    {
        return Base64Url::encode(random_bytes($bytes));
    }

    // A tiny page that sends the whole window on (the app's own address, same origin)
    private static function leaveFrame(string $to, array $cookies): Response
    {
        $target = str_replace('<', '\\u003c', json_encode($to, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        return new Response(200, ['content-type' => 'text/html; charset=utf-8', 'cache-control' => 'no-store'], '<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace(' . $target . ')</script>', $cookies);
    }
}
