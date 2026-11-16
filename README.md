# inid/inid

Sign-in with [InID](https://inid.co) for PHP and Laravel. People sign in with their phone (a code by WhatsApp or SMS), Face ID, their fingerprint or Google, without passwords. Your server knows who they are, their role and their permissions.

The package covers the sign-in routes, a session that renews itself, paths protected by role or permission, webhooks, InID's API for your users, and bearer tokens from native apps. It has no dependencies beyond PHP 8.1 with `ext-openssl` and `ext-json`. Laravel is optional.

```bash
composer require inid/inid
```

Set your keys from InID's panel (Settings → Keys):

```bash
INID_PUBLISHABLE_KEY=pk_test_...
INID_SECRET_KEY=sk_test_...
# Optional
INID_WEBHOOK_SECRET=whsec_...          # to verify webhooks
INID_APP_URL=https://app.example.com   # behind a proxy that hides the app's address
INID_ISSUER=https://id.inid.co         # the default
```

A key that is missing or malformed throws an `InID\InIDException` whose message names the key.

## Plain PHP

`gate()` does everything for one request. It answers InID's routes (`/api/inid/…`), keeps the session fresh, and sends anyone who isn't signed in away from protected paths.

```php
<?php // public/index.php, the front controller (php -S localhost:8000 public/index.php)
require __DIR__ . '/../vendor/autoload.php';

use InID\InID;
use InID\Request;

$inid = InID::fromEnv();
$gate = $inid->gate(Request::fromGlobals(), [
    '/dashboard',                                       // /dashboard and everything under it
    '#^/orgs/\d+/billing#',                             // a regular expression (any rule not starting with "/")
    ['path' => '/admin', 'role' => 'admin'],
    ['path' => '/reports', 'permission' => 'reports:read'],
    ['path' => '/team', 'role' => 'staff', 'entrance' => 'team'],
]);
if ($gate->response) {           // InID's routes, a sign-in, a 403
    $gate->response->send();
    exit;
}
foreach ($gate->setCookies as $cookie) {   // a renewed session
    header('set-cookie: ' . $cookie, false);
}

$auth = $gate->auth;
echo $auth->isSignedIn ? 'Hola, ' . htmlspecialchars($auth->user->name ?? '') : 'Hola';
```

`$auth` has `isSignedIn`, `userId` (this person's id in your app), `user`, `session` and `has(role: 'admin')` / `has(permission: 'reports:read')`. With no arguments, `has()` is true for anyone signed in. `user` is an `InID\User` with `id`, `firstName`, `lastName`, `name`, `email`, `emailVerified`, `phone` (E.164), `roles`, `permissions` and `publicMetadata`, and serializes to JSON in camelCase. If you aren't using the gate, `$inid->auth($request)` reads who's signed in. Only the gate renews the session.

Protect rules can also be a `callable(InID\Request): bool`.

**PSR-7 (Slim, Mezzio…):** `Request::fromPsr($serverRequest)` turns a PSR-7 request into an InID one, and `$response->toPsr($responseFactory, $streamFactory)` goes the other way. Add the `setCookies` with `withAddedHeader('set-cookie', (string) $cookie)`.

**Keys cache:** InID's public keys are kept in memory for an hour. Under PHP-FPM, pass any PSR-16 cache so every request doesn't fetch them again: `InID::fromEnv(cache: $psr16Cache)`.

**HTTP client:** requests to InID use curl when it is installed and PHP streams otherwise. To use your own, implement `InID\Http\HttpClient` and pass it as `http:`.

## Laravel

The service provider is auto-discovered and reads the keys from `.env`. You get:

- InID's routes under `/api/inid` (sign in, callback, sign out, session, sessions). They sit outside the `web` group, so they need no CSRF token or Laravel session.
- The `inid` middleware on every `web` route. It renews the session before it ends, and it forwards someone coming back from Google on your own domain to InID.

```php
// routes/web.php
use Illuminate\Http\Request;
use InID\Laravel\Facades\InID;

Route::get('/', fn () => view('welcome'));

Route::get('/dashboard', function (Request $request) {
    $user = $request->inid()->user;        // or InID::user(), or inid()->user()
    return view('dashboard', ['user' => $user]);
})->middleware('inid:auth');               // someone signed in

Route::middleware('inid:role,admin')->group(function () {
    Route::get('/admin', fn () => 'Only admins');
});
Route::get('/reports', fn () => '…')->middleware('inid:permission,reports:read');
Route::get('/team', fn () => '…')->middleware('inid:role,staff,entrance,team');  // signs in through the "team" entrance
```

Anyone not signed in goes to InID and comes back to the same page. Someone signed in without the role or permission gets a 403.

`InID::user()`, `InID::userId()`, `InID::isSignedIn()`, `InID::has(role: 'admin')`, `InID::auth()`, and the same through `inid()->…` and `$request->inid()` (an `InID\Auth`).

### Blade

```blade
@inidSignedOut
    @inidSignIn(['appName' => 'Mi App', 'returnTo' => '/dashboard'])
@endInidSignedOut

@inidSignedIn
    Hola, {{ InID::user()->firstName }}
    <inid-user-button></inid-user-button>
@endInidSignedIn

@inidSignedIn(['role' => 'admin'])
    <a href="/admin">Admin</a>
@endInidSignedIn
```

`@inidSignIn` renders `<inid-sign-in app-name="Mi App" return-to="/dashboard">`, InID's form inside your page. It adds the [`@inid/js`](https://www.npmjs.com/package/@inid/js) script from jsDelivr once per page. Use `@inidScript` to add the script on its own for the other components (`<inid-user-button>`, `<inid-sign-in-button>`, `<inid-sign-out-button>`…).

### Configuration

`php artisan vendor:publish --tag=inid-config` writes `config/inid.php`. In it you can set:

- `protect`: paths that need someone signed in, in one place (the same rules as in plain PHP).
- `api_path` and `scope`.
- `routes` and `web_middleware`: set either to `false` to wire them yourself.
- `cache`: the cache store for InID's public keys. `null` uses the default store; `false` keeps them in memory only.
- `script`: the URL of `@inid/js`.

InID's cookies (`__inid_session`, `__inid_refresh`, `__inid_out`) hold InID's own signed tokens, so the package excludes them from Laravel's cookie encryption.

## Webhooks

InID signs each webhook with `InID-Signature: t=…,v1=…` (HMAC-SHA256 with your webhook secret). Verify it against the body exactly as it arrived:

```php
// Plain PHP
try {
    $event = $inid->verifyWebhook(file_get_contents('php://input'), $_SERVER['HTTP_INID_SIGNATURE'] ?? null);
} catch (InID\InIDException $e) {
    http_response_code(400);
    exit;
}

// Laravel (exclude the route from CSRF, or put it in routes/api.php)
Route::post('/webhooks/inid', function () {
    $event = InID::verifyWebhook();   // throws InID\InIDException if it isn't InID's
    match ($event['type']) {
        'user.updated' => UpdateUser::dispatch($event['sub']),
        'session.ended' => /* $event['sid'] */ null,
        default => null,
    };
    return response()->noContent();
});
```

A signature older than 5 minutes is rejected. Event types: `user.created`, `user.updated`, `user.deleted` (may carry `token`), `session.created`, `session.ended` (carries `sid`), `subscription.cancel_requested`, `customer.logged_out`, `customer.registered`, `checkout.abandoned`. Every event has `type`, `created_at`, and `sub` or `token`.

## Your users (the app API)

Calls to InID's API use your secret key:

```php
$api = $inid->api();                 // Laravel: InID::api()
$api->user($sub);                    // id, firstName, lastName, email, phone, role…
$api->users(search: 'laura');
$api->setRole($sub, 'admin');        // null: the role new users get
$api->setMetadata($sub, public: ['plan' => 'pro'], private: ['stripe' => 'cus_…']);
$api->roles();
$api->invite('ana@example.com', 'admin');
$api->inviteMany([['email' => 'a@x.co'], ['email' => 'b@x.co', 'role' => 'member']]);
$api->sessions($sub);
$api->endSessions($sub, $sid);       // one session, or every one without $sid
$api->call('GET', '/v1/access');     // anything else
```

Errors throw `InID\InIDException` with InID's code (`$e->error`, such as `user_not_found`) and its HTTP status (`$e->status`).

## Native apps (bearer tokens)

An iOS, Android, React Native or Flutter app signs in with InID itself and calls your backend with the ID token as `Authorization: Bearer <id_token>`. Your backend verifies the token with the same checks the session cookie gets: InID's signature, issuer, audience = your publishable key, and not expired.

```php
// Plain PHP
$session = $inid->verifyBearer($_SERVER['HTTP_AUTHORIZATION'] ?? null);   // InID\Session or null
if (!$session) { http_response_code(401); exit; }
echo $session->user->id;

// Laravel: the inid.bearer middleware answers 401 or 403 itself
Route::middleware('inid.bearer')->get('/api/me', fn () => ['id' => InID::userId()]);
Route::middleware('inid.bearer:role,admin')->get('/api/admin/stats', fn () => …);
```

## Tests

```bash
docker run --rm -v "$PWD":/app -w /app composer:2 composer install
docker run --rm -v "$PWD":/app -w /app php:8.2-cli vendor/bin/phpunit
```

The tests run against a fake InID that serves a JWKS and signs ID tokens with an RSA key generated during the run.

## License

MIT
