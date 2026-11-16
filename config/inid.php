<?php

// InID for this Laravel app. The keys come from .env; publish this file
// (php artisan vendor:publish --tag=inid-config) only to change the rest.
return [
    'publishable_key' => env('INID_PUBLISHABLE_KEY'),
    'secret_key' => env('INID_SECRET_KEY'),
    'issuer' => env('INID_ISSUER', 'https://id.inid.co'),
    // The app's own origin, when the requests it sees don't say it (behind some proxies)
    'app_url' => env('INID_APP_URL'),
    'webhook_secret' => env('INID_WEBHOOK_SECRET'),

    // Where InID's routes live (signin, callback, signout, session, sessions)
    'api_path' => '/api/inid',
    'scope' => 'openid profile email phone',

    // Register InID's routes under api_path
    'routes' => true,

    // Run the gate on every route of the "web" group: the session is renewed before it ends,
    // and the return from Google on the app's own domain goes on to InID
    'web_middleware' => true,

    // Paths that need someone signed in: '/dashboard' (and its subpaths), a regular expression
    // ('#^/orgs/\d+/billing#'), or ['path' => '/admin', 'role' => 'admin', 'entrance' => 'team'].
    // Routes can also say it themselves: ->middleware('inid:role,admin')
    'protect' => [],

    // The cache store for InID's public keys (null: the default store; false: memory only)
    'cache' => env('INID_CACHE_STORE'),

    // @inid/js, for @inidSignIn
    'script' => 'https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js',
];
