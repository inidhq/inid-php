<?php

declare(strict_types=1);

namespace InID\Laravel;

use Illuminate\Http\Request as LaravelRequest;
use Illuminate\Http\Response as LaravelResponse;
use InID\Cookie;
use InID\Request;
use InID\Response;
use Symfony\Component\HttpFoundation\Cookie as SymfonyCookie;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

// Between Laravel's requests and responses and the SDK's
final class Bridge
{
    public static function request(LaravelRequest $request): Request
    {
        $headers = [];
        foreach ($request->headers->all() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }
        // getSchemeAndHttpHost honors the app's trusted proxies
        return new Request($request->getMethod(), $request->getSchemeAndHttpHost() . $request->getRequestUri(), $headers);
    }

    public static function response(Response $response): LaravelResponse
    {
        $laravel = new LaravelResponse($response->body, $response->status, $response->headers);
        return self::withCookies($laravel, $response->cookies);
    }

    /**
     * @template T of SymfonyResponse
     * @param T $response
     * @param list<Cookie> $cookies
     * @return T
     */
    public static function withCookies(SymfonyResponse $response, array $cookies): SymfonyResponse
    {
        foreach ($cookies as $cookie) {
            $response->headers->setCookie(self::cookie($cookie));
        }
        return $response;
    }

    // Built here rather than parsed from the header line, so Max-Age=0 really deletes it
    public static function cookie(Cookie $cookie): SymfonyCookie
    {
        $expires = $cookie->maxAge > 0 ? time() + $cookie->maxAge : 1;
        return new SymfonyCookie($cookie->name, $cookie->value, $expires, $cookie->path, null, $cookie->secure, true, false, SymfonyCookie::SAMESITE_LAX);
    }
}
