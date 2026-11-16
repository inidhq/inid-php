<?php

declare(strict_types=1);

namespace InID;

// The little the SDK needs from a request: method, full URL, cookies and Authorization
final class Request
{
    private readonly array $parts;
    private readonly array $query;

    /** @param array<string, string> $headers */
    public function __construct(
        public readonly string $method,
        // Absolute: https://app.example/path?query
        public readonly string $url,
        private readonly array $headers = [],
    ) {
        $this->parts = parse_url($url) ?: [];
        parse_str($this->parts['query'] ?? '', $query);
        $this->query = $query;
    }

    // From PHP's globals, for a plain front controller
    public static function fromGlobals(): self
    {
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] ?? null) == 443;
        $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_') && is_string($value)) {
                $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
            }
        }
        return new self($_SERVER['REQUEST_METHOD'] ?? 'GET', ($https ? 'https' : 'http') . '://' . $host . ($_SERVER['REQUEST_URI'] ?? '/'), $headers);
    }

    /** From a PSR-7 request (Slim, Mezzio, anything PSR-7) */
    public static function fromPsr(\Psr\Http\Message\ServerRequestInterface $request): self
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[strtolower((string) $name)] = implode(strtolower((string) $name) === 'cookie' ? '; ' : ', ', $values);
        }
        return new self($request->getMethod(), (string) $request->getUri(), $headers);
    }

    public function header(string $name): ?string
    {
        foreach ($this->headers as $key => $value) {
            if (strcasecmp($key, $name) === 0) {
                return $value;
            }
        }
        return null;
    }

    public function cookieHeader(): ?string
    {
        return $this->header('cookie');
    }

    public function path(): string
    {
        return $this->parts['path'] ?? '/';
    }

    // The raw query string, as received (the Google return passes it on untouched)
    public function queryString(): string
    {
        return $this->parts['query'] ?? '';
    }

    public function query(string $name): ?string
    {
        $value = $this->query[$name] ?? null;
        return is_string($value) ? $value : null;
    }

    public function hasQuery(string $name): bool
    {
        return array_key_exists($name, $this->query);
    }

    public function origin(): string
    {
        $port = isset($this->parts['port']) ? ':' . $this->parts['port'] : '';
        return ($this->parts['scheme'] ?? 'http') . '://' . ($this->parts['host'] ?? 'localhost') . $port;
    }
}
