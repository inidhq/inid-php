<?php

declare(strict_types=1);

namespace InID;

// What the SDK answers: status, headers, cookies (each its own Set-Cookie) and body
final class Response
{
    /**
     * @param array<string, string> $headers lowercase names, without set-cookie
     * @param list<Cookie> $cookies
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly array $cookies = [],
    ) {
    }

    public static function redirect(string $location, int $status = 302, array $cookies = []): self
    {
        return new self($status, ['location' => $location, 'cache-control' => 'no-store'], '', $cookies);
    }

    public static function json(mixed $data, int $status = 200, array $cookies = []): self
    {
        return new self($status, ['content-type' => 'application/json', 'cache-control' => 'no-store'], json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), $cookies);
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** @param list<Cookie> $cookies */
    public function withCookies(array $cookies): self
    {
        return new self($this->status, $this->headers, $this->body, [...$this->cookies, ...$cookies]);
    }

    /** @return list<string> every Set-Cookie line */
    public function setCookieHeaders(): array
    {
        return array_map('strval', $this->cookies);
    }

    // For a plain PHP front controller
    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $name => $value) {
            header("$name: $value");
        }
        foreach ($this->cookies as $cookie) {
            header('set-cookie: ' . $cookie, false);
        }
        echo $this->body;
    }

    public function toPsr(\Psr\Http\Message\ResponseFactoryInterface $responses, \Psr\Http\Message\StreamFactoryInterface $streams): \Psr\Http\Message\ResponseInterface
    {
        $response = $responses->createResponse($this->status)->withBody($streams->createStream($this->body));
        foreach ($this->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        foreach ($this->cookies as $cookie) {
            $response = $response->withAddedHeader('set-cookie', (string) $cookie);
        }
        return $response;
    }
}
