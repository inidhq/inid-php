<?php

declare(strict_types=1);

namespace InID;

final class SessionResult
{
    /** @param list<Cookie> $setCookies */
    public function __construct(
        public readonly ?Session $session,
        // Cookies to send back to the browser (a renewed or an ended session)
        public readonly array $setCookies = [],
        // The request's cookies as they are now, for the rest of this same request
        public readonly ?string $cookieHeader = null,
    ) {
    }
}
