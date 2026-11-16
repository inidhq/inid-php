<?php

declare(strict_types=1);

namespace InID;

final class GateResult
{
    /** @param list<Cookie> $setCookies */
    public function __construct(
        public readonly Auth $auth,
        // When set, answer with it: InID's routes, a sign-in, back from Google, a 403
        public readonly ?Response $response = null,
        // Cookies the page's own response must carry (a renewed session)
        public readonly array $setCookies = [],
        // The request's cookies as they are now (renewed), for the rest of this same request
        public readonly ?string $cookieHeader = null,
        // Under the api path with routes off: nothing was done, the framework's route answers
        public readonly bool $skipped = false,
    ) {
    }
}
