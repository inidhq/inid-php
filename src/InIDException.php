<?php

declare(strict_types=1);

namespace InID;

// $error is InID's code ("invalid_grant", "invalid_signature"); $status the HTTP status
// InID answered with, when it did (a 4xx ends the session, a 5xx doesn't)
class InIDException extends \RuntimeException
{
    public function __construct(public readonly string $error, public readonly ?int $status = null, ?\Throwable $previous = null)
    {
        parent::__construct($error, $status ?? 0, $previous);
    }
}
