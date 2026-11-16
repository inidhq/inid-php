<?php

declare(strict_types=1);

namespace InID;

// A cookie the SDK sets. Kept structured (not only as a header line) so frameworks with their
// own cookie objects (Laravel, Symfony) get it without parsing it back.
final class Cookie implements \Stringable
{
    public const SESSION = '__inid_session';
    public const REFRESH = '__inid_refresh';
    public const FLOW = '__inid_flow';
    // This browser signed out of the app: its next sign-in asks, instead of going in by itself
    public const SIGNED_OUT = '__inid_out';

    public function __construct(
        public readonly string $name,
        public readonly string $value,
        // 0 deletes it
        public readonly int $maxAge,
        public readonly string $path = '/',
        public readonly bool $secure = true,
    ) {
    }

    public function __toString(): string
    {
        return $this->name . '=' . rawurlencode($this->value) . '; Path=' . $this->path . '; Max-Age=' . $this->maxAge . '; HttpOnly; SameSite=Lax' . ($this->secure ? '; Secure' : '');
    }

    /** @return array<string, string> */
    public static function parse(?string $header): array
    {
        $jar = [];
        foreach (preg_split('/;\s*/', (string) $header) as $part) {
            $at = strpos($part, '=');
            if ($at > 0) {
                $jar[substr($part, 0, $at)] = rawurldecode(substr($part, $at + 1));
            }
        }
        return $jar;
    }

    /** @param array<string, string> $jar */
    public static function serialize(array $jar): string
    {
        $parts = [];
        foreach ($jar as $name => $value) {
            $parts[] = $name . '=' . rawurlencode($value);
        }
        return implode('; ', $parts);
    }
}
