<?php

declare(strict_types=1);

namespace InID;

final class Config
{
    public function __construct(
        public readonly string $publishableKey,
        public readonly string $secretKey,
        // InID itself; a local one while developing InID
        public readonly string $issuer = 'https://id.inid.co',
        // Where the app's sign-in routes live
        public readonly string $apiPath = '/api/inid',
        public readonly string $scope = 'openid profile email phone',
        // The app's own origin, when requests don't say it (behind some proxies)
        public readonly ?string $appUrl = null,
        public readonly ?string $webhookSecret = null,
    ) {
        if (!str_starts_with($publishableKey, 'pk_')) {
            throw new InIDException('INID_PUBLISHABLE_KEY is missing: set it to your publishable key (pk_...)');
        }
        if (!str_starts_with($secretKey, 'sk_')) {
            throw new InIDException('INID_SECRET_KEY is missing: set it to your secret key (sk_...)');
        }
    }

    /**
     * Settings given win; the rest come from the environment (INID_PUBLISHABLE_KEY,
     * INID_SECRET_KEY, INID_ISSUER, INID_APP_URL, INID_WEBHOOK_SECRET).
     *
     * @param array{publishableKey?: string, secretKey?: string, issuer?: string, apiPath?: string, scope?: string, appUrl?: ?string, webhookSecret?: ?string} $given
     */
    public static function fromEnv(array $given = []): self
    {
        $pick = static fn (string $key, string $env) => self::filled($given[$key] ?? null) ?? self::filled(self::env($env));
        $appUrl = $pick('appUrl', 'INID_APP_URL');
        return new self(
            publishableKey: (string) $pick('publishableKey', 'INID_PUBLISHABLE_KEY'),
            secretKey: (string) $pick('secretKey', 'INID_SECRET_KEY'),
            issuer: rtrim($pick('issuer', 'INID_ISSUER') ?? 'https://id.inid.co', '/'),
            apiPath: rtrim(self::filled($given['apiPath'] ?? null) ?? '/api/inid', '/'),
            scope: self::filled($given['scope'] ?? null) ?? 'openid profile email phone',
            appUrl: $appUrl !== null ? (rtrim($appUrl, '/') ?: null) : null,
            webhookSecret: $pick('webhookSecret', 'INID_WEBHOOK_SECRET'),
        );
    }

    private static function filled(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    // getenv() misses what some setups only put in $_ENV or $_SERVER (Dotenv)
    private static function env(string $name): ?string
    {
        $value = $_ENV[$name] ?? $_SERVER[$name] ?? getenv($name);
        return is_string($value) ? $value : null;
    }
}
