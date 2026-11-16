<?php

declare(strict_types=1);

namespace InID\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \InID\Auth auth(?\Illuminate\Http\Request $request = null)
 * @method static ?\InID\User user()
 * @method static ?string userId()
 * @method static ?\InID\Session session()
 * @method static bool isSignedIn()
 * @method static bool has(?string $role = null, ?string $permission = null)
 * @method static \InID\Auth bearer(?\Illuminate\Http\Request $request = null)
 * @method static \InID\AppApi api()
 * @method static array verifyWebhook(?\Illuminate\Http\Request $request = null)
 * @method static \InID\InID core()
 * @method static string signIn(array $attributes = [])
 *
 * @see \InID\Laravel\InIDManager
 */
final class InID extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'inid';
    }
}
