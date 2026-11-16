<?php

declare(strict_types=1);

namespace InID\Laravel;

use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Illuminate\View\Compilers\BladeCompiler;
use InID\Config;
use InID\Cookie;
use InID\Http\DefaultHttpClient;
use InID\Http\HttpClient;
use InID\InID;
use InID\Laravel\Http\RouteController;
use InID\Laravel\Middleware\Authenticate;
use InID\Laravel\Middleware\AuthenticateBearer;

final class InIDServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/inid.php', 'inid');

        $this->app->bindIf(HttpClient::class, DefaultHttpClient::class, true);
        // Built on first use, so artisan works before the keys are set; a missing key then
        // fails with the message saying which one
        $this->app->singleton(InID::class, function ($app) {
            $config = $app['config']['inid'];
            return new InID(Config::fromEnv([
                'publishableKey' => $config['publishable_key'] ?? null,
                'secretKey' => $config['secret_key'] ?? null,
                'issuer' => $config['issuer'] ?? null,
                'apiPath' => $config['api_path'] ?? null,
                'scope' => $config['scope'] ?? null,
                'appUrl' => $config['app_url'] ?? null,
                'webhookSecret' => $config['webhook_secret'] ?? null,
            ]), $app->make(HttpClient::class), $this->cache($config['cache'] ?? null));
        });
        $this->app->singleton('inid', fn ($app) => new InIDManager($app));
        $this->app->alias('inid', InIDManager::class);
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../../config/inid.php' => $this->app->configPath('inid.php')], 'inid-config');

        /** @var Router $router */
        $router = $this->app['router'];
        $router->aliasMiddleware('inid', Authenticate::class);
        $router->aliasMiddleware('inid.bearer', AuthenticateBearer::class);
        if (config('inid.web_middleware', true)) {
            // Through the HTTP kernel: it syncs its groups onto the router, replacing what the
            // router alone was given
            $kernel = $this->app->bound(\Illuminate\Contracts\Http\Kernel::class) ? $this->app->make(\Illuminate\Contracts\Http\Kernel::class) : null;
            if ($kernel && method_exists($kernel, 'appendMiddlewareToGroup')) {
                $kernel->appendMiddlewareToGroup('web', Authenticate::class);
            } else {
                $router->pushMiddlewareToGroup('web', Authenticate::class);
            }
        }

        // InID's cookies hold InID's own signed tokens: Laravel mustn't encrypt them
        if (method_exists(EncryptCookies::class, 'except')) {
            EncryptCookies::except([Cookie::SESSION, Cookie::REFRESH, Cookie::SIGNED_OUT]);
        }

        // Outside the "web" group: no CSRF (sign-out is a same-site POST; SameSite=Lax cookies)
        // and no Laravel session needed
        if (config('inid.routes', true) && !$this->app->routesAreCached()) {
            $apiPath = trim((string) config('inid.api_path', '/api/inid'), '/');
            $router->any($apiPath . '/{action}', RouteController::class)->where('action', '.*')->name('inid');
        }

        Request::macro('inid', function () {
            /** @var Request $this */
            return app('inid')->auth($this);
        });

        $this->callAfterResolving('blade.compiler', function (BladeCompiler $blade) {
            $blade->directive('inidSignIn', fn ($expression) => "<?php echo app('inid')->signIn(" . ($expression ?: '[]') . '); ?>');
            $blade->directive('inidScript', fn () => "<?php echo app('inid')->script(); ?>");
            $blade->directive('inidSignedIn', fn ($expression) => $expression
                ? "<?php if (app('inid')->has(...(array) ($expression))): ?>"
                : "<?php if (app('inid')->isSignedIn()): ?>");
            $blade->directive('endInidSignedIn', fn () => '<?php endif; ?>');
            $blade->directive('inidSignedOut', fn () => "<?php if (!app('inid')->isSignedIn()): ?>");
            $blade->directive('endInidSignedOut', fn () => '<?php endif; ?>');
        });
    }

    private function cache(mixed $store): ?\Psr\SimpleCache\CacheInterface
    {
        if ($store === false || $store === 'false' || !$this->app->bound('cache')) {
            return null;
        }
        $repository = $this->app['cache']->store($store ?: null);
        return $repository instanceof \Psr\SimpleCache\CacheInterface ? $repository : null;
    }
}
