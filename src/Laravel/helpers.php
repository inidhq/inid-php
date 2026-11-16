<?php

declare(strict_types=1);

// inid()->user() in a Laravel app. Defined only where nothing else took the name.
if (!function_exists('inid')) {
    function inid(): \InID\Laravel\InIDManager
    {
        if (!function_exists('app')) {
            throw new \InID\InIDException('inid() needs Laravel; elsewhere, use an InID\\InID instance');
        }
        return app('inid');
    }
}
