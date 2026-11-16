<?php

declare(strict_types=1);

namespace InID\Laravel\Http;

use Illuminate\Http\Request;
use InID\InID;
use InID\Laravel\Bridge;

// InID's routes under the api path: signin, callback, signout, session, sessions
final class RouteController
{
    public function __invoke(Request $request, InID $inid)
    {
        return Bridge::response($inid->handle(Bridge::request($request)));
    }
}
