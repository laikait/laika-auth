<?php
/**
 * Laika Auth
 * Author: Showket Ahmed
 * Email: riyadhtayf@gmail.com
 * License: MIT
 * This file is part of the Laika PHP MVC Framework.
 * For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Laika\Auth;

use Laika\Auth\Guards\SessionGuard;
use Laika\Auth\Guards\CookieGuard;
use Laika\Auth\Guards\TokenGuard;
use Laika\Auth\Guards\OauthGuard;
use Laika\Auth\Providers\GoogleOauthProvider;
use Laika\Auth\Providers\FacebookOauthProvider;

class AuthManager
{
    /** @var array Config Data */
    protected array $config;

    /** @var array Resolved Guard */
    protected array $resolved = [];

    /**
     * When no explicit $config is passed, guards come from a fixed set of
     * AUTH_*_DRIVER / AUTH_*_PROVIDER environment variables — env vars can't
     * discover an arbitrary list of guard names on their own, so only these
     * four (matching the framework's defaults) are wired here. A consumer
     * with different/more guards should pass $config explicitly.
     */
    public function __construct(?array $config = null)
    {
        $this->config = $config ?? [
            'web'      => ['driver' => env('AUTH_WEB_DRIVER', 'session'), 'provider' => env('AUTH_WEB_PROVIDER', 'web')],
            'remember' => ['driver' => env('AUTH_REMEMBER_DRIVER', 'cookie'), 'provider' => env('AUTH_REMEMBER_PROVIDER', 'remember')],
            'admin'    => ['driver' => env('AUTH_ADMIN_DRIVER', 'token'), 'provider' => env('AUTH_ADMIN_PROVIDER', '')],
            'user'     => ['driver' => env('AUTH_USER_DRIVER', 'token'), 'provider' => env('AUTH_USER_PROVIDER', '')],
        ];
    }

    /**
     * Get Guard object
     * @param string $name
     * @return SessionGuard|CookieGuard|TokenGuard
     */
    public function guard(string $name): SessionGuard|CookieGuard|TokenGuard
    {
        if (isset($this->resolved[$name])) return $this->resolved[$name];

        $conf = $this->config[$name]
            ?? throw new \InvalidArgumentException("Guard [$name] not configured.");

        $guard = match ($conf['driver']) {
            'session'   =>  new SessionGuard($conf['provider'] ?? null, $name),
            'cookie'    =>  new CookieGuard($conf['provider'] ?? null, $name),
            'token'     =>  new TokenGuard($conf['provider'], $name),
            default     =>  throw new \InvalidArgumentException("Unknown auth driver [{$conf['driver']}]."),
        };

        return $this->resolved[$name] = $guard;
    }
}
