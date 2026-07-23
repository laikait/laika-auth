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

    public function __construct(?array $config = null)
    {
        $this->config = $config ?? config('auth');
    }

    /**
     * Get Guard object
     * @param string $name
     * @return SessionGuard|CookieGuard|TokenGuard
     */
    public function guard(string $name): SessionGuard|CookieGuard|TokenGuard
    {
        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        $conf = $this->config['guards'][$name]
            ?? throw new \InvalidArgumentException("Guard [$name] not configured.");

        $guard = match ($conf['driver']) {
            'session'   =>  new SessionGuard($conf['provider'] ?? null, $name),
            'cookie'    =>  new CookieGuard($conf['provider'] ?? null, $name),
            'token'     =>  new TokenGuard($conf['provider'], $name),
            default     =>  throw new \InvalidArgumentException("Unknown auth driver [{$conf['driver']}]."),
        };

        return $this->resolved[$name] = $guard;
    }

    /**
     * Outh Guard
     * @param string $provider
     * @return OauthGuard
     */
    public function oauth(string $provider): OauthGuard
    {
        $conf = $this->config['oauth'][$provider]
            ?? throw new \InvalidArgumentException("OAuth provider [$provider] not configured.");

        $providerInstance = match ($provider) {
            'google' => new GoogleOauthProvider($conf['client_id'], $conf['client_secret']),
            'facebook' => new FacebookOauthProvider($conf['client_id'], $conf['client_secret']),
            default => throw new \InvalidArgumentException("Unsupported provider [$provider]."),
        };

        $tokenGuard = new TokenGuard("{$provider}_oauth");

        return new OauthGuard($providerInstance, $tokenGuard, $conf['user_model']);
    }
}
