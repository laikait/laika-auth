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

namespace Laika\Auth\Guards;

use Laika\Service\Cookie;

class CookieGuard
{
    /** @var ?string Provider */
    protected ?string $provider;

    /** @var string $guard Name */
    protected string $guardName;

    /** @var string Cookie Name */
    protected string $cookieName;

    public function __construct(?string $provider, string $guardName = 'web')
    {
        $this->provider = $provider;
        $this->guardName = $guardName;
        $this->cookieName = "laika_remember_{$guardName}";
    }

    /**
     * Remember Token
     * @param string $token
     * @param int $ttl Default is 2592000 (30 days)
     * @return void
     */
    public function remember(string $token, int $ttl = 2592000): void
    {
        Cookie::ttl($ttl)->set($this->cookieName, $token);
    }

    /**
     * Get Cookie Token
     * @return ?string
     */
    public function token(): ?string
    {
        return Cookie::get($this->cookieName, null);
    }

    /**
     * Forget Cookie
     * @return void
     */
    public function forget(): void
    {
        Cookie::pop($this->cookieName);
    }
}
