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

use Laika\Session\Session;

class SessionGuard
{
    /** @var ?string Provider */
    protected ?string $provider;

    /** @var string Guard */
    protected string $guardName;
    
    /** @var string Session Key */
    protected string $sessionKey;

    public function __construct(?string $provider, string $guardName = 'web')
    {
        $this->provider = $provider;
        $this->guardName = $guardName;
        $this->sessionKey = "laika_auth_{$guardName}";
    }

    /**
     * Make Login
     * @param array $user
     * @return void
     */
    public function login(array $user): void
    {
        Session::set($this->sessionKey, $user, $this->provider);
    }

    /**
     * Get User
     * @return array
     */
    public function user(): ?array
    {
        return Session::get($this->sessionKey, null, $this->provider);
    }

    /**
     * Logout
     * @return void
     */
    public function logout(): void
    {
        Session::pop($this->sessionKey, $this->provider);
    }
}
