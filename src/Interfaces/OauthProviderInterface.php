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

namespace Laika\Auth\Interfaces;

interface OauthProviderInterface
{
    public function getAuthUrl(string $redirectUri, array $scopes = []): string;

    public function getAccessToken(string $code, string $redirectUri): array;

    public function getUserProfile(string $accessToken): array; // ['id','email','name','avatar']

    public function name(): string;
}
